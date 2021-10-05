"""Module contains classes required to create Protobuf editor tabs."""
import re
import traceback
import base64
import zlib
import burp
import copy
import struct
import blackboxprotobuf
from javax.swing import JSplitPane, JPanel, JButton, BoxLayout, JOptionPane
from javax.swing import Box, JTextField, JScrollPane, JList, ListSelectionModel, ListModel
from javax.swing.event import  ListSelectionListener, ListDataEvent, ListDataListener
from java.awt import Component, Dimension, FlowLayout
from java.awt.event import ActionListener
from javax.swing.border import EmptyBorder
from blackboxprotobuf.burp import user_funcs
from blackboxprotobuf.burp import typedef_editor
from blackboxprotobuf.lib.exceptions import BlackboxProtobufException, DecoderException, EncoderException

NAME_REGEX = re.compile(r'\A[a-zA-Z_][a-zA-Z0-9_]*\Z')

class ProtoBufEditorTabFactory(burp.IMessageEditorTabFactory):
    """Just returns instances of ProtoBufEditorTab"""

    def __init__(self, extender):
        self._extender = extender

    def createNewInstance(self, controller, editable):
        """Return new instance of editor tab for a new message"""
        return ProtoBufEditorTab(self._extender, controller, editable)

class ProtoBufEditorTab(burp.IMessageEditorTab):
    """Tab in interceptor/repeater for editing protobuf message.
    Decodes them to JSON and back.
    The message type is attached to this object.
    """

    def __init__(self, extension, controller, editable):

        self._extension = extension
        self._callbacks = extension.callbacks
        self._helpers = extension.helpers

        self._controller = controller

        self._text_editor = self._callbacks.createTextEditor()
        self._text_editor.setEditable(editable)
        self._editable = editable

        self._last_valid_type_index = None

        self._filtered_message_model = FilteredMessageModel(extension.known_message_model)

        self._type_list_component = JList(self._filtered_message_model)
        self._type_list_component.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._type_list_component.addListSelectionListener(TypeListListener(self))


        self._new_type_field = JTextField()

        self._component = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self._component.setLeftComponent(self._text_editor.getComponent())
        self._component.setRightComponent(self.createButtonPane())
        self._component.setResizeWeight(0.95)


        self.message_type = None
        self._is_request = None
        self._encoder = None
        self._original_json = None
        self._original_typedef = None
        self._last_set_json = ""
        self._content_info = None
        self._request_content_info = None
        self._request = None
        self._original_content = None

    def getTabCaption(self):
        """Return message tab caption"""
        return "Protobuf"

    def getMessage(self):
        """Transform the JSON format back to the binary protobuf message"""
        try:
            if self.message_type is None or not self.isModified():
                return self._original_content

            json_data = self._text_editor.getText().tostring()

            protobuf_data = blackboxprotobuf.protobuf_from_json(json_data, self.message_type)

            protobuf_data = self.encodePayload(protobuf_data)
            if 'set_protobuf_data' in dir(user_funcs):
                result = user_funcs.set_protobuf_data(
                    protobuf_data, self._original_content,
                    self._is_request, self._content_info,
                    self._helpers, self._request,
                    self._request_content_info)
                if result is not None:
                    return result

            headers = self._content_info.getHeaders()
            return self._helpers.buildHttpMessage(headers, str(protobuf_data))

        except Exception as exc:
            self._callbacks.printError(traceback.format_exc())
            JOptionPane.showMessageDialog(self._component, "Error encoding protobuf: " + str(exc))
            # Resets state
            return self._original_content

    def setMessage(self, content, is_request, retry=True):
        """Get the data from the request/response and parse into JSON.
           sets self.message_type
        """
        # Save original content
        self._original_content = content
        if is_request:
            self._content_info = self._helpers.analyzeRequest(self._controller.getHttpService(),
                                                              content)
        else:
            self._content_info = self._helpers.analyzeResponse(content)
        self._is_request = is_request
        self._request = None
        self._request_content_info = None

        if not is_request:
            self._request = self._controller.getRequest()
            self._request_content_info = self._helpers.analyzeRequest(
                self._controller.getHttpService(), self._request)

        # how we remember which message type correlates to which endpoint
        self._message_hash = self.getMessageHash()

        # Try to find saved messsage type
        self.message_type = None
        self.message_type_name = None
        if self._message_hash in self._extension.saved_types:
            typename = self._extension.saved_types[self._message_hash]
            self.message_type_name = typename
            self.message_type  = blackboxprotobuf.known_messages[typename]

        try:
            protobuf_data = None
            if 'get_protobuf_data' in dir(user_funcs):
                protobuf_data = user_funcs.get_protobuf_data(
                    content, is_request, self._content_info, self._helpers,
                    self._request, self._request_content_info)
            if protobuf_data is None:
                protobuf_data = content[self._content_info.getBodyOffset():].tostring()

            protobuf_data = self.decodePayload(protobuf_data)

            # source_typedef will be the original, updatable version of the dict
            # TODO fix this hack
            self._original_data = protobuf_data
            self._filtered_message_model.set_new_data(protobuf_data)
            self._source_typedef = self.message_type
            json_data, self.message_type = blackboxprotobuf.protobuf_to_json(
                protobuf_data, self.message_type)

            self._original_json = json_data
            self._original_typedef = self.message_type
            self._last_set_json = str(json_data)
            self._text_editor.setText(json_data)
            success = True
        except Exception as exc:
            success = False
            self._callbacks.printError(traceback.format_exc())

        # Bring out of exception handler to avoid nexting handlers
        if not success:
            if self._message_hash in self._extension.known_types:
                del self._extension.known_types[self._message_hash]
                self.setMessage(content, is_request, False)

        if self.message_type_name:
            self.forceSelectType(self.message_type_name)

    def decodePayload(self, payload):
        """Add support for decoding a few default methods. Including Base64 and GZIP"""
        if payload.startswith(bytearray([0x1f, 0x8b, 0x08])):
            gzip_decompress = zlib.decompressobj(-zlib.MAX_WBITS)
            self._encoder = 'gzip'
            return gzip_decompress.decompress(payload)

        # Try to base64 decode
        try:
            protobuf = base64.b64decode(payload, validate=True)
            self._encoder = 'base64'
            return protobuf
        except Exception as exc:
            pass

        # try decoding as a gRPC payload: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md
        # we're naiively handling only uncompressed payloads
        if len(payload) > 1 + 4 and payload.startswith(bytearray([0x00])): # gRPC has 1 byte flag + 4 byte length
            (message_length,) = struct.unpack_from(">I", payload[1:])
            if len(payload) == 1 + 4 + message_length:
                self._encoder = 'gRPC'
                return payload[1 + 4:]
        #try:
        #    protobuf = base64.urlsafe_b64decode(payload)
        #    self._encoder = 'base64_url'
        #    return protobuf
        #except Exception as exc:
        #    pass

        self._encoder = None
        return payload

    def encodePayload(self, payload):
        """If we detected an encoding like gzip or base64 when decoding, redo
           that encoding step here
        """
        if self._encoder == 'base64':
            return base64.b64encode(payload)
        elif self._encoder == 'base64_url':
            return  base64.urlsafe_b64encode(payload)
        elif self._encoder == 'gzip':
            gzip_compress = zlib.compressobj(-1, zlib.DEFLATED, -zlib.MAX_WBITS)
            self._encoder = 'gzip'
            return gzip_compress.compress(payload)
        elif self._encoder == 'gRPC':
            message_length = struct.pack(">I", len(payload))
            return bytearray([0x00]) + bytearray(message_length) + payload
        else:
            return payload

    def getSelectedData(self):
        """Get text currently selected in message"""
        return self._text_editor.getSelectedText()

    def getUiComponent(self):
        """Return Java AWT component for this tab"""
        return self._component

    def isEnabled(self, content, is_request):
        """Try to detect a protobuf in the message to enable the tab. Defaults
           to content-type header of 'x-protobuf'. User overridable
        """
        # TODO implement some more default checks
        if is_request:
            info = self._helpers.analyzeRequest(content)
        else:
            info = self._helpers.analyzeResponse(content)

        if 'detect_protobuf' in dir(user_funcs):
            result = user_funcs.detect_protobuf(content, is_request, info, self._helpers)
            if result is not None:
                return result

        # Bail early if there is no body
        if info.getBodyOffset() == len(content):
            return False

        protobuf_content_types = ['x-protobuf', 'application/protobuf', 'application/grpc']
        # Check all headers for x-protobuf
        for header in info.getHeaders():
            if 'content-type' in header.lower():
                for protobuf_content_type in protobuf_content_types:
                    if protobuf_content_type in header.lower():
                        return True

        return False

    def isModified(self):
        """Return if the message was modified"""
        return self._text_editor.isTextModified()

    def createButtonPane(self):
        """Create a new button pane for the message editor tab"""
        self._button_listener = EditorButtonListener(self)

        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(EmptyBorder(5,5,5,5))

        panel.add(Box.createRigidArea(Dimension(0, 5)))
        type_scroll_pane = JScrollPane(self._type_list_component)
        type_scroll_pane.setMaximumSize(Dimension(200, 100))
        type_scroll_pane.setMinimumSize(Dimension(150, 100))
        panel.add(type_scroll_pane)
        panel.add(Box.createRigidArea(Dimension(0, 3)))

        new_type_panel = JPanel()
        new_type_panel.setLayout(BoxLayout(new_type_panel, BoxLayout.X_AXIS))
        new_type_panel.add(self._new_type_field)
        new_type_panel.add(Box.createRigidArea(Dimension(3, 0)))
        new_type_panel.add(self.createButton("New", "new-type", "Save this message's type under a new name"))
        new_type_panel.setMaximumSize(Dimension(200, 20))
        new_type_panel.setMinimumSize(Dimension(150, 20))

        panel.add(new_type_panel)

        button_panel = JPanel()
        button_panel.setLayout(FlowLayout())
        if self._editable:
            button_panel.add(self.createButton("Validate", "validate", "Validate the message can be encoded."))
        button_panel.add(self.createButton("Edit Type", "edit-type", "Edit the message type"))
        button_panel.add(self.createButton("Reset Message", "reset", "Reset the message and undo changes"))
        button_panel.add(self.createButton("Clear Type", "clear-type", "Reparse the message with an empty type"))
        button_panel.setMinimumSize(Dimension(100, 200))
        button_panel.setPreferredSize(Dimension(200, 1000))

        panel.add(button_panel)

        return panel

    def createButton(self, text, command, tooltip):
        """Create a new button with the given text and command"""
        button = JButton(text)
        button.setAlignmentX(Component.CENTER_ALIGNMENT)
        button.setActionCommand(command)
        button.addActionListener(self._button_listener)
        button.setToolTipText(tooltip)
        return button

    def validateMessage(self):
        """Callback for validate button. Attempts to encode the message with
           the current type definition
        """
        try:
            json_data = self._text_editor.getText().tostring()
            blackboxprotobuf.protobuf_from_json(json_data, self.message_type)
            # If it works, save the message
            self._original_json = json_data
            self._original_typedef = self.message_type
        except Exception as exc:
            JOptionPane.showMessageDialog(self._component, str(exc))
            self._callbacks.printError(traceback.format_exc())

    def resetMessage(self):
        """Drop any changes and reset the message. Callback for "reset"
           button
        """

        self._last_set_json = str(self._original_json)
        self._text_editor.setText(self._original_json)
        self.message_type = self._original_typedef

    def getMessageHash(self):
        """Compute an "identifier" for the message which is used for sticky
           type definitions. User modifiable
        """
        message_hash = None
        if 'hash_message' in dir(user_funcs):
            message_hash = user_funcs.hash_message(
                self._original_content, self._is_request, self._content_info,
                self._helpers, self._request, self._request_content_info)
        if message_hash is None:
            # Base it off just the URL and request/response

            content_info = self._content_info if self._is_request else self._request_content_info
            url = content_info.getUrl().getPath()
            message_hash = (url, self._is_request)
        return message_hash


    def forceSelectType(self, typename):
        index = self._filtered_message_model.get_type_index(typename)
        if index is not None:
            self._last_valid_type_index = index
            self._type_list_component.setSelectedIndex(index)

    def updateTypeSelection(self):
        """ Apply a new typedef based on the selected type in the type list """
        # Check if something is selected
        if self._type_list_component.isSelectionEmpty():
            return

        if self._last_valid_type_index == self._type_list_component.getSelectedIndex():
            # hasn't actually changed since last time we tried
            # otherwise can trigger a second time when we call setSelectedIndex below on failure
            return

        type_name = self._type_list_component.getSelectedValue()
        # try to catch none here...
        if not type_name or type_name not in blackboxprotobuf.known_messages:
            return

        try:
            self.applyType(blackboxprotobuf.known_messages[type_name])
        except BlackboxProtobufException as exc:
            self._callbacks.printError(traceback.format_exc())

            if isinstance(exc, EncoderException):
                JOptionPane.showMessageDialog(self._component, "Error encoding protobuf with previous type: %s" % (exc))
            elif isinstance(exc, DecoderException):
                JOptionPane.showMessageDialog(self._component, "Error encoding protobuf with type %s: %s" % (type_name, exc))
                # decoder exception means it doesn't match the message that was sucessfully encoded by the prev type
                self._filtered_message_model.remove_type(type_name)

            if self._last_valid_type_index is not None:
                type_name = self._type_list_component.setSelectedIndex(self._last_valid_type_index)
            else:
                self._type_list_component.clearSelection()
            return

        self._extension.saved_types[self._message_hash] = type_name
        self._last_valid_type_index = self._type_list_component.getSelectedIndex()

    def editType(self, typedef):
        """ Apply the new typedef. Use dict.update to change the original
        dictionary, so we also update the anonymous cached definition and ones
        stored in known_messages """
        # TODO this is kind of an ugly hack. Should redo how these are referenced
        # probably means rewriting a bunch of the editor
        old_source = self._source_typedef
        old_source.clear()
        old_source.update(typedef)
        self.applyType(old_source)


    def applyType(self, typedef):
        """Apply a new typedef to the message. Throws an exception if type is invalid."""
        # store a reference for later mutation?
        self._source_typedef = typedef
        # Convert to protobuf as old type and re-interpret as new type
        old_message_type = self.message_type
        json_data = self._text_editor.getText().tostring()
        protobuf_data = blackboxprotobuf.protobuf_from_json(json_data, old_message_type)

        new_json, message_type = blackboxprotobuf.protobuf_to_json(str(protobuf_data), typedef)

        # Should exception out before now if there is an issue
        self.message_type = message_type

        # if the json data was modified, then re-check our types
        if json_data != self._last_set_json:
            self._filtered_message_model.set_new_data(protobuf_data)
        self._last_set_json = str(new_json)
        self._text_editor.setText(str(new_json))

    def saveAsNewType(self):
        """ Copy the current type into known_messages """
        name = self._new_type_field.getText().strip()
        if not NAME_REGEX.match(name):
            JOptionPane.showMessageDialog(self._component,
                "%s is not a valid "
                "message name. Message names should be alphanumeric."
                % name)
            return
        if name in blackboxprotobuf.known_messages:
            JOptionPane.showMessageDialog(self._component, "Message name %s is "
            "already taken." % name)
            return


        # Do a deep copy on the dictionary so we don't accidentally modify others
        blackboxprotobuf.known_messages[name] = copy.deepcopy(self.message_type)
        # update the list of messages. This should trickle down to known message model
        self._extension.known_message_model.addElement(name)
        self._new_type_field.setText("")
        self._extension.saved_types[self._message_hash] = name

    def clearType(self):
        self.applyType({})
        self._type_list_component.clearSelection()
        self._new_type_field.setText("")

class EditorButtonListener(ActionListener):
    """Callback listener for buttons in the message editor tab"""
    def __init__(self, editor_tab):
        self._editor_tab = editor_tab

    def actionPerformed(self, event):
        """Called when when a button in the message editor is pressed"""
        if event.getActionCommand() == "validate":
            self._editor_tab.validateMessage()
        elif event.getActionCommand() == "reset":
            self._editor_tab.resetMessage()
        elif event.getActionCommand() == "edit-type":
            # TODO hook up something to kill this window when we unload
            typedef_editor.TypeEditorWindow(
                self._editor_tab._callbacks,
                self._editor_tab.message_type,
                self._editor_tab.editType).show()
        elif event.getActionCommand() == "new-type":
            self._editor_tab.saveAsNewType()
        elif event.getActionCommand() == "clear-type":
            self._editor_tab.clearType()

class TypeListListener(ListSelectionListener):
    """ Callback listener for when a new type is selected form the list """
    def __init__(self, editor_tab):
        self._editor_tab = editor_tab

    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        self._editor_tab.updateTypeSelection()

class FilteredMessageModel(ListModel, ListDataListener):
    """ listens to a java ListModel and keeps a subset with just valid types
    for a message """

    def __init__(self, parent):
        self._data = None
        self._parent_model = parent
        self._listeners = []

        # list of types in the parent model
        self._types = []
        self._parent_types = set(parent.elements())
        self._rejected_types = set()
        self._working_types = set()

        self._parent_model.addListDataListener(self)

    def set_new_data(self, data):
        self._data = data

        # clear caches
        self._working_types.clear()
        self._rejected_types.clear()

        # recheck all the types with the new data
        for typename in self._types[:]:
            if not self._check_type(typename):
                removed_index = self._types.index(type_name)
                self._types.remove(type_name)
                event = ListDataEvent(self, ListDataEvent.INTERVAL_REMOVED, removed_index, removed_index)
                self._send_event(event)

        interval_start = len(self._types)
        for typename in self._parent_types:
            if typename not in self._types and self._check_type(typename):
                self._types.append(typename)

        if len(self._types) > interval_start:
            event = ListDataEvent(self, ListDataEvent.INTERVAL_ADDED, interval_start, len(self._types) - 1)
            self._send_event(event)

    def get_type_index(self, typename):
        if typename in self._types:
            return self._types.index(typename)
        return None

    def remove_type(self, typename):
        # if we failed to apply a type, then this lets us remove it
        if typename not in self._types:
            return

        type_index = self._types.index(typename)
        # delete by index because we have it
        del self._types[type_index]
        self._working_types.remove(typename)
        self._rejected_types.add(typename)

        event = ListDataEvent(self, ListDataEvent.INTERVAL_REMOVED, type_index, type_index)
        self._send_event(event)

    def update_types(self):
        new_parent_types = set(self._parent_model.elements())
        added_parent_types = new_parent_types - self._parent_types
        removed_parent_types = self._parent_types - new_parent_types
        self._parent_types = new_parent_types

        for type_name in removed_parent_types:
            if type_name in self._types:
                removed_index = self._types.index(type_name)
                self._types.remove(type_name)
                event = ListDataEvent(self, ListDataEvent.INTERVAL_REMOVED, removed_index, removed_index)
                self._send_event(event)

        interval_start = len(self._types)
        for type_name in added_parent_types:
            if type_name not in self._types and self._check_type(type_name):
                self._types.append(type_name)

        # not sure how much effort we want to put into the events. could just mark everything as changed all the time
        if len(self._types) > interval_start:
            # if we didn't remove anything, then  just issue an added event?
            event = ListDataEvent(self, ListDataEvent.INTERVAL_ADDED, interval_start, len(self._types) - 1)
            self._send_event(event)


    def _send_event(self, event):
        event_type = event.getType()
        if event_type == ListDataEvent.CONTENTS_CHANGED:
            for listener in self._listeners:
                listener.contentsChanged(event)
        elif event_type == ListDataEvent.INTERVAL_ADDED:
            for listener in self._listeners:
                listener.intervalAdded(event)
        elif event_type == ListDataEvent.INTERVAL_REMOVED:
            for listener in self._listeners:
                listener.intervalRemoved(event)

    def _check_type(self, typename):
        if typename in self._rejected_types:
            return False
        if typename in self._working_types:
            return True

        # if we don't have data yet, just quit early
        if not self._data:
            return False
        if typename not in blackboxprotobuf.known_messages:
            return False
        typedef = blackboxprotobuf.known_messages[typename]
        try:
            _, _ = blackboxprotobuf.protobuf_to_json(self._data, typedef)
        except BlackboxProtobufExceptions as exc:
            self._callbacks.printError(traceback.format_exc())
            self._rejected_types.add(typename)
            return False
        self._working_types.add(typename)
        return True

    def addListDataListener(self, listener):
        self._listeners.append(listener)

    def getElementAt(self, i):
        return self._types[i]

    def getSize(self):
        return len(self._types)

    def removeListDataListener(self, listener):
        self._listeners.remove(listener)

    # data listener stuff
    def contentsChanged(self, event):
        self.update_types()

    def intervalAdded(self, event):
        self.update_types()

    def intervalRemoved(self, event):
        self.update_types()
