"""Module contains classes required to create Protobuf editor tabs."""
import traceback
import base64
import zlib
import burp
import blackboxprotobuf
from javax.swing import JSplitPane, JPanel, JButton, BoxLayout, JOptionPane
from java.awt import Component
from java.awt.event import ActionListener
from blackboxprotobuf.burp import user_funcs
from blackboxprotobuf.burp import typedef_editor

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

    def __init__(self, extender, controller, editable):

        self._extender = extender
        self._callbacks = extender.callbacks
        self._helpers = extender.helpers

        self._controller = controller

        self._text_editor = self._callbacks.createTextEditor()
        self._text_editor.setEditable(editable)
        self._editable = editable

        self._component = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self._component.setLeftComponent(self._text_editor.getComponent())
        self._component.setRightComponent(self.createButtonPane())
        self._component.setResizeWeight(0.8)

        self.message_type = None
        self._is_request = None
        self._encoder = None
        self._original_json = None
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

        message_hash = self.getMessageHash()

        # Try to find saved messsage type
        self.message_type = None
        if message_hash in self._extender.known_types:
            self.message_type = self._extender.known_types[message_hash]

        try:
            protobuf_data = None
            if 'get_protobuf_data' in dir(user_funcs):
                protobuf_data = user_funcs.get_protobuf_data(
                    content, is_request, self._content_info, self._helpers,
                    self._request, self._request_content_info)
            if protobuf_data is None:
                protobuf_data = content[self._content_info.getBodyOffset():].tostring()

            protobuf_data = self.decodePayload(protobuf_data)
            json_data, self.message_type = blackboxprotobuf.protobuf_to_json(
                protobuf_data, self.message_type)

            # Save the message type
            self._extender.known_types[message_hash] = self.message_type

            self._original_json = json_data
            self._text_editor.setText(json_data)
            success = True
        except Exception as exc:
            success = False
            self._callbacks.printError(traceback.format_exc())

        # Bring out of exception handler to avoid nexting handlers
        if not success:
            if retry:
                # Clear existing type info and retry
                prev_type = self.message_type
                self.message_type = None
                if message_hash in self._extender.known_types:
                    del self._extender.known_types[message_hash]
                try:
                    self.setMessage(content, is_request, False)
                except Exception as exc:
                    # If it still won't parse, restore the types
                    self.message_type = prev_type
                    self._extender.known_types[message_hash] = prev_type
            else:
                self._text_editor.setText("Error parsing protobuf")

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

        try:
            protobuf = base64.urlsafe_b64decode(payload)
            self._encoder = 'base64_url'
            return protobuf
        except Exception as exc:
            pass

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

        protobuf_content_types = ['x-protobuf', 'application/protobuf']
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

        if self._editable:
            panel.add(self.createButton("Validate", "validate"))
        panel.add(self.createButton("Save Type", "save-type"))
        panel.add(self.createButton("Load Type", "load-type"))
        panel.add(self.createButton("Edit Type", "edit-type"))
        panel.add(self.createButton("Reset", "reset"))
        return panel

    def createButton(self, text, command):
        """Create a new button with the given text and command"""
        button = JButton(text)
        button.setAlignmentX(Component.CENTER_ALIGNMENT)
        button.setActionCommand(command)
        button.addActionListener(self._button_listener)
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
        except Exception as exc:
            JOptionPane.showMessageDialog(self._component, str(exc))
            self._callbacks.printError(traceback.format_exc())

    def resetMessage(self):
        """Drop any changes and reset the message. Callback for "reset"
           button
        """
        self._text_editor.setText(self._original_json)

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

    def saveTypeMenu(self):
        """Open an input dialog to save the current type definiton"""
        type_defs = blackboxprotobuf.known_messages.keys()
        type_defs.insert(0, "New...")
        selection = JOptionPane.showInputDialog(
            self._component, "Select name for type", "Type selection",
            JOptionPane.PLAIN_MESSAGE, None, type_defs, None)
        if selection is None:
            return
        elif selection == "New...":
            selection = JOptionPane.showInputDialog("Enter new name")
        blackboxprotobuf.known_messages[selection] = self.message_type
        self._extender.suite_tab.updateList()

    def loadTypeMenu(self):
        """Open an input menu dialog to load a type definition"""
        type_defs = blackboxprotobuf.known_messages.keys()
        selection = JOptionPane.showInputDialog(
            self._component, "Select type", "Type selection",
            JOptionPane.PLAIN_MESSAGE, None, type_defs, None)

        if selection is None:
            return

        message_type = blackboxprotobuf.known_messages[selection]

        try:
            self.applyType(message_type)
        except Exception as exc:
            self._callbacks.printError(traceback.format_exc())
            JOptionPane.showMessageDialog(self._component, "Error applying type: " + str(exc))

    def applyType(self, typedef):
        """Apply a new typedef to the message. Throws an exception if type is invalid."""
        # Convert to protobuf as old type and re-interpret as new type
        old_message_type = self.message_type
        json_data = self._text_editor.getText().tostring()
        protobuf_data = blackboxprotobuf.protobuf_from_json(json_data, old_message_type)
        new_json, message_type = blackboxprotobuf.protobuf_to_json(str(protobuf_data), typedef)

        # Should exception out before now if there is an issue
        # Set the message type and reparse with the new type
        self.message_type = message_type
        self._text_editor.setText(str(new_json))

        message_hash = self.getMessageHash()
        self._extender.known_types[message_hash] = message_type

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
            typedef_editor.TypeEditorWindow(
                self._editor_tab._callbacks,
                self._editor_tab.message_type,
                self._editor_tab.applyType).show()
        elif event.getActionCommand() == "save-type":
            self._editor_tab.saveTypeMenu()
        elif event.getActionCommand() == "load-type":
            self._editor_tab.loadTypeMenu()
