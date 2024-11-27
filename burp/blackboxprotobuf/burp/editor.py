"""Module contains classes required to create Protobuf editor tabs."""

# Copyright (c) 2018-2023 NCC Group Plc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import re
import six
import traceback
import base64
import zlib
import burp
import copy
import struct
import blackboxprotobuf
from javax.swing import JSplitPane, JPanel, JButton, BoxLayout, JOptionPane
from javax.swing import (
    Box,
    JTextField,
    JScrollPane,
    JList,
    ListSelectionModel,
    ListModel,
)
from javax.swing.event import ListSelectionListener, ListDataEvent, ListDataListener
from java.awt import Component, Dimension, FlowLayout
from java.awt.event import ActionListener
from javax.swing.border import EmptyBorder
from blackboxprotobuf.burp import user_funcs
from blackboxprotobuf.burp import typedef_editor
from blackboxprotobuf.lib import payloads
from blackboxprotobuf.lib.config import default as default_config
from blackboxprotobuf.lib.exceptions import (
    BlackboxProtobufException,
    DecoderException,
    EncoderException,
)

NAME_REGEX = re.compile(r"\A[a-zA-Z_][a-zA-Z0-9_]*\Z")


class ProtoBufEditorTabFactory(burp.IMessageEditorTabFactory):
    """Just returns instances of ProtoBufEditorTab"""

    def __init__(self, extender, callbacks):
        self._callbacks = callbacks
        self._extender = extender

    def createNewInstance(self, controller, editable):
        """Return new instance of editor tab for a new message"""
        return ProtoBufEditorTab(self._extender, controller, editable, self._callbacks)


class ProtoBufEditorTab(burp.IMessageEditorTab):
    """Tab in interceptor/repeater for editing protobuf message.

    Decodes the message to JSON and back for editing.
    The message type definition is attached to this object for re-encoding or editing.
    """

    def __init__(self, extension, controller, editable, callbacks):
        self._callbacks = callbacks
        self._extension = extension
        self._callbacks = extension.callbacks
        self._helpers = extension.helpers

        self._controller = controller

        self._text_editor = self._callbacks.createTextEditor()
        self._text_editor.setEditable(editable)
        self._editable = editable

        self._last_valid_type_index = None

        self._filtered_message_model = FilteredMessageModel(
            extension.known_message_model, self._callbacks
        )

        self._type_list_component = JList(self._filtered_message_model)
        self._type_list_component.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._type_list_component.addListSelectionListener(TypeListListener(self))

        self._new_type_field = JTextField()

        self._component = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self._component.setLeftComponent(self._text_editor.getComponent())
        self._component.setRightComponent(self.createButtonPane())
        self._component.setResizeWeight(0.95)

        self._message_info = None
        self._payload_info = None
        self._last_good_msg = None  # (msg, typedef, source)
        self._decode_task = None

    def getTabCaption(self):
        """Return message tab caption"""
        return "Protobuf"

    def getMessage(self):
        """Transform the JSON format back to the binary protobuf message"""
        # Noticing this gets called twice for some reason
        # If we haven't finished decoding the message, cancel and return the original content
        if self._decode_task and (
            not self._decode_task.isDone() or self._decode_task.isCancelled()
        ):
            self._decode_task.cancel(True)
            self._decode_task = None
            # self._callbacks.printOutput(
            #    "Called getMessage before decode task was done, returning original content"
            # )
            return self._message_info.content()

        if self._last_good is None or not self.isModified():
            return self._message_info.content()

        success = False
        try:
            json_data = self._text_editor.getText().tostring()
            protobuf_data = blackboxprotobuf.protobuf_from_json(
                json_data, self._last_good.typedef
            )

            success = True
            self._payload_info.protobuf_data = protobuf_data
            return self._payload_info.generate_http(self._message_info, self._helpers)

        except Exception as exc:
            self._callbacks.printError(traceback.format_exc())

        if not success:
            try:
                protobuf_data = blackboxprotobuf.protobuf_from_json(
                    self._last_good.message, self._last_good.typedef
                )

                # Put the error here so that we only have one error to the user if the above encoding doesn't work
                JOptionPane.showMessageDialog(
                    self._component,
                    "Error encoding protobuf as-is. Reset data to previous good state: "
                    + str(exc),
                )

                success = True
                # Reset the message and protobuf data both
                self._text_editor.setText(self._last_good.message)
                self._payload_info.protobuf_data = protobuf_data
                return self._payload_info.generate_http(
                    self._message_info, self._helpers
                )
            except Exception as exc:
                self._callbacks.printError(traceback.format_exc())
                JOptionPane.showMessageDialog(
                    self._component,
                    "Error encoding protobuf. Setting data to the original message. Error: "
                    + str(exc),
                )
                self._text_editor.setText(self._message_info.content())
                return self._message_info.content()

    def _handle_protobuf(
        self, message_info, protobuf_data, message_type_in, typedef_source
    ):
        """
        Sets the protobuf message for the editor.
        """
        try:
            json_data, message_type = blackboxprotobuf.protobuf_to_json(
                protobuf_data, message_type_in
            )

            self._last_good = LastGoodData(json_data, message_type, typedef_source)
            self._filtered_message_model.set_new_data(protobuf_data)
            self._text_editor.setText(json_data)  # UI access
            success = True
        except Exception as exc:
            success = False
            self._callbacks.printError(
                "Got error decoding protobuf binary: " + traceback.format_exc()
            )

        # Bring out of exception handler to avoid nesting handlers
        if success:
            if typedef_source is not None:
                self.forceSelectType(typedef_source)
            else:
                self._type_list_component.clearSelection()
        elif len(message_type_in) == 0:
            self._callbacks.printError(
                "Error decoding protobuf with saved type, trying with empty type"
            )
            self._handle_protobuf(message_info, protobuf_data, {}, None)
        else:
            self._callbacks.printError("Error decoding protobuf with empty type")
            self._text_editor.setText("Error decoding protobuf")

    def setMessage(self, content, is_request):
        """
        Get the data from the request/response and parse into JSON.
        """
        # Run in a separate thread to avoid hanging the Burp UI
        # It has been observed that the Burp UI can hang when the message is large
        # and the decoding process takes a long time

        message_info = MessageInfo(content, is_request, self._helpers, self._controller)
        payload_info = PayloadInfo(message_info, self._helpers)
        message_type, typedef_source = self._get_saved_typedef(message_info)

        if (
            self._decode_task
            and not self._decode_task.isCancelled()
            and not self._decode_task.isDone()
        ):
            # If we're processing the same message as the running task
            # check message has
            # check protobuf data
            # TODO do we want to check typedef? Can switch away and back to restart it if we need to
            if (
                message_info.message_hash == self._message_info.message_hash
                and payload_info.raw_data == self._payload_info.raw_data
            ):
                # self._callbacks.printOutput(
                #    "Switched to tab that is still running with the same hash and payload. Not cancelling."
                # )
                return
            else:
                # self._callbacks.printOutput(
                #    "Have existing task that is still running, cancelling"
                # )
                # Cancel the old task
                self._decode_task.cancel(True)

        self._message_info = message_info
        self._payload_info = payload_info
        self._last_good_msg = None
        self._decode_task = None

        self._text_editor.setText("Please wait...")

        def run():
            try:
                decoders = payloads.find_decoders(payload_info.raw_data)
                for decoder in decoders:
                    try:
                        protobuf_data, encoding_alg = decoder(payload_info.raw_data)
                    except BlackboxProtobufException:
                        continue

                    try:
                        self._handle_protobuf(
                            message_info,
                            protobuf_data,
                            message_type,
                            typedef_source,
                        )

                        # Payload successfully decoded, so we probably have the right wrapper for the payload
                        self._payload_info.protobuf_data = protobuf_data
                        self._payload_info.encoding_alg = encoding_alg

                        return
                    except BlackboxProtobufException:
                        if encoding_alg == "none":
                            # Reraise the exception to the parent context and halt decoding
                            six.reraise(*sys.exc_info())
                        continue

            except Exception as ex:
                # Catch all, otherwise it disappears
                self._text_editor.setText("Error decoding protobuf")
                self._callbacks.printError("Error decoding protobuf: %s" % ex)

        self._decode_task = self._extension.thread_executor.submit(run)

    def getSelectedData(self):
        """Get text currently selected in message"""
        return self._text_editor.getSelectedText()

    def getUiComponent(self):
        """Return Java AWT component for this tab"""
        return self._component

    def isEnabled(self, content, is_request):
        """Try to detect a protobuf in the message to enable the tab.

        Defaults to content-type header of 'x-protobuf'. User overridable in
        `user_funcs.py`
        """
        # TODO implement some more default checks
        if is_request:
            info = self._helpers.analyzeRequest(content)
        else:
            info = self._helpers.analyzeResponse(content)

        if "detect_protobuf" in dir(user_funcs):
            result = user_funcs.detect_protobuf(
                content, is_request, info, self._helpers
            )
            if result is not None:
                return result

        # Bail early if there is no body
        if info.getBodyOffset() == len(content):
            return False

        protobuf_content_types = [
            "protobuf",
            "grpc",
        ]
        # Check all headers for x-protobuf
        for header in info.getHeaders():
            if "content-type" in header.lower():
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
        panel.setBorder(EmptyBorder(5, 5, 5, 5))

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
        new_type_panel.add(
            self.createButton(
                "New", "new-type", "Save this message's type under a new name"
            )
        )
        new_type_panel.setMaximumSize(Dimension(200, 20))
        new_type_panel.setMinimumSize(Dimension(150, 20))

        panel.add(new_type_panel)

        button_panel = JPanel()
        button_panel.setLayout(FlowLayout())
        if self._editable:
            button_panel.add(
                self.createButton(
                    "Validate", "validate", "Validate the message can be encoded."
                )
            )
        button_panel.add(
            self.createButton("Edit Type", "edit-type", "Edit the message type")
        )
        button_panel.add(
            self.createButton(
                "Reset Message", "reset", "Reset the message and undo changes"
            )
        )
        button_panel.add(
            self.createButton(
                "Clear Type", "clear-type", "Reparse the message with an empty type"
            )
        )
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
            typedef = self._last_good.typedef
            protobuf_data = blackboxprotobuf.protobuf_from_json(json_data, typedef)
            # If it works, save the message
            # Don't need to save typeddef because we're using the one from lastgood
            self._last_good.message = json_data
            self._payload_info.protobuf_data = protobuf_data

        except Exception as exc:
            JOptionPane.showMessageDialog(
                self._component,
                "Got exception while trying to encode the message: " + str(exc),
            )
            self._callbacks.printError(traceback.format_exc())

    def resetMessage(self):
        """Drop any changes and revert to the last good message. Callback for
        "reset" button
        """

        self._text_editor.setText(self._last_good.message)

    def forceSelectType(self, typename):
        index = self._filtered_message_model.get_type_index(typename)
        if index is not None:
            self._last_valid_type_index = index
            self._type_list_component.setSelectedIndex(index)

    def updateTypeSelection(self):
        """Apply a new typedef based on the selected type in the type list"""
        # TODO It sucks that we lose the anonymous type if we accidentally
        # click a type. Maybe we should have an entry in the cached type in the
        # list?
        # Or have a warning before switching
        # Or require a click + a button press?

        # Check if something is selected
        if self._type_list_component.isSelectionEmpty():
            self._last_valid_type_index = None
            self._extension.saved_types.pop(self._message_info.message_hash, None)
            return

        # TODO won't actually work right if we delete the type we're using a
        # new type is now in the index
        if self._last_valid_type_index == self._type_list_component.getSelectedIndex():
            # hasn't actually changed since last time we tried
            # otherwise can trigger a second time when we call setSelectedIndex below on failure
            return

        type_name = self._type_list_component.getSelectedValue()
        # try to catch none here...
        if not type_name or type_name not in default_config.known_types:
            return

        try:
            self.applyType(default_config.known_types[type_name], type_name)
        except BlackboxProtobufException as exc:
            self._callbacks.printError(traceback.format_exc())

            if isinstance(exc, EncoderException):
                JOptionPane.showMessageDialog(
                    self._component,
                    "Error encoding protobuf with previous type: %s" % (exc),
                )
            elif isinstance(exc, DecoderException):
                JOptionPane.showMessageDialog(
                    self._component,
                    "Error encoding protobuf with type %s: %s" % (type_name, exc),
                )
                # decoder exception means it doesn't match the message that was sucessfully encoded by the prev type
                self._filtered_message_model.remove_type(type_name)

            if self._last_valid_type_index is not None:
                type_name = self._type_list_component.setSelectedIndex(
                    self._last_valid_type_index
                )
            else:
                self._type_list_component.clearSelection()
            return

        self._extension.saved_types[self._message_info.message_hash] = type_name
        self._last_valid_type_index = self._type_list_component.getSelectedIndex()

    def editType(self, typedef, source):
        """Apply and save the new typedef"""
        # Try to apply the type first
        try:
            # TODO Background this like with handle_protobuf? I think we need
            # to be more confident that we can validate the typedef without
            # decoding first
            # The decoding here throws an exception that will prevent us from
            # closing the typedef editor window if it's not valid
            self.applyType(typedef, source)
        except BlackboxProtobufException as exc:
            self._callbacks.printError("Got exception trying to apply edited typedef.")
            JOptionPane.showMessageDialog(
                self._component,
                "Error decoding the protobuf with the new type: %s" % (exc),
            )
            return

        if source is None:
            # Anonymous typedef tied to message hash
            # save the typedef
            self._extension.saved_types[self._message_info.message_hash] = typedef
        else:
            # Named typedef
            # save under known typedefs and save the name in source
            default_config.known_types[source] = typedef
            self._extension.saved_types[self._message_info.message_hash] = source

    def applyType(self, typedef, source):
        """Apply a new typedef to the message. Throws an exception if type is invalid."""
        # Convert to protobuf as old type and re-interpret as new type
        old_typedef = self._last_good.typedef
        json_data = self._text_editor.getText().tostring()

        protobuf_data = blackboxprotobuf.protobuf_from_json(json_data, old_typedef)
        self._payload_info.protobuf_data = protobuf_data

        new_json, new_typedef = blackboxprotobuf.protobuf_to_json(
            protobuf_data, typedef
        )

        self._last_good = LastGoodData(new_json, new_typedef, source)

        self._filtered_message_model.set_new_data(protobuf_data)
        self._text_editor.setText(str(new_json))
        # We do not try to remember the type here, this should be handled by the caller

    def saveAsNewType(self):
        """Copy the current type into known_messages"""

        name = self._new_type_field.getText().strip()
        if not NAME_REGEX.match(name):
            JOptionPane.showMessageDialog(
                self._component,
                "%s is not a valid "
                "message name. Message names should be alphanumeric." % name,
            )
            return
        if name in default_config.known_types:
            JOptionPane.showMessageDialog(
                self._component, "Message name %s is " "already taken." % name
            )
            return

        typedef = self._last_good.typedef

        # Do a deep copy on the dictionary so we don't accidentally modify others
        default_config.known_types[name] = copy.deepcopy(typedef)
        self._last_good.source = name  # remember the source, typedef is still the same

        # update the list of messages. This should trickle down to known message model
        self._extension.known_message_model.addElement(name)
        self._new_type_field.setText("")
        self._extension.saved_types[self._message_info.message_hash] = name

        # force select our new type
        self.forceSelectType(name)

    def clearType(self):
        self.applyType({}, None)
        self._type_list_component.clearSelection()
        self._new_type_field.setText("")
        self._extension.saved_types.pop(self._message_info.message_hash, None)

    def open_typedef_window(self):
        typedef = self._last_good.typedef
        source = self._last_good.source
        self._extension.open_typedef_editor(typedef, source, self.editType)

    def _get_saved_typedef(self, message_info):
        # Get the typedef we have saved for this message
        # It can be anonymous, but saved based on the message hash
        # Or it can be named
        # Return typedef, typename tuple
        if message_info.message_hash in self._extension.saved_types:
            saved_type = self._extension.saved_types[message_info.message_hash]
            if isinstance(saved_type, dict):
                return saved_type, None
            elif saved_type in default_config.known_types:
                typename = saved_type
                typedef = default_config.known_types[typename]
                return typedef, typename
            else:
                # We had a type, but it isn't a dict and not in known types
                # Error, so clear
                self._extension.saved_types.pop(message_info.message_hash, None)
                self._callbacks.printError(
                    "Found unknown saved type: %s for %s"
                    % (saved_type, message_info.message_hash)
                )
        else:
            return {}, None


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
            self._editor_tab.open_typedef_window()
        elif event.getActionCommand() == "new-type":
            self._editor_tab.saveAsNewType()
        elif event.getActionCommand() == "clear-type":
            self._editor_tab.clearType()


class TypeListListener(ListSelectionListener):
    """Callback listener for when a new type is selected form the list"""

    def __init__(self, editor_tab):
        self._editor_tab = editor_tab

    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        self._editor_tab.updateTypeSelection()


class FilteredMessageModel(ListModel, ListDataListener):
    """Listens to a java ListModel and keeps a subset with just valid types
    for a message.
    """

    def __init__(self, parent, callbacks):
        self._callbacks = callbacks
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
                removed_index = self._types.index(typename)
                self._types.remove(typename)
                event = ListDataEvent(
                    self, ListDataEvent.INTERVAL_REMOVED, removed_index, removed_index
                )
                self._send_event(event)

        interval_start = len(self._types)
        for typename in self._parent_types:
            if typename not in self._types and self._check_type(typename):
                self._types.append(typename)

        if len(self._types) > interval_start:
            event = ListDataEvent(
                self, ListDataEvent.INTERVAL_ADDED, interval_start, len(self._types) - 1
            )
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

        event = ListDataEvent(
            self, ListDataEvent.INTERVAL_REMOVED, type_index, type_index
        )
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
                event = ListDataEvent(
                    self, ListDataEvent.INTERVAL_REMOVED, removed_index, removed_index
                )
                self._send_event(event)

        interval_start = len(self._types)
        for type_name in added_parent_types:
            if type_name not in self._types and self._check_type(type_name):
                self._types.append(type_name)

        # not sure how much effort we want to put into the events. could just mark everything as changed all the time
        if len(self._types) > interval_start:
            # if we didn't remove anything, then  just issue an added event?
            event = ListDataEvent(
                self, ListDataEvent.INTERVAL_ADDED, interval_start, len(self._types) - 1
            )
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
        # TODO this hangs the UI as well
        # TODO would be better to check by comparing typedefs instead of trying
        # to decode
        if typename in self._rejected_types:
            return False
        if typename in self._working_types:
            return True

        # if we don't have data yet, just quit early
        if not self._data:
            return False
        if typename not in default_config.known_types:
            return False
        typedef = default_config.known_types[typename]
        try:
            _, _ = blackboxprotobuf.protobuf_to_json(self._data, typedef)
        except BlackboxProtobufException as exc:
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


class MessageInfo:
    """This class parses the data we get from burp for us to use throughout the processing"""

    def __init__(self, content, is_request, helpers, controller):
        self.is_request = is_request

        if is_request:
            self.request = content
        else:
            self.request = controller.getRequest()

            self.response = content
            self.response_content_info = helpers.analyzeResponse(content)

        self.request_content_info = helpers.analyzeRequest(
            controller.getHttpService(), self.request
        )

        self.message_hash = self._message_hash(helpers)

    def content(self):
        if self.is_request:
            return self.request
        else:
            return self.response

    def content_info(self):
        if self.is_request:
            return self.request_content_info
        else:
            return self.response_content_info

    def _message_hash(self, helpers):
        """Compute an "identifier" for the message which is used for sticky
        type definitions. User modifiable
        """
        message_hash = None
        if "hash_message" in dir(user_funcs):
            message_hash = user_funcs.hash_message(
                self.content(),
                self.is_request,
                self.content_info(),
                helpers,
                self.request,
                self.request_content_info,
            )
        if message_hash is None:
            # Base it off just the URL and request/response
            url = self.request_content_info.getUrl()
            message_hash = ":".join(
                [url.getAuthority(), url.getPath(), str(self.is_request)]
            )

        return message_hash


class PayloadInfo:
    """This class stores the latest payload data and functions to transform it to or from a HTTP message"""

    def __init__(self, message_info, helpers):
        self.raw_data = None  # Raw data from payload
        # These attributes must be set from outside this payload
        self.encoding_alg = None
        self.protobuf_data = None  # last known good encoded protobuf payload
        self.parse_http(message_info, helpers)

    def parse_http(self, message_info, helpers):
        raw_data = None
        if "get_protobuf_data" in dir(user_funcs):
            raw_data = user_funcs.get_protobuf_data(
                message_info.content(),
                message_info.is_request,
                message_info.content_info(),
                helpers,
                message_info.request,
                message_info.request_content_info,
            )
        if raw_data is None:
            raw_data = message_info.content()[
                message_info.content_info().getBodyOffset() :
            ].tostring()
        self.raw_data = raw_data

    def generate_http(self, message_info, helpers):
        if "set_protobuf_data" in dir(user_funcs):
            result = user_funcs.set_protobuf_data(
                self.protobuf_data,
                message_info.content(),
                message_info.is_request,
                message_info.content_info(),
                helpers,
                message_info.request,
                message_info.request_content_info,
            )
            if result is not None:
                return result

        if self.protobuf_data is None:
            raise BlackboxProtobufException(
                "Error generating HTTP body. PayloadInfo does not have valid protobuf data to encode"
            )
        raw_data = payloads.encode_payload(self.protobuf_data, self.encoding_alg)
        headers = message_info.content_info().getHeaders()
        return helpers.buildHttpMessage(headers, str(raw_data))


class LastGoodData:
    """This class stores data about the last now valid combination of message and typedef"""

    def __init__(self, message, typedef, source):
        self.message = message
        self.typedef = typedef
        self.source = source
