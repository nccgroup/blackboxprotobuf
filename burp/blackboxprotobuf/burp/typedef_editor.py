"""Contains classes for a window for editing type definitions. Called from both
   the message editor tab and from the suite tabs.
"""

# Copyright (c) 2018-2022 NCC Group Plc
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

import traceback
import json
import blackboxprotobuf
from java.awt import Component, Dimension, Frame
from java.awt.event import ActionListener, WindowEvent
from javax.swing import (
    JSplitPane,
    JPanel,
    JButton,
    BoxLayout,
    JOptionPane,
    JDialog,
    Box,
    JTextField,
)


class TypeEditorWindow(JDialog):
    """New free-standing window for editing a specified type definition. Will
    callback into the calling class when the type is saved
    """

    def __init__(self, burp_callbacks, typedef, callback):
        burp_window = None
        for frame in Frame.getFrames():
            if "Burp Suite" in frame.getName():
                burp_window = frame
                break
        JDialog.__init__(self, burp_window)
        self._burp_callbacks = burp_callbacks
        self._type_callback = callback
        self.setSize(1000, 700)

        self._original_typedef = typedef
        self._type_editor = burp_callbacks.createTextEditor()
        self._type_editor.setEditable(True)
        self._type_editor.setText(json.dumps(self._original_typedef, indent=4))

        splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        splitPane.setLeftComponent(self._type_editor.getComponent())
        splitPane.setRightComponent(self.createButtonPane())
        splitPane.setResizeWeight(0.8)

        self.add(splitPane)

        self.is_open = True

    def createButtonPane(self):
        """Create a new button pane with the type editor window"""
        self._button_listener = TypeEditorButtonListener(self)

        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))

        panel.add(Box.createRigidArea(Dimension(0, 5)))
        panel.add(
            self.createButton("Validate", "validate", "Check if typedef is valid")
        )
        panel.add(Box.createRigidArea(Dimension(0, 3)))
        panel.add(self.createButton("Save", "save", "Save the typedef"))
        panel.add(Box.createRigidArea(Dimension(0, 3)))
        panel.add(self.createButton("Reset", "reset", "Reset to original"))
        panel.add(Box.createRigidArea(Dimension(0, 3)))
        panel.add(self.createButton("Exit", "exit", "Close window and reset"))
        panel.add(Box.createRigidArea(Dimension(0, 3)))

        return panel

    def createButton(self, text, command, tooltip):
        """Generate a new button with a given text and command"""
        button = JButton(text)
        button.setAlignmentX(Component.CENTER_ALIGNMENT)
        button.setActionCommand(command)
        button.addActionListener(self._button_listener)
        button.setToolTipText(tooltip)
        return button

    def applyType(self):
        """Callback for the apply button. Validates the definition and calls
        the callback provided when opening the window
        """
        try:
            message_type = json.loads(self._type_editor.getText().tostring())
            blackboxprotobuf.validate_typedef(message_type, self._original_typedef)

            self._type_callback(message_type)
            self.exitTypeWindow()

        except Exception as exc:
            self._burp_callbacks.printError(traceback.format_exc())
            JOptionPane.showMessageDialog(self, "Error saving type: " + str(exc))

    def resetTypeWindow(self):
        """Callback for reset button. Resets to the original type definition"""
        self._type_editor.setText(json.dumps(self._original_typedef, indent=4))

    def exitTypeWindow(self):
        """Callback for exit button. Exits the window without saving"""
        self.is_open = False
        self.dispatchEvent(WindowEvent(self, WindowEvent.WINDOW_CLOSING))

    def validateType(self):
        """Callback for validate button. Validates the type without saving"""
        try:
            message_type = json.loads(self._type_editor.getText().tostring())
        except Exception as exc:
            self._burp_callbacks.printError(traceback.format_exc())
            JOptionPane.showMessageDialog(self, "Error decoding JSON: " + str(exc))
            return

        try:
            blackboxprotobuf.validate_typedef(message_type, self._original_typedef)
        except Exception as exc:
            self._burp_callbacks.printError(traceback.format_exc())
            JOptionPane.showMessageDialog(self, "Error validating type: " + str(exc))
            return


class TypeEditorButtonListener(ActionListener):
    """Button action listener for the type editor window"""

    def __init__(self, type_editor):
        self._type_editor = type_editor

    def actionPerformed(self, event):
        """Called when a button is pressed"""
        if event.getActionCommand() == "validate":
            self._type_editor.validateType()
        elif event.getActionCommand() == "save":
            self._type_editor.applyType()
        elif event.getActionCommand() == "reset":
            self._type_editor.resetTypeWindow()
        elif event.getActionCommand() == "exit":
            self._type_editor.exitTypeWindow()
