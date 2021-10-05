"""Contains classes for a window for editing type definitions. Called from both
   the message editor tab and from the suite tabs.
"""
import traceback
import json
import blackboxprotobuf
from java.awt import Component
from java.awt.event import ActionListener, WindowEvent
from javax.swing import JSplitPane, JPanel, JButton, BoxLayout, JOptionPane, JFrame

class TypeEditorWindow(JFrame):
    """New free-standing window for editing a specified type definition. Will
       callback into the calling class when the type is saved
    """
    def __init__(self, burp_callbacks, typedef, callback):
        self._burp_callbacks = burp_callbacks
        self._type_callback = callback
        self.setSize(1000,700)

        self._original_typedef = typedef
        self._type_editor = burp_callbacks.createTextEditor()
        self._type_editor.setEditable(True)
        self._type_editor.setText(json.dumps(self._original_typedef, indent=4))

        splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        splitPane.setLeftComponent(self._type_editor.getComponent())
        splitPane.setRightComponent(self.createButtonPane())
        splitPane.setResizeWeight(0.8)

        self.add(splitPane)

    def createButtonPane(self):
        """Create a new button pane with the type editor window"""
        self._button_listener = TypeEditorButtonListener(self)

        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))

        panel.add(self.createButton("Validate", "validate"))
        panel.add(self.createButton("Apply", "apply"))
        panel.add(self.createButton("Reset", "reset"))
        panel.add(self.createButton("Exit", "exit"))
        return panel

    def createButton(self, text, command):
        """Generate a new button with a given text and command"""
        button = JButton(text)
        button.setAlignmentX(Component.CENTER_ALIGNMENT)
        button.setActionCommand(command)
        button.addActionListener(self._button_listener)
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
        elif event.getActionCommand() == "apply":
            self._type_editor.applyType()
        elif event.getActionCommand() == "reset":
            self._type_editor.resetTypeWindow()
        elif event.getActionCommand() == "exit":
            self._type_editor.exitTypeWindow()
