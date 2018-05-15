""" TypeDefinitionTab is a top-level Burp Suite tab which allows saved/named
    types to be added/modified at any time. It also adds options for
    importing/exporting protobuf types to .json files.
"""
import os
import json
import burp
import blackboxprotobuf
from javax.swing import JSplitPane, JScrollPane, JPanel, JButton, BoxLayout
from javax.swing import JOptionPane, JList, ListSelectionModel, JFileChooser
from javax.swing.filechooser import FileNameExtensionFilter
from java.awt import Component
from java.awt.event import ActionListener
from blackboxprotobuf.burp import typedef_editor

class TypeDefinitionTab(burp.ITab):
    """Implements an interface for editing known message type definitions."""

    def __init__(self, burp_callbacks):
        self._burp_callbacks = burp_callbacks

        self._type_list_component = JList(blackboxprotobuf.known_messages.keys())
        self._type_list_component.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)

        self._component = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self._component.setLeftComponent(JScrollPane(self._type_list_component))
        self._component.setRightComponent(self.createButtonPane())
        self._component.setResizeWeight(0.9)

    def getTabCaption(self):
        """Returns name on tab"""
        return "Protobuf Type Editor"

    def getUiComponent(self):
        """Returns Java AWT component for tab"""
        return self._component

    def createButtonPane(self):
        """Create AWT window panel for buttons"""
        self._button_listener = TypeDefinitionButtonListener(self)

        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))

        panel.add(self.createButton("New Type", "new-type"))
        panel.add(self.createButton("Edit Type", "edit-type"))
        panel.add(self.createButton("Delete Type", "delete-type"))
        panel.add(self.createButton("Save All Types To File", "save-types"))
        panel.add(self.createButton("Load All Types To File", "load-types"))
        return panel

    def createButton(self, text, command):
        """Generate new button with the given text and command string"""
        button = JButton(text)
        button.setAlignmentX(Component.CENTER_ALIGNMENT)
        button.setActionCommand(command)
        button.addActionListener(self._button_listener)
        return button

    def updateList(self):
        """Let the UI know that the list of message types has been updated"""
        self._type_list_component.setListData(blackboxprotobuf.known_messages.keys())

class TypeDefinitionButtonListener(ActionListener):
    """Callback listener for buttons in the TypeDefinition interface"""
    def __init__(self, type_def_tab):
        self._type_def_tab = type_def_tab

    def create_save_callback(self, name):
        """Generate a callback for when the save button inside an opened type
           editor window is saved. Saves the type and tells the list to
           refresh.
        """
        def save_callback(type_def):
            """Save typedef and update list for a given message name"""
            blackboxprotobuf.known_messages[name] = type_def
            self._type_def_tab.updateList()
        return save_callback

    def actionPerformed(self, event):
        """Called when a button is pressed."""
        if event.getActionCommand() == "new-type":
            type_name = JOptionPane.showInputDialog("Enter new name")

            # Error out if already defined
            if type_name in blackboxprotobuf.known_messages:
                JOptionPane.showMessageDialog(self._type_def_tab._component,
                                              "Message type %s already exists" % type_name)
                return

            typedef_editor.TypeEditorWindow(self._type_def_tab._burp_callbacks,
                                            {}, self.create_save_callback(type_name)).show()

        elif event.getActionCommand() == "edit-type":
            list_component = self._type_def_tab._type_list_component
            # Check if something is selected
            if list_component.isSelectionEmpty():
                return

            type_name = list_component.getSelectedValue()
            typedef_editor.TypeEditorWindow(self._type_def_tab._burp_callbacks,
                                            blackboxprotobuf.known_messages[type_name],
                                            self.create_save_callback(type_name)).show()

        elif event.getActionCommand() == "delete-type":
            list_component = self._type_def_tab._type_list_component
            # Check if something is selected
            if list_component.isSelectionEmpty():
                return

            type_name = list_component.getSelectedValue()
            #TODO Confirm delete?
            del blackboxprotobuf.known_messages[type_name]
            self._type_def_tab.updateList()

        elif event.getActionCommand() == 'save-types':
            chooser = JFileChooser()
            chooser.setFileFilter(FileNameExtensionFilter("JSON Type Definition", ["json"]))
            chooser.setMultiSelectionEnabled(False)

            action = chooser.showSaveDialog(self._type_def_tab.getUiComponent())
            if action == JFileChooser.CANCEL_OPTION or action == JFileChooser.ERROR_OPTION:
                return

            file_name = chooser.getSelectedFile().getCanonicalPath()
            ext = os.path.splitext(file_name)[1]
            if ext == '':
                #No extension, add .json
                file_name += '.json'

            with open(file_name, 'w+') as selected_file:
                json.dump(blackboxprotobuf.known_messages, selected_file, indent=4, sort_keys=True)

        elif event.getActionCommand() == 'load-types':
            chooser = JFileChooser()
            chooser.setFileFilter(FileNameExtensionFilter("JSON Type Definition", ["json"]))
            chooser.setMultiSelectionEnabled(False)

            action = chooser.showOpenDialog(self._type_def_tab.getUiComponent())
            if action == JFileChooser.CANCEL_OPTION or action == JFileChooser.ERROR_OPTION:
                return

            file_name = chooser.getSelectedFile().getCanonicalPath()
            types = {}
            with open(file_name, 'r') as selected_file:
                types = json.load(selected_file)
            for key, value in types.items():
                blackboxprotobuf.known_messages[key] = value
            self._type_def_tab.updateList()
