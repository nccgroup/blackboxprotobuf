""" TypeDefinitionTab is a top-level Burp Suite tab which allows saved/named
    types to be added/modified at any time. It also adds options for
    importing/exporting protobuf types to .json files.
"""
import os
import re
import json
import burp
import traceback
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
        panel.add(self.createButton("Load All Types From File", "load-types"))
        panel.add(self.createButton("Export All types As .proto", "export-proto"))
        panel.add(self.createButton("Import .proto", "import-proto"))
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
    def __init__(self, typedef_tab):
        self._typedef_tab = typedef_tab

    def create_save_callback(self, name):
        """Generate a callback for when the save button inside an opened type
           editor window is saved. Saves the type and tells the list to
           refresh.
        """
        def save_callback(typedef):
            """Save typedef and update list for a given message name"""
            blackboxprotobuf.known_messages[name] = typedef
            self._typedef_tab.updateList()
        return save_callback

    def actionPerformed(self, event):
        """Called when a button is pressed."""
        if event.getActionCommand() == "new-type":
            type_name = JOptionPane.showInputDialog("Enter new name")

            # Error out if already defined
            if type_name in blackboxprotobuf.known_messages:
                JOptionPane.showMessageDialog(self._typedef_tab._component,
                                              "Message type %s already exists" % type_name)
                return

            typedef_editor.TypeEditorWindow(self._typedef_tab._burp_callbacks,
                                            {}, self.create_save_callback(type_name)).show()

        elif event.getActionCommand() == "edit-type":
            list_component = self._typedef_tab._type_list_component
            # Check if something is selected
            if list_component.isSelectionEmpty():
                return

            type_name = list_component.getSelectedValue()
            typedef_editor.TypeEditorWindow(self._typedef_tab._burp_callbacks,
                                            blackboxprotobuf._sort_typedef(blackboxprotobuf.known_messages[type_name]),
                                            self.create_save_callback(type_name)).show()

        elif event.getActionCommand() == "delete-type":
            list_component = self._typedef_tab._type_list_component
            # Check if something is selected
            if list_component.isSelectionEmpty():
                return

            type_name = list_component.getSelectedValue()
            #TODO Confirm delete?
            del blackboxprotobuf.known_messages[type_name]
            self._typedef_tab.updateList()

        elif event.getActionCommand() == 'save-types':
            chooser = JFileChooser()
            chooser.setFileFilter(FileNameExtensionFilter("JSON Type Definition", ["json"]))
            chooser.setMultiSelectionEnabled(False)

            action = chooser.showSaveDialog(self._typedef_tab.getUiComponent())
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

            action = chooser.showOpenDialog(self._typedef_tab.getUiComponent())
            if action == JFileChooser.CANCEL_OPTION or action == JFileChooser.ERROR_OPTION:
                return

            file_name = chooser.getSelectedFile().getCanonicalPath()
            types = {}
            with open(file_name, 'r') as selected_file:
                types = json.load(selected_file)
            for key, value in types.items():
                # check to make sure we don't nuke existing messages
                if key in blackboxprotobuf.known_messages:
                    overwrite = JOptionPane.showConfirmDialog(self._typedef_tab._component, "Message %s already saved. Overwrite?" % key) == 0
                    if not overwrite:
                        continue
                blackboxprotobuf.known_messages[key] = value
            self._typedef_tab.updateList()
        elif event.getActionCommand() == 'export-proto':
            chooser = JFileChooser()
            chooser.setFileFilter(FileNameExtensionFilter("Protobuf Type Definition", ["proto"]))
            chooser.setMultiSelectionEnabled(False)

            action = chooser.showSaveDialog(self._typedef_tab.getUiComponent())
            if action == JFileChooser.CANCEL_OPTION or action == JFileChooser.ERROR_OPTION:
                return

            file_name = chooser.getSelectedFile().getCanonicalPath()
            ext = os.path.splitext(file_name)[1]
            if ext == '':
                #No extension, add .proto
                file_name += '.proto'

            if os.path.exists(file_name):
                # 0 is the YES option
                overwrite = JOptionPane.showConfirmDialog(self._typedef_tab._component, "File %s already exists. Overwrite?" % file_name) == 0
                if not overwrite:
                    return
                print("overwriting file: %s" % file_name)
            try:
                blackboxprotobuf.export_protofile(blackboxprotobuf.known_messages, file_name)
            except Exception as exc:
                self._typedef_tab._burp_callbacks.printError(traceback.format_exc())
                JOptionPane.showMessageDialog(self._typedef_tab._component, "Error saving .proto file: " + str(exc))

        elif event.getActionCommand() == 'import-proto':
            chooser = JFileChooser()
            chooser.setFileFilter(FileNameExtensionFilter("Protobuf Type Definition", ["proto"]))
            chooser.setMultiSelectionEnabled(False)

            action = chooser.showSaveDialog(self._typedef_tab.getUiComponent())
            if action == JFileChooser.CANCEL_OPTION or action == JFileChooser.ERROR_OPTION:
                return

            file_name = chooser.getSelectedFile().getCanonicalPath()
            if not os.path.exists(file_name):
                self._typedef_tab._burp_callbacks.printError("Attempted to import %s, but the file does not exist." % file_name)
                JOptionPane.showMessageDialog(self._typedef_tab._component, "File %s does not exist to import." + str(exc))
                return
            try:
                new_typedefs = blackboxprotobuf.import_protofile(file_name, save_to_known=False)
                for key, value in new_typedefs.items():
                    # check to make sure we don't nuke existing messages
                    if key in blackboxprotobuf.known_messages:
                        overwrite = JOptionPane.showConfirmDialog(self._typedef_tab._component, "Message %s already saved. Overwrite?" % key) == 0
                        if not overwrite:
                            continue
                    blackboxprotobuf.known_messages[key] = value
                self._typedef_tab.updateList()
            except Exception as exc:
                self._typedef_tab._burp_callbacks.printError(traceback.format_exc())
                JOptionPane.showMessageDialog(self._typedef_tab._component, "Error saving .proto file: " + str(exc))
