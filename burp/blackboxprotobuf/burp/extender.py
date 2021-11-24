"""Adds the top level type definition editor and registers the protobuf message
   editor factory for individual tabs
"""
import inspect
import os
import sys
import traceback
import burp
import json
from javax.swing import DefaultListModel


# Add correct directory to sys.path
_BASE_DIR = os.path.abspath(
    os.path.dirname(inspect.getfile(inspect.currentframe())) + "../../../../"
)
sys.path.insert(0, _BASE_DIR + "/burp/")

import blackboxprotobuf
from blackboxprotobuf.lib.config import default as default_config
from blackboxprotobuf.burp import editor, typedef_tab, typedef_editor


EXTENSION_NAME = "BlackboxProtobuf"


class BurpExtender(burp.IBurpExtender, burp.IExtensionStateListener):
    """Primary extension class. Sets up all other functionality."""

    def __init__(self):
        self.open_windows = []
        self.callbacks = None
        self.helpers = None
        self.saved_types = {}
        self.suite_tab = None
        # global list of known messages for all views
        # this should mirror what is in blackboxprotobuf.known_messages
        # TODO bundle them together so it doesn't have to be manually updated
        self.known_message_model = DefaultListModel()
        self.refresh_message_model()

    def refresh_message_model(self):
        self.known_message_model.clear()
        for name in default_config.known_types.keys():
            self.known_message_model.addElement(name)

    def registerExtenderCallbacks(self, callbacks):
        """Called by burp. Collects callback object and sets up UI"""
        try:
            callbacks.registerExtensionStateListener(self)

            self.callbacks = callbacks

            self.helpers = callbacks.getHelpers()

            callbacks.setExtensionName(EXTENSION_NAME)

            callbacks.registerMessageEditorTabFactory(
                editor.ProtoBufEditorTabFactory(self, callbacks)
            )

            self.suite_tab = typedef_tab.TypeDefinitionTab(self, callbacks)
            callbacks.addSuiteTab(self.suite_tab)
            self.loadKnownMessages()
            self.refresh_message_model()
        except Exception as exc:
            self.callbacks.printError(traceback.format_exc())
            raise exc

    def loadKnownMessages(self):
        message_json = self.callbacks.loadExtensionSetting("known_types")
        if message_json:
            default_config.known_types.update(json.loads(message_json))
        saved_types = self.callbacks.loadExtensionSetting("saved_type_map")
        if saved_types:
            self.saved_types.update(json.loads(saved_types))

    def saveKnownMessages(self):
        # TODO might be good to cll this more often (eg. when messages are updated)
        # save the known messages
        self.callbacks.saveExtensionSetting(
            "known_types", json.dumps(default_config.known_types)
        )
        self.callbacks.saveExtensionSetting(
            "saved_type_map", json.dumps(self.saved_types)
        )

    def extensionUnloaded(self):
        self.saveKnownMessages()
        for window in self.open_windows:
            window.exitTypeWindow()

    def open_typedef_editor(self, message_type, callback):
        self.open_windows = [window for window in self.open_windows if window.is_open]

        window = typedef_editor.TypeEditorWindow(
            self.callbacks,
            message_type,
            callback,
        )
        window.show()

        self.open_windows.append(window)
