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
_BASE_DIR = os.path.abspath(os.path.dirname(inspect.getfile(inspect.currentframe())) + '../../../../')
sys.path.insert(0, _BASE_DIR + '/burp/')

import blackboxprotobuf
from blackboxprotobuf.burp import editor, typedef_tab


EXTENSION_NAME = "BlackboxProtobuf"

class BurpExtender(burp.IBurpExtender, burp.IExtensionStateListener):
    """Primary extension class. Sets up all other functionality."""


    def __init__(self):
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
        for name in blackboxprotobuf.known_messages.keys():
            self.known_message_model.addElement(name)

    def registerExtenderCallbacks(self, callbacks):
        """Called by burp. Collects callback object and sets up UI"""
        try:
            callbacks.registerExtensionStateListener(self)

            self.callbacks = callbacks
            self.helpers = callbacks.getHelpers()

            callbacks.setExtensionName(EXTENSION_NAME)

            callbacks.registerMessageEditorTabFactory(editor.ProtoBufEditorTabFactory(self))

            self.suite_tab = typedef_tab.TypeDefinitionTab(self, callbacks)
            callbacks.addSuiteTab(self.suite_tab)
            self.loadKnownMessages()
            self.refresh_message_model()
        except Exception as exc:
            self.callbacks.printError(traceback.format_exc())
            raise exc
    def loadKnownMessages(self):
        message_json = self.callbacks.loadExtensionSetting("known_messages")
        if message_json:
            blackboxprotobuf.known_messages.update(json.loads(message_json))
        saved_types = self.callbacks.loadExtensionSetting("saved_type_map")
        if saved_types:
            self.saved_types.update(json.loads(saved_types))

    def saveKnownMessages(self):
        # save the known messages
        self.callbacks.saveExtensionSetting("known_messages", json.dumps(blackboxprotobuf.known_messages))
        self.callbacks.saveExtensionSetting("saved_type_map", json.dumps(self.saved_types))

    def extensionUnloaded(self):
        # TODO kill any open editor windows
        self.saveKnownMessages()
