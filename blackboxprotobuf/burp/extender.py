"""Adds the top level type definition editor and registers the protobuf message
   editor factory for individual tabs
"""
import inspect
import os
import sys
import traceback
import burp

# Add correct directory to sys.path
_BASE_DIR = os.path.abspath(os.path.dirname(inspect.getfile(inspect.currentframe())) + '../../../')
sys.path.insert(0, _BASE_DIR)
sys.path.insert(0, _BASE_DIR + '/burp-deps/protobuf/python/')
sys.path.insert(0, _BASE_DIR + '/burp-deps/six/')

from blackboxprotobuf.burp import editor, typedef_tab



EXTENSION_NAME = "BlackboxProtobuf"

class BurpExtender(burp.IBurpExtender):
    """Primary extension class. Sets up all other functionality."""


    def __init__(self):
        self.callbacks = None
        self.helpers = None
        self.known_types = None
        self.suite_tab = None

    def registerExtenderCallbacks(self, callbacks):
        """Called by burp. Collects callback object and sets up UI"""
        try:
            self.callbacks = callbacks
            self.helpers = callbacks.getHelpers()

            self.known_types = {}

            callbacks.setExtensionName(EXTENSION_NAME)

            callbacks.registerMessageEditorTabFactory(editor.ProtoBufEditorTabFactory(self))

            self.suite_tab = typedef_tab.TypeDefinitionTab(callbacks)
            callbacks.addSuiteTab(self.suite_tab)
        except Exception as exc:
            self.callbacks.printError(traceback.format_exc())
            raise exc
