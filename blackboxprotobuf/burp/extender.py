"""Adds the top level type definition editor and registers the protobuf message
   editor factory for individual tabs
"""
import inspect
import os
import sys
import traceback
import burp
from javax.swing import DefaultListModel


# Add correct directory to sys.path
_BASE_DIR = os.path.abspath(os.path.dirname(inspect.getfile(inspect.currentframe())) + '../../../')
sys.path.insert(0, _BASE_DIR)
sys.path.insert(0, _BASE_DIR + '/burp-deps/six/')

# Hack to fix loading protobuf libraries within Jython. See https://github.com/protocolbuffers/protobuf/issues/7776
def fix_protobuf():
    import six
    u = six.u
    def new_u(s):
        if s == r'[\ud800-\udfff]':
            # Don't match anything
            return '$^'
        else:
            return u(s)
    six.u = new_u
fix_protobuf()


sys.path.insert(0, _BASE_DIR + '/burp-deps/protobuf/python/')

import blackboxprotobuf
from blackboxprotobuf.burp import editor, typedef_tab



EXTENSION_NAME = "BlackboxProtobuf"

class BurpExtender(burp.IBurpExtender):
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
            self.callbacks = callbacks
            self.helpers = callbacks.getHelpers()

            self.known_types = {}

            callbacks.setExtensionName(EXTENSION_NAME)

            callbacks.registerMessageEditorTabFactory(editor.ProtoBufEditorTabFactory(self))

            self.suite_tab = typedef_tab.TypeDefinitionTab(self, callbacks)
            callbacks.addSuiteTab(self.suite_tab)
        except Exception as exc:
            self.callbacks.printError(traceback.format_exc())
            raise exc
