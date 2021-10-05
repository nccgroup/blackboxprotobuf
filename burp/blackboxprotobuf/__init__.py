import os
import sys
import inspect

# Add correct directory to sys.path
_BASE_DIR = os.path.abspath(
    os.path.dirname(inspect.getfile(inspect.currentframe())) + "../../../"
)

sys.path.insert(0, _BASE_DIR + "/lib/")
sys.path.insert(0, _BASE_DIR + "/burp/deps/six/")
sys.path.insert(0, _BASE_DIR + "/burp/deps/protobuf/python/")

# extend_path looks for other 'blackboxprotobuf' modules in the sys.path and
# adds them to __path__
from pkgutil import extend_path

__path__ = extend_path(__path__, __name__)

# Hack to fix loading protobuf libraries within Jython. See https://github.com/protocolbuffers/protobuf/issues/7776
def fix_protobuf():
    import six

    u = six.u

    def new_u(s):
        if s == r"[\ud800-\udfff]":
            # Don't match anything
            return "$^"
        else:
            return u(s)

    six.u = new_u


fix_protobuf()

# mirror what we do in lib so we can use blackboxprotobuf.<function>
from blackboxprotobuf.lib.api import *
