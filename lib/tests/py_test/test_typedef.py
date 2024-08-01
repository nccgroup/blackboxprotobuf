# Copyright (c) 2018-2024 NCC Group Plc
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

from hypothesis import given, assume, note, example, reproduce_failure
import hypothesis.strategies as st
import collections
import strategies
import six
import binascii

from blackboxprotobuf.lib.config import Config
from blackboxprotobuf.lib.types import length_delim
from blackboxprotobuf.lib.types import type_maps
from blackboxprotobuf.lib.typedef import TypeDef


# Test for bug when alt typedef string is unicode/string
def test_alt_typedef_unicode():
    config = Config()

    typedef = {
        "1": {"type": "message", "message_typedef": {}, "alt_typedefs": {"1": "string"}}
    }

    message = {"1-1": "test"}

    data = length_delim.encode_message(message, config, TypeDef.from_dict(typedef))
    length_delim.decode_message(data, config, TypeDef.from_dict(typedef))

    # try unicode too
    typedef = {
        "1": {"type": "message", "message_typedef": {}, "alt_typedefs": {"1": "string"}}
    }
    data = length_delim.encode_message(message, config, TypeDef.from_dict(typedef))
    length_delim.decode_message(data, config, TypeDef.from_dict(typedef))


def test_alt_field_id_unicode():
    # Check for bug when field id is a str and not unicode in python2
    config = Config()

    typedef = {
        "1": {"type": "message", "message_typedef": {}, "alt_typedefs": {"1": "string"}}
    }

    message = {"1-1": "test"}

    data = length_delim.encode_message(message, config, TypeDef.from_dict(typedef))
    length_delim.decode_message(data, config, TypeDef.from_dict(typedef))

    # try unicode
    message = {"1-1": "test"}

    data = length_delim.encode_message(message, config, TypeDef.from_dict(typedef))
    length_delim.decode_message(data, config, TypeDef.from_dict(typedef))
