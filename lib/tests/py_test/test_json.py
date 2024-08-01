"""Tests similar to the length_delim or protobuf tests, but make sure we can round trip through the JSON encode/decode """

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
import strategies
import json
import six
import binascii

from blackboxprotobuf.lib.config import Config
from blackboxprotobuf.lib.types import length_delim
from blackboxprotobuf.lib.types import type_maps
from blackboxprotobuf.lib.typedef import TypeDef
from blackboxprotobuf.lib.payloads import grpc, gzip
import blackboxprotobuf


@given(x=strategies.gen_message())
def test_message_json_inverse(x):
    config = Config()
    typedef, message = x
    encoded = length_delim.encode_message(message, config, TypeDef.from_dict(typedef))
    decoded_json, typedef_out = blackboxprotobuf.protobuf_to_json(
        encoded, config=config, message_type=typedef
    )
    blackboxprotobuf.validate_typedef(typedef_out)
    encoded_json = blackboxprotobuf.protobuf_from_json(
        decoded_json, config=config, message_type=typedef_out
    )
    assert not isinstance(encoded_json, list)
    decoded, typedef_out = blackboxprotobuf.decode_message(
        encoded_json, config=config, message_type=typedef
    )
    blackboxprotobuf.validate_typedef(typedef_out)
    assert isinstance(encoded, bytearray)
    assert isinstance(decoded, dict)
    assert message == decoded


@given(x=strategies.gen_message(), n=st.integers(min_value=2, max_value=10))
def test_multiple_encoding(x, n):
    config = Config()
    typedef, message = x
    encoded = length_delim.encode_message(message, config, TypeDef.from_dict(typedef))

    bufs = [encoded] * n
    message_json, typedef_out = blackboxprotobuf.protobuf_to_json(bufs, typedef, config)
    messages = json.loads(message_json)
    assert isinstance(messages, list)
    assert len(messages) == n

    encoded2 = blackboxprotobuf.protobuf_from_json(message_json, typedef, config)
    assert isinstance(encoded2, list)
    assert len(encoded2) == n


@given(x=strategies.gen_message(anon=True))
def test_anon_json_decode(x):
    """Create a new encoded message, the try to decode without a typedef into a
    json, from json back to binary and then  finally decode the message back to
    the original format. Makes sure json decoding can handle any types and does
    not change the essage.
    """
    config = Config()
    typedef, message = x
    encoded = blackboxprotobuf.encode_message(
        message, config=config, message_type=typedef
    )
    decoded_json, typedef_out = blackboxprotobuf.protobuf_to_json(
        encoded, config=config
    )
    blackboxprotobuf.validate_typedef(typedef_out)
    note("To Json Typedef: %r" % dict(typedef_out))
    encoded_json = blackboxprotobuf.protobuf_from_json(
        decoded_json, config=config, message_type=typedef_out
    )
    assert not isinstance(encoded_json, list)
    decoded, typedef_out = blackboxprotobuf.decode_message(
        encoded_json, config=config, message_type=typedef
    )
    blackboxprotobuf.validate_typedef(typedef_out)
    note("Original message: %r" % message)
    note("Decoded JSON: %r" % decoded_json)
    note("Decoded message: %r" % decoded)
    note("Original typedef: %r" % typedef)
    note("Decoded typedef: %r" % typedef_out)

    def check_message(orig, orig_typedef, new, new_typedef):
        for field_number in set(orig.keys()) | set(new.keys()):
            # verify all fields are there
            assert field_number in orig
            assert field_number in orig_typedef
            assert field_number in new
            assert field_number in new_typedef

            orig_values = orig[field_number]
            new_values = new[field_number]
            orig_type = orig_typedef[field_number]["type"]
            new_type = new_typedef[field_number]["type"]

            note("Parsing field# %s" % field_number)
            note("orig_values: %r" % orig_values)
            note("new_values: %r" % new_values)
            note("orig_type: %s" % orig_type)
            note("new_type: %s" % new_type)
            # Fields might be lists. Just convert everything to a list
            if not isinstance(orig_values, list):
                orig_values = [orig_values]
                assert not isinstance(new_values, list)
                new_values = [new_values]
            assert isinstance(orig_values, list)
            assert isinstance(new_values, list)

            # if the types don't match, then try to convert them
            if new_type == "message" and orig_type in ["bytes", "string"]:
                # if the type is a message, we want to convert the orig type to a message
                # this isn't ideal, we'll be using the unintended type, but
                # best way to compare. Re-encoding a  message to binary might
                # not keep the field order
                new_field_typedef = new_typedef[field_number]["message_typedef"]
                for i, orig_value in enumerate(orig_values):
                    if orig_type == "bytes":
                        (
                            orig_values[i],
                            orig_field_typedef,
                            _,
                            _,
                        ) = length_delim.decode_lendelim_message(
                            length_delim.encode_bytes(orig_value),
                            config,
                            TypeDef.from_dict(new_field_typedef),
                        )
                        orig_field_typedef = orig_field_typedef.to_dict()
                    else:
                        # string value
                        (
                            orig_values[i],
                            orig_field_typedef,
                            _,
                            _,
                        ) = length_delim.decode_lendelim_message(
                            length_delim.encode_string(orig_value),
                            config,
                            TypeDef.from_dict(new_field_typedef),
                        )
                        orig_field_typedef = orig_field_typedef.to_dict()
                    orig_typedef[field_number]["message_typedef"] = orig_field_typedef
                orig_type = "message"

            if new_type == "string" and orig_type == "bytes":
                # our bytes were accidently valid string
                new_type = "bytes"
                for i, new_value in enumerate(new_values):
                    new_values[i], _ = length_delim.decode_bytes(
                        length_delim.encode_string(new_value), 0
                    )
            note("New values: %r" % new_values)
            # sort the lists with special handling for dicts
            orig_values.sort(key=lambda x: x if not isinstance(x, dict) else x.items())
            new_values.sort(key=lambda x: x if not isinstance(x, dict) else x.items())
            for orig_value, new_value in zip(orig_values, new_values):
                if orig_type == "message":
                    check_message(
                        orig_value,
                        orig_typedef[field_number]["message_typedef"],
                        new_value,
                        new_typedef[field_number]["message_typedef"],
                    )
                else:
                    assert orig_value == new_value

    check_message(message, typedef, decoded, typedef_out)
    # assert message == decoded
