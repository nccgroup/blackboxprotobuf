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
import copy
import binascii

from blackboxprotobuf.lib.config import Config
from blackboxprotobuf.lib.types import length_delim
from blackboxprotobuf.lib.types import type_maps
from blackboxprotobuf.lib.typedef import TypeDef

if six.PY2:
    string_types = (unicode, str)
else:
    string_types = str


# Inverse checks. Ensure a value encoded by bbp decodes to the same value
@given(x=strategies.input_map["bytes"])
def test_bytes_inverse(x):
    encoded = length_delim.encode_bytes(x)
    decoded, pos = length_delim.decode_bytes(encoded, 0)
    assert isinstance(encoded, bytearray)
    assert isinstance(decoded, bytearray)
    assert pos == len(encoded)
    assert decoded == x


# Inverse checks. Ensure a value encoded by bbp decodes to the same value
@given(x=strategies.input_map["bytes"])
def test_bytes_guess_inverse(x):
    config = Config()
    # wrap the message in a new message so that it's a guess inside
    wrapper_typedef = {"1": {"type": "bytes"}}
    wrapper_message = {"1": x}

    encoded = length_delim.encode_lendelim_message(
        wrapper_message, config, TypeDef.from_dict(wrapper_typedef)
    )
    value, typedef, _, pos = length_delim.decode_lendelim_message(
        encoded, config, TypeDef()
    )
    typedef = typedef.to_dict()

    # would like to fail if it guesses wrong, but sometimes it might parse as a message
    assume(typedef["1"]["type"] == "bytes")

    assert isinstance(encoded, bytearray)
    assert isinstance(value["1"], bytearray)
    assert pos == len(encoded)
    assert value["1"] == x


@given(x=strategies.input_map["bytes"].map(binascii.hexlify))
def test_bytes_hex_inverse(x):
    encoded = length_delim.encode_bytes_hex(x)
    decoded, pos = length_delim.decode_bytes_hex(encoded, 0)
    assert isinstance(encoded, bytearray)
    assert isinstance(decoded, (bytearray, bytes))
    assert pos == len(encoded)
    assert decoded == x


@given(x=strategies.input_map["string"])
def test_string_inverse(x):
    encoded = length_delim.encode_bytes(x)
    decoded, pos = length_delim.decode_string(encoded, 0)
    assert isinstance(encoded, bytearray)
    assert isinstance(decoded, string_types)
    assert pos == len(encoded)
    assert decoded == x


@given(x=strategies.gen_message())
def test_message_inverse(x):
    config = Config()
    typedef, message = x
    encoded = length_delim.encode_lendelim_message(
        message, config, TypeDef.from_dict(typedef)
    )
    decoded, typedef_out, _, pos = length_delim.decode_lendelim_message(
        encoded, config, TypeDef.from_dict(typedef), 0
    )
    typedef_out = typedef_out.to_dict()
    note(encoded)
    note(typedef)
    note(typedef_out)
    assert isinstance(encoded, bytearray)
    assert isinstance(decoded, dict)
    assert pos == len(encoded)
    assert message == decoded


@given(x=strategies.gen_message(anon=True))
def test_anon_decode(x):
    config = Config()
    typedef, message = x
    encoded = length_delim.encode_lendelim_message(
        message, config, TypeDef.from_dict(typedef)
    )
    decoded, typedef_out, _, pos = length_delim.decode_lendelim_message(
        encoded, config, TypeDef(), 0
    )
    typedef_out = typedef_out.to_dict()
    note("Original message: %r" % message)
    note("Decoded message: %r" % decoded)
    note("Original typedef: %r" % typedef)
    note("Decoded typedef: %r" % typedef_out)

    def check_message(orig, orig_typedef, new, new_typedef):
        for field_number in set(orig.keys()) | set(new.keys()):
            # Skip cases where we accidentally wind up with an alt-typedef
            assume("-" not in field_number)
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


@given(x=strategies.gen_message())
@example(x=({"1": {"seen_repeated": True, "type": "string"}}, {"1": ["", "0"]}))
@example(
    x=(
        {
            "1": {"seen_repeated": False, "type": "sfixed32"},
            "2": {"seen_repeated": True, "type": "string"},
        },
        {"1": 0, "2": ["0", "00"]},
    )
)
def test_message_guess_inverse(x):
    config = Config()
    type_def, message = x
    # wrap the message in a new message so that it's a guess inside
    wrapper_typedef = {"1": {"type": "message", "message_typedef": type_def}}
    wrapper_message = {"1": message}

    encoded = length_delim.encode_lendelim_message(
        wrapper_message, config, TypeDef.from_dict(wrapper_typedef)
    )
    note("Encoded length %d" % len(encoded))
    value, decoded_type, _, pos = length_delim.decode_lendelim_message(
        encoded, config, TypeDef()
    )
    decoded_type = decoded_type.to_dict()

    note(value)
    assert decoded_type["1"]["type"] == "message"

    assert isinstance(encoded, bytearray)
    assert isinstance(value, dict)
    assert isinstance(value["1"], dict)
    assert pos == len(encoded)


@given(bytes_in=st.binary())
def test_message_guess_bytes(bytes_in):
    # Test that a given byte array can be decoded anonymously then re-encoded to the same bytes

    config = Config()

    # embed it in a another message so we get proper type guessing
    wrapper_typedef = {"1": {"type": "bytes"}}
    wrapper_message = {"1": bytes_in}
    bytes_in = length_delim.encode_message(
        wrapper_message, config, TypeDef.from_dict(wrapper_typedef)
    )

    decoded_message, guessed_typedef, field_order, pos = length_delim.decode_message(
        bytes_in, config, TypeDef()
    )
    guessed_typedef = guessed_typedef.to_dict()
    assert pos == len(bytes_in)
    bytes_out = length_delim.encode_message(
        decoded_message, config, TypeDef.from_dict(guessed_typedef)
    )
    assert bytes_in == bytes_out


@given(x=strategies.gen_message(anon=True), rng=st.randoms())
def test_message_ordering(x, rng):
    # messages need to preserve field ordering when encoding then decoding
    # ordering technically shouldn't matter in a protobuf message, but if we
    # decode a non-protobuf message as a protobuf and then re-encode it to
    # bytes, it will scramble the bytes and violate the rule that decoding then
    # re-encoding shouldn't change the message
    config = Config()
    typedef, message = x

    # wrap the message in a new message so that it's a guess inside
    typedef = {"1": {"type": "message", "message_typedef": typedef}}
    message = {"1": message}

    # encode to bytes first
    message_bytes = length_delim.encode_message(
        message, config, TypeDef.from_dict(typedef)
    )

    # now we have bytes that could be decoded as a message, we don't care what the original typedef is
    decoded_message, typedef, _, _ = length_delim.decode_message(
        message_bytes, config, TypeDef()
    )
    typedef = typedef.to_dict()

    message_items = list(decoded_message["1"].items())
    rng.shuffle(message_items)
    decoded_message["1"] = collections.OrderedDict(message_items)

    new_message_bytes = length_delim.encode_message(
        decoded_message, config, TypeDef.from_dict(typedef)
    )

    assert message_bytes == new_message_bytes


@given(x=strategies.input_map["packed_uint"])
def test_packed_uint_inverse(x):
    encoded = type_maps.ENCODERS["packed_uint"](x)
    decoded, pos = type_maps.DECODERS["packed_uint"](encoded, 0)
    assert isinstance(encoded, bytearray)
    assert pos == len(encoded)
    assert x == decoded


@given(x=strategies.input_map["packed_int"])
def test_packed_int_inverse(x):
    encoded = type_maps.ENCODERS["packed_int"](x)
    decoded, pos = type_maps.DECODERS["packed_int"](encoded, 0)
    assert isinstance(encoded, bytearray)
    assert pos == len(encoded)
    assert x == decoded


@given(x=strategies.input_map["packed_sint"])
def test_packed_sint_inverse(x):
    encoded = type_maps.ENCODERS["packed_sint"](x)
    decoded, pos = type_maps.DECODERS["packed_sint"](encoded, 0)
    assert isinstance(encoded, bytearray)
    assert pos == len(encoded)
    assert x == decoded


@given(x=strategies.input_map["packed_fixed32"])
def test_packed_fixed32_inverse(x):
    encoded = type_maps.ENCODERS["packed_fixed32"](x)
    decoded, pos = type_maps.DECODERS["packed_fixed32"](encoded, 0)
    assert isinstance(encoded, bytearray)
    assert pos == len(encoded)
    assert x == decoded


@given(x=strategies.input_map["packed_sfixed32"])
def test_packed_sfixed32_inverse(x):
    encoded = type_maps.ENCODERS["packed_sfixed32"](x)
    decoded, pos = type_maps.DECODERS["packed_sfixed32"](encoded, 0)
    assert isinstance(encoded, bytearray)
    assert pos == len(encoded)
    assert x == decoded


@given(x=strategies.input_map["packed_float"])
def test_packed_float_inverse(x):
    encoded = type_maps.ENCODERS["packed_float"](x)
    decoded, pos = type_maps.DECODERS["packed_float"](encoded, 0)
    assert isinstance(encoded, bytearray)
    assert pos == len(encoded)
    assert x == decoded


@given(x=strategies.input_map["packed_fixed64"])
def test_packed_fixed64_inverse(x):
    encoded = type_maps.ENCODERS["packed_fixed64"](x)
    decoded, pos = type_maps.DECODERS["packed_fixed64"](encoded, 0)
    assert isinstance(encoded, bytearray)
    assert pos == len(encoded)
    assert x == decoded


@given(x=strategies.input_map["packed_sfixed64"])
def test_packed_sfixed64_inverse(x):
    encoded = type_maps.ENCODERS["packed_sfixed64"](x)
    decoded, pos = type_maps.DECODERS["packed_sfixed64"](encoded, 0)
    assert isinstance(encoded, bytearray)
    assert pos == len(encoded)
    assert x == decoded


@given(x=strategies.input_map["packed_double"])
def test_packed_double_inverse(x):
    encoded = type_maps.ENCODERS["packed_double"](x)
    decoded, pos = type_maps.DECODERS["packed_double"](encoded, 0)
    assert isinstance(encoded, bytearray)
    assert pos == len(encoded)
    assert x == decoded


def test_seen_repeated():
    # Make sure seen_repeated gets set and perserved
    config = Config()

    message = {"1": [1, 2, 3], "2": [{"1": 1}, {"1": 1}]}
    typedef = {
        "1": {"type": "int"},
        "2": {"type": "message", "message_typedef": {"1": {"type": "int"}}},
    }

    # Make sure we set seen_repeated for lists with multiple items
    encoded = length_delim.encode_lendelim_message(
        message, config, TypeDef.from_dict(typedef)
    )
    decoded, typedef_out, _, pos = length_delim.decode_lendelim_message(
        encoded, config, TypeDef.from_dict(typedef), 0
    )
    typedef_out = typedef_out.to_dict()
    assert "seen_repeated" in typedef_out["1"]
    assert typedef_out["1"]["seen_repeated"]
    assert "seen_repeated" in typedef_out["2"]
    assert typedef_out["2"]["seen_repeated"]

    message = {"1": 1, "2": {"1": 1}}
    encoded = length_delim.encode_lendelim_message(
        message, config, TypeDef.from_dict(typedef)
    )
    decoded, typedef_out, _, pos = length_delim.decode_lendelim_message(
        encoded, config, TypeDef.from_dict(typedef), 0
    )
    typedef_out = typedef_out.to_dict()
    # Make sure we don't set seen_repeated for single
    assert "seen_repeated" not in typedef_out["1"]
    assert "seen_repeated" not in typedef_out["2"]

    typedef["1"]["seen_repeated"] = True
    typedef["2"]["seen_repeated"] = True
    decoded, typedef_out, _, pos = length_delim.decode_lendelim_message(
        encoded, config, TypeDef.from_dict(typedef), 0
    )
    typedef_out = typedef_out.to_dict()
    # Make sure we preserve seen_repeated and output as a list
    assert "seen_repeated" in typedef_out["1"]
    assert typedef_out["1"]["seen_repeated"]
    # Make sure our output is a list, even though it only has one list
    assert isinstance(decoded["1"], list)

    assert "seen_repeated" in typedef_out["2"]
    assert typedef_out["2"]["seen_repeated"]
    # Make sure our output is a list, even though it only has one list
    assert isinstance(decoded["2"], list)


def test_immutable_typedef():
    # we want to ensure that the original typedef is never modified by a decode operation
    config = Config()

    typedef0 = {
        "1": {"type": "int"},
        "2": {
            "type": "message",
            "message_typedef": {"1": {"type": "int"}},
            "alt_typedefs": {
                "2": "bytes",
                "3": {"1": {"type": "fixed64"}},
            },
        },
    }
    typedef0_deepcopy = copy.deepcopy(typedef0)
    message0 = {
        "1": 1,
        "2": {"1": 1},
    }
    data0 = length_delim.encode_lendelim_message(
        message0, config, TypeDef.from_dict(typedef0)
    )

    typedef1 = {
        "1": {"type": "int"},
        "2": {"type": "string"},
    }
    message1 = {
        "1": 5,
        "2": "Test123",
    }
    data1 = length_delim.encode_lendelim_message(
        message1, config, TypeDef.from_dict(typedef1)
    )

    length_delim.decode_lendelim_message(data1, config, TypeDef.from_dict(typedef0))
    assert typedef0 == typedef0_deepcopy

    typedef2 = {
        "1": {"type": "int"},
        "2": {
            "type": "message",
            "message_typedef": {"1": {"type": "int"}, "2": {"type": "int"}},
        },
        "3": {"type": "int"},
    }
    message2 = {
        "1": 7,
        "2": {
            "1": 1,
            "2": 3,
        },
        "3": 8,
    }
    data2 = length_delim.encode_lendelim_message(
        message2, config, TypeDef.from_dict(typedef2)
    )

    length_delim.decode_lendelim_message(data2, config, TypeDef.from_dict(typedef0))
    assert typedef0 == typedef0_deepcopy
