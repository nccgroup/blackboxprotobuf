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

from hypothesis import given, example, note
import hypothesis.strategies as st
import hypothesis
import strategies
import warnings
import base64
import json
import six

import blackboxprotobuf


warnings.filterwarnings(
    "ignore",
    "Call to deprecated create function.*",
)

try:
    import Test_pb2
except:
    import os

    os.system(
        "cd tests/payloads; protoc --python_out ../py_test/ Test.proto; cd ../../"
    )
    import Test_pb2

testMessage_typedef = {
    "1": {"type": "double", "name": six.u("testDouble")},
    "2": {"type": "float", "name": six.u("testFloat")},
    # "4": {"type": "int", "name": "testInt32"},
    "8": {"type": "int", "name": six.u("testInt64")},
    # "16": {"type": "uint", "name": "testUInt32"},
    "32": {"type": "uint", "name": six.u("testUInt64")},
    # "64": {"type": "sint", "name": "testSInt32"},
    "128": {"type": "sint", "name": six.u("testSInt64")},
    "256": {"type": "fixed32", "name": six.u("testFixed32")},
    "512": {"type": "fixed64", "name": six.u("testFixed64")},
    "1024": {"type": "sfixed32", "name": six.u("testSFixed32")},
    "2048": {"type": "sfixed64", "name": six.u("testSFixed64")},
    # "4096": {"type": "int", "name": "testBool"},
    "8192": {"type": "string", "name": six.u("testString")},
    "16384": {"type": "bytes", "name": six.u("testBytes")},
    # "32768": {"type": "message", "name": "testEmbed",
    #          "message_typedef": {
    #                "3": {"type": "double", "name": "embedDouble"},
    #                "2": {"type": "bytes", "name": "embedString"}}
    # },
    # "65536": {"type": "packed_int", "name": "testRepeatedInt32"}
}


# Test decoding from blackboxprotobuf
@given(x=strategies.gen_message_data(testMessage_typedef))
def test_decode(x):
    message = Test_pb2.TestMessage()
    for key, value in x.items():
        setattr(message, key, value)
    encoded = message.SerializeToString()
    decoded, typedef = blackboxprotobuf.decode_message(encoded, testMessage_typedef)
    blackboxprotobuf.validate_typedef(typedef)
    hypothesis.note("Decoded: %r" % decoded)
    for key in decoded.keys():
        assert x[key] == decoded[key]


# Test encoding with blackboxprotobuf
@given(x=strategies.gen_message_data(testMessage_typedef))
def test_encode(x):
    encoded = blackboxprotobuf.encode_message(x, testMessage_typedef)
    message = Test_pb2.TestMessage()
    message.ParseFromString(encoded)

    for key in x.keys():
        assert getattr(message, key) == x[key]


# Try to modify a random key with blackbox and re-encode
# TODO: In the future do more random modifications, like swap the whole value
@given(
    x=strategies.gen_message_data(testMessage_typedef),
    modify_num=st.sampled_from(sorted(testMessage_typedef.keys())),
)
def test_modify(x, modify_num):
    modify_key = testMessage_typedef[modify_num]["name"]
    message = Test_pb2.TestMessage()
    for key, value in x.items():
        setattr(message, key, value)
    encoded = message.SerializeToString()
    decoded, typedef = blackboxprotobuf.decode_message(encoded, testMessage_typedef)
    blackboxprotobuf.validate_typedef(typedef)

    # eliminate any cases where protobuf defaults out a field
    hypothesis.assume(modify_key in decoded)

    if isinstance(decoded[modify_key], six.text_type):
        mod_func = lambda x: six.u("test")
    elif isinstance(decoded[modify_key], bytes):
        mod_func = lambda x: b"test"
    elif isinstance(decoded[modify_key], six.integer_types):
        mod_func = lambda x: 10
    elif isinstance(decoded[modify_key], float):
        mod_func = lambda x: 10
    else:
        hypothesis.note(
            "Failed to modify key: %s (%r)" % (modify_key, type(decoded[modify_key]))
        )
        assert False

    decoded[modify_key] = mod_func(decoded[modify_key])
    x[modify_key] = mod_func(x[modify_key])

    encoded = blackboxprotobuf.encode_message(decoded, testMessage_typedef)
    message = Test_pb2.TestMessage()
    message.ParseFromString(encoded)

    for key in decoded.keys():
        assert getattr(message, key) == x[key]


## Second copies of the above methods that use the protobuf to/from json functions


@given(x=strategies.gen_message_data(testMessage_typedef))
@example(x={"testBytes": b"test123"})
@example(x={"testBytes": b"\x80"})
def test_decode_json(x):
    # Test with JSON payload
    message = Test_pb2.TestMessage()
    for key, value in x.items():
        setattr(message, key, value)
    encoded = message.SerializeToString()

    decoded_json, typedef_json = blackboxprotobuf.protobuf_to_json(
        encoded, testMessage_typedef
    )
    blackboxprotobuf.validate_typedef(typedef_json)
    hypothesis.note("Encoded JSON:")
    hypothesis.note(decoded_json)
    decoded = json.loads(decoded_json)
    hypothesis.note("Original value:")
    hypothesis.note(x)
    hypothesis.note("Decoded valuec:")
    hypothesis.note(decoded)
    for key in decoded.keys():
        if key == "testBytes":
            decoded[key] = six.ensure_binary(decoded[key], encoding="latin1")
        assert x[key] == decoded[key]


@given(x=strategies.gen_message_data(testMessage_typedef))
@example(x={"testBytes": b"\x80"})
def test_encode_json(x):
    # Test with JSON payload
    if "testBytes" in x:
        x["testBytes"] = x["testBytes"].decode("latin1")
    json_str = json.dumps(x)

    hypothesis.note("JSON Str Input:")
    hypothesis.note(json_str)
    hypothesis.note(json.loads(json_str))

    encoded = blackboxprotobuf.protobuf_from_json(json_str, testMessage_typedef)
    assert not isinstance(encoded, list)
    hypothesis.note("BBP decoding:")

    test_decode, _ = blackboxprotobuf.decode_message(encoded, testMessage_typedef)
    hypothesis.note(test_decode)

    message = Test_pb2.TestMessage()
    message.ParseFromString(encoded)
    hypothesis.note("Message:")
    hypothesis.note(message)

    for key in x.keys():
        hypothesis.note("Message value")
        hypothesis.note(type(getattr(message, key)))
        hypothesis.note("Original value")
        hypothesis.note(type(x[key]))
        if key == "testBytes":
            x[key] = six.ensure_binary(x[key], encoding="latin1")
        assert getattr(message, key) == x[key]


@given(
    x=strategies.gen_message_data(testMessage_typedef),
    modify_num=st.sampled_from(sorted(testMessage_typedef.keys())),
)
def test_modify_json(x, modify_num):
    modify_key = testMessage_typedef[modify_num]["name"]
    message = Test_pb2.TestMessage()
    for key, value in x.items():
        setattr(message, key, value)
    encoded = message.SerializeToString()
    decoded_json, typedef = blackboxprotobuf.protobuf_to_json(
        encoded, testMessage_typedef
    )
    blackboxprotobuf.validate_typedef(typedef)
    decoded = json.loads(decoded_json)

    # eliminate any cases where protobuf defaults out a field
    hypothesis.assume(modify_key in decoded)

    if isinstance(decoded[modify_key], six.text_type):
        mod_func = lambda x: six.u("test")
    elif isinstance(decoded[modify_key], bytes):
        mod_func = lambda x: b"test"
    elif isinstance(decoded[modify_key], six.integer_types):
        mod_func = lambda x: 10
    elif isinstance(decoded[modify_key], float):
        mod_func = lambda x: 10
    else:
        hypothesis.note(
            "Failed to modify key: %s (%r)" % (modify_key, type(decoded[modify_key]))
        )
        assert False

    decoded[modify_key] = mod_func(decoded[modify_key])
    x[modify_key] = mod_func(x[modify_key])

    encoded = blackboxprotobuf.protobuf_from_json(
        json.dumps(decoded), testMessage_typedef
    )
    assert not isinstance(encoded, list)
    message = Test_pb2.TestMessage()
    message.ParseFromString(encoded)

    for key in decoded.keys():
        hypothesis.note("Message value:")
        hypothesis.note(type(getattr(message, key)))
        hypothesis.note("Orig value:")
        hypothesis.note((x[key]))
        if key == "testBytes":
            x[key] = six.ensure_binary(x[key], encoding="latin1")
        assert getattr(message, key) == x[key]
