from hypothesis import given, example, note
import hypothesis.strategies as st
import hypothesis
import strategies
import warnings
import json
import six

import blackboxprotobuf


warnings.filterwarnings('ignore', 'Call to deprecated create function.*', )

try:
    import Test_pb2
except:
    import os
    os.system("cd tests/payloads; protoc --python_out ../py_test/ Test.proto; cd ../../")
    import Test_pb2

# TODO: need to find a different way to generate protobuf messages off of this
testMessage_typedef = {
    "1": {"type": "double", "name": "testDouble"},
    "2": {"type": "float", "name": "testFloat"},
    #"4": {"type": "int", "name": "testInt32"},
    "8": {"type": "int", "name": "testInt64"},
    #"16": {"type": "uint", "name": "testUInt32"},
    "32": {"type": "uint", "name": "testUInt64"},
    #"64": {"type": "sint", "name": "testSInt32"},
    "128": {"type": "sint", "name": "testSInt64"},
    "256": {"type": "fixed32", "name": "testFixed32"},
    "512": {"type": "fixed64", "name": "testFixed64"},
    "1024": {"type": "sfixed32", "name": "testSFixed32"},
    "2048": {"type": "sfixed64", "name": "testSFixed64"},
    #"4096": {"type": "int", "name": "testBool"},
    "8192": {"type": "string", "name": "testString"},
    "16384": {"type": "bytes", "name": "testBytes"},
    #"32768": {"type": "message", "name": "testEmbed",
    #          "message_typedef": {
    #                "3": {"type": "double", "name": "embedDouble"},
    #                "2": {"type": "bytes", "name": "embedString"}}
    #},
    #"65536": {"type": "packed_int", "name": "testRepeatedInt32"}
}

# Test decoding from blackboxprotobuf
@given(x=strategies.gen_message_data(testMessage_typedef))
def test_decode(x):
    message = Test_pb2.TestMessage()
    for key,value in x.items():
        setattr(message, key, value)
    encoded = message.SerializeToString()
    decoded, typedef = blackboxprotobuf.decode_message(encoded, testMessage_typedef)
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
@given(x=strategies.gen_message_data(testMessage_typedef), modify_num=st.sampled_from(sorted(testMessage_typedef.keys())))
def test_modify(x, modify_num):
    modify_key = testMessage_typedef[modify_num]["name"]
    message = Test_pb2.TestMessage()
    for key,value in x.items():
        setattr(message, key, value)
    encoded = message.SerializeToString()
    decoded, typedef = blackboxprotobuf.decode_message(encoded, testMessage_typedef)

    # eliminate any cases where protobuf defaults out a field
    hypothesis.assume(modify_key in decoded)

    if isinstance(decoded[modify_key], str):
        mod_func = lambda x: "test"
    elif six.PY2 and isinstance(decoded[modify_key], unicode):
        mod_func = lambda x: six.u("test")
    elif isinstance(decoded[modify_key], bytes):
        mod_func = lambda x: b'test'
    elif isinstance(decoded[modify_key], six.integer_types):
        mod_func = lambda x: 10
    elif isinstance(decoded[modify_key], float):
        mod_func = lambda x: 10
    else:
        hypothesis.note("Failed to modify key: %s (%r)" % (modify_key,type(decoded[modify_key]) ))
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
    for key,value in x.items():
        setattr(message, key, value)
    encoded = message.SerializeToString()

    decoded_json, typedef_json = blackboxprotobuf.protobuf_to_json(encoded, testMessage_typedef)
    hypothesis.note("Encoded JSON:")
    hypothesis.note(decoded_json)
    decoded = json.loads(decoded_json)
    hypothesis.note("Original value:")
    hypothesis.note(x)
    hypothesis.note("Decoded valuec:")
    hypothesis.note(decoded)
    for key in decoded.keys():
        if key == 'testBytes':
            decoded[key] = six.ensure_binary(decoded[key], encoding='latin1')
        assert x[key] == decoded[key]

@given(x=strategies.gen_message_data(testMessage_typedef))
@example(x={"testBytes": b"\x80"})
def test_encode_json(x):
    # Test with JSON payload
    if 'testBytes' in x:
        x['testBytes'] = x['testBytes'].decode('latin1')
    json_str = json.dumps(x)

    hypothesis.note("JSON Str Input:")
    hypothesis.note(json_str)
    hypothesis.note(json.loads(json_str))

    encoded = blackboxprotobuf.protobuf_from_json(json_str, testMessage_typedef)
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
        if key == 'testBytes':
            x[key] = six.ensure_binary(x[key], encoding='latin1')
        assert getattr(message, key) == x[key]

@given(x=strategies.gen_message_data(testMessage_typedef), modify_num=st.sampled_from(sorted(testMessage_typedef.keys())))
def test_modify_json(x, modify_num):
    modify_key = testMessage_typedef[modify_num]["name"]
    message = Test_pb2.TestMessage()
    for key,value in x.items():
        setattr(message, key, value)
    encoded = message.SerializeToString()
    decoded_json, typedef = blackboxprotobuf.protobuf_to_json(encoded, testMessage_typedef)
    decoded = json.loads(decoded_json)

    # eliminate any cases where protobuf defaults out a field
    hypothesis.assume(modify_key in decoded)

    if isinstance(decoded[modify_key], str):
        mod_func = lambda x: "test"
    elif six.PY2 and isinstance(decoded[modify_key], unicode):
        mod_func = lambda x: six.u("test")
    elif isinstance(decoded[modify_key], bytes):
        mod_func = lambda x: b'test'
    elif isinstance(decoded[modify_key], six.integer_types):
        mod_func = lambda x: 10
    elif isinstance(decoded[modify_key], float):
        mod_func = lambda x: 10
    else:
        hypothesis.note("Failed to modify key: %s (%r)" % (modify_key,type(decoded[modify_key]) ))
        assert False

    decoded[modify_key] = mod_func(decoded[modify_key])
    x[modify_key] = mod_func(x[modify_key])

    encoded = blackboxprotobuf.protobuf_from_json(json.dumps(decoded), testMessage_typedef)
    message = Test_pb2.TestMessage()
    message.ParseFromString(encoded)

    for key in decoded.keys():
        hypothesis.note("Message value:")
        hypothesis.note(type(getattr(message, key)))
        hypothesis.note("Orig value:")
        hypothesis.note((x[key]))
        if key == "testBytes":
            x[key] = six.ensure_binary(x[key], encoding='latin1')
        assert getattr(message, key) == x[key]
