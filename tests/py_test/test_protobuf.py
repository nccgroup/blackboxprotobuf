from hypothesis import given
import hypothesis.strategies as st
import hypothesis
import strategies
import json

import blackboxprotobuf


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
    #"8192": {"type": "bytes", "name": "testString"},
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
    encoded = str(blackboxprotobuf.encode_message(x, testMessage_typedef))
    message = Test_pb2.TestMessage()
    message.ParseFromString(encoded)

    for key in x.keys():
        assert getattr(message, key) == x[key]

# Try to modify a random key with blackbox and re-encode
# TODO: In the future do more random modifications, like swap the whole value
@given(x=strategies.gen_message_data(testMessage_typedef), modify_num=st.sampled_from(testMessage_typedef.keys()))
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
    elif isinstance(decoded[modify_key], int):
        mod_func = lambda x: 10
    elif isinstance(decoded[modify_key], long):
        mod_func = lambda x: 10
    elif isinstance(decoded[modify_key], float):
        mod_func = lambda x: 10
    else:
        hypothesis.note("Failed to modify key: %s (%r)" % (modify_key,type(decoded[modify_key]) ))
        assert False
    decoded[modify_key] = mod_func(decoded[modify_key])
    x[modify_key] = mod_func(x[modify_key])

    encoded = str(blackboxprotobuf.encode_message(decoded, testMessage_typedef))
    message = Test_pb2.TestMessage()
    message.ParseFromString(encoded)

    for key in decoded.keys():
        assert getattr(message, key) == x[key]
