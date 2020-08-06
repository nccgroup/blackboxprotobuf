from hypothesis import given
import hypothesis.strategies as st
import strategies
import six

from blackboxprotobuf.lib.types import length_delim 
from blackboxprotobuf.lib.types import type_maps

# Inverse checks. Ensure a value encoded by bbp decodes to the same value
@given(x=strategies.input_map['bytes'])
def test_bytes_inverse(x):
    encoded = length_delim.encode_bytes(x)
    decoded,pos = length_delim.decode_bytes(encoded,0)
    assert pos == len(encoded)
    assert decoded == x

@given(x=strategies.gen_message())
def test_message_inverse(x):
    type_def, message = x
    # TODO: Type is weird here, need to reconcile the return type to expected input on decode
    encoded = length_delim.encode_message(message, type_def)
    decoded, _, pos = length_delim.decode_message(encoded, type_def, 0)
    assert pos == len(encoded)
    assert message == decoded

@given(x=strategies.input_map['packed_uint'])
def test_packed_uint_inverse(x):
    encoded = type_maps.encoders['packed_uint'](x)
    decoded, pos = type_maps.decoders['packed_uint'](encoded, 0)
    assert pos == len(encoded)
    assert x == decoded

@given(x=strategies.input_map['packed_int'])
def test_packed_int_inverse(x):
    encoded = type_maps.encoders['packed_int'](x)
    decoded, pos = type_maps.decoders['packed_int'](encoded, 0)
    assert pos == len(encoded)
    assert x == decoded

@given(x=strategies.input_map['packed_sint'])
def test_packed_sint_inverse(x):
    encoded = type_maps.encoders['packed_sint'](x)
    decoded, pos = type_maps.decoders['packed_sint'](encoded, 0)
    assert pos == len(encoded)
    assert x == decoded

@given(x=strategies.input_map['packed_fixed32'])
def test_packed_fixed32_inverse(x):
    encoded = type_maps.encoders['packed_fixed32'](x)
    decoded, pos = type_maps.decoders['packed_fixed32'](encoded, 0)
    assert pos == len(encoded)
    assert x == decoded

@given(x=strategies.input_map['packed_sfixed32'])
def test_packed_sfixed32_inverse(x):
    encoded = type_maps.encoders['packed_sfixed32'](x)
    decoded, pos = type_maps.decoders['packed_sfixed32'](encoded, 0)
    assert pos == len(encoded)
    assert x == decoded

@given(x=strategies.input_map['packed_float'])
def test_packed_float_inverse(x):
    encoded = type_maps.encoders['packed_float'](x)
    decoded, pos = type_maps.decoders['packed_float'](encoded, 0)
    assert pos == len(encoded)
    assert x == decoded

@given(x=strategies.input_map['packed_fixed64'])
def test_packed_fixed64_inverse(x):
    encoded = type_maps.encoders['packed_fixed64'](x)
    decoded, pos = type_maps.decoders['packed_fixed64'](encoded, 0)
    assert pos == len(encoded)
    assert x == decoded

@given(x=strategies.input_map['packed_sfixed64'])
def test_packed_sfixed64_inverse(x):
    encoded = type_maps.encoders['packed_sfixed64'](x)
    decoded, pos = type_maps.decoders['packed_sfixed64'](encoded, 0)
    assert pos == len(encoded)
    assert x == decoded

@given(x=strategies.input_map['packed_double'])
def test_packed_double_inverse(x):
    encoded = type_maps.encoders['packed_double'](x)
    decoded, pos = type_maps.decoders['packed_double'](encoded, 0)
    assert pos == len(encoded)
    assert x == decoded
