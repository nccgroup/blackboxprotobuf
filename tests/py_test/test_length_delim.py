from hypothesis import given,assume,note
import hypothesis.strategies as st
import strategies
import six
import binascii

from blackboxprotobuf.lib.types import length_delim 
from blackboxprotobuf.lib.types import type_maps

if six.PY2:
    string_types = (unicode,str)
else:
    string_types = str

# Inverse checks. Ensure a value encoded by bbp decodes to the same value
@given(x=strategies.input_map['bytes'])
def test_bytes_inverse(x):
    encoded = length_delim.encode_bytes(x)
    decoded,pos = length_delim.decode_bytes(encoded,0)
    assert isinstance(encoded, bytearray)
    assert isinstance(decoded, bytearray)
    assert pos == len(encoded)
    assert decoded == x

# Inverse checks. Ensure a value encoded by bbp decodes to the same value
@given(x=strategies.input_map['bytes'])
def test_bytes_guess_inverse(x):
    encoded = length_delim.encode_bytes(x)
    value, decoded_type = length_delim.decode_guess(encoded,0)

    # would like to fail if it guesses wrong, but sometimes it might parse as a message
    assume(decoded_type == type_maps.default_binary_type)

    decoded, pos = value
    assert isinstance(encoded, bytearray)
    assert isinstance(decoded, bytearray)
    assert pos == len(encoded)
    assert decoded == x

@given(x=strategies.input_map['bytes'].map(binascii.hexlify))
def test_bytes_hex_inverse(x):
    encoded = length_delim.encode_bytes_hex(x)
    decoded, pos = length_delim.decode_bytes_hex(encoded,0)
    assert isinstance(encoded, bytearray)
    assert isinstance(decoded, (bytearray,bytes))
    assert pos == len(encoded)
    assert decoded == x

@given(x=strategies.input_map['string'])
def test_string_inverse(x):
    encoded = length_delim.encode_bytes(x)
    decoded,pos = length_delim.decode_string(encoded,0)
    assert isinstance(encoded, bytearray)
    assert isinstance(decoded, string_types)
    assert pos == len(encoded)
    assert decoded == x

@given(x=strategies.gen_message())
def test_message_inverse(x):
    type_def, message = x
    encoded = length_delim.encode_lendelim_message(message, type_def)
    decoded, _, pos = length_delim.decode_lendelim_message(encoded, type_def, 0)
    assert isinstance(encoded, bytearray)
    assert isinstance(decoded, dict)
    assert pos == len(encoded)
    assert message == decoded

@given(x=strategies.gen_message())
def test_message_guess_inverse(x):
    type_def, message = x

    encoded = length_delim.encode_lendelim_message(message, type_def)
    value, decoded_type = length_delim.decode_guess(encoded, 0)

    assert decoded_type == 'message'
    decoded, _, pos = value

    assert isinstance(encoded, bytearray)
    assert isinstance(decoded, dict)
    assert pos == len(encoded)

@given(x=strategies.input_map['packed_uint'])
def test_packed_uint_inverse(x):
    encoded = type_maps.encoders['packed_uint'](x)
    decoded, pos = type_maps.decoders['packed_uint'](encoded, 0)
    assert isinstance(encoded, bytearray)
    assert pos == len(encoded)
    assert x == decoded

@given(x=strategies.input_map['packed_int'])
def test_packed_int_inverse(x):
    encoded = type_maps.encoders['packed_int'](x)
    decoded, pos = type_maps.decoders['packed_int'](encoded, 0)
    assert isinstance(encoded, bytearray)
    assert pos == len(encoded)
    assert x == decoded

@given(x=strategies.input_map['packed_sint'])
def test_packed_sint_inverse(x):
    encoded = type_maps.encoders['packed_sint'](x)
    decoded, pos = type_maps.decoders['packed_sint'](encoded, 0)
    assert isinstance(encoded, bytearray)
    assert pos == len(encoded)
    assert x == decoded

@given(x=strategies.input_map['packed_fixed32'])
def test_packed_fixed32_inverse(x):
    encoded = type_maps.encoders['packed_fixed32'](x)
    decoded, pos = type_maps.decoders['packed_fixed32'](encoded, 0)
    assert isinstance(encoded, bytearray)
    assert pos == len(encoded)
    assert x == decoded

@given(x=strategies.input_map['packed_sfixed32'])
def test_packed_sfixed32_inverse(x):
    encoded = type_maps.encoders['packed_sfixed32'](x)
    decoded, pos = type_maps.decoders['packed_sfixed32'](encoded, 0)
    assert isinstance(encoded, bytearray)
    assert pos == len(encoded)
    assert x == decoded

@given(x=strategies.input_map['packed_float'])
def test_packed_float_inverse(x):
    encoded = type_maps.encoders['packed_float'](x)
    decoded, pos = type_maps.decoders['packed_float'](encoded, 0)
    assert isinstance(encoded, bytearray)
    assert pos == len(encoded)
    assert x == decoded

@given(x=strategies.input_map['packed_fixed64'])
def test_packed_fixed64_inverse(x):
    encoded = type_maps.encoders['packed_fixed64'](x)
    decoded, pos = type_maps.decoders['packed_fixed64'](encoded, 0)
    assert isinstance(encoded, bytearray)
    assert pos == len(encoded)
    assert x == decoded

@given(x=strategies.input_map['packed_sfixed64'])
def test_packed_sfixed64_inverse(x):
    encoded = type_maps.encoders['packed_sfixed64'](x)
    decoded, pos = type_maps.decoders['packed_sfixed64'](encoded, 0)
    assert isinstance(encoded, bytearray)
    assert pos == len(encoded)
    assert x == decoded

@given(x=strategies.input_map['packed_double'])
def test_packed_double_inverse(x):
    encoded = type_maps.encoders['packed_double'](x)
    decoded, pos = type_maps.decoders['packed_double'](encoded, 0)
    assert isinstance(encoded, bytearray)
    assert pos == len(encoded)
    assert x == decoded
