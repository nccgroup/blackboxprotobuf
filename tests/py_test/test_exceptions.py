"""Try to test the exception generation by the library. Everything should
throw some form of BlackboxProtobufException."""

from hypothesis import given
import hypothesis.strategies as st

from blackboxprotobuf.lib.types import fixed, varint, length_delim
from blackboxprotobuf.lib.exceptions import BlackboxProtobufException, DecoderException, EncoderException

# Fixed exception tests

## Encoding
@given(value=st.integers())
def test_encode_fixed32(value):
    try:
        fixed.encode_fixed32(value)
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, DecoderException)
        pass
@given(value=st.integers())
def test_encode_sfixed32(value):
    try:
        fixed.encode_sfixed32(value)
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, DecoderException)
        pass
    
@given(value=st.decimals())
def test_encode_float(value):
    try:
        fixed.encode_float(value)
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, DecoderException)
        pass
@given(value=st.integers())
def test_encode_fixed64(value):
    try:
        fixed.encode_fixed64(value)
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, DecoderException)
        pass
@given(value=st.integers())
def test_encode_sfixed64(value):
    try:
        fixed.encode_sfixed64(value)
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, DecoderException)
        pass

@given(value=st.decimals())
def test_encode_double(value):
    try:
        fixed.encode_double(value)
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, DecoderException)
        pass

## Decoding

@given(buf=st.binary(max_size=100), pos=st.integers(max_value=200))
def test_decode_fixed32(buf, pos):
    try:
        fixed.decode_fixed32(buf, pos)
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, EncoderException)
        pass
@given(buf=st.binary(max_size=100), pos=st.integers(max_value=200))
def test_decode_sfixed32(buf, pos):
    try:
        fixed.decode_sfixed32(buf, pos)
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, EncoderException)
        pass
@given(buf=st.binary(max_size=100), pos=st.integers(max_value=200))
def test_decode_float(buf, pos):
    try:
        fixed.decode_float(buf, pos)
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, EncoderException)
        pass
@given(buf=st.binary(max_size=100), pos=st.integers(max_value=200))
def test_decode_fixed64(buf, pos):
    try:
        fixed.decode_fixed64(buf, pos)
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, EncoderException)
        pass
@given(buf=st.binary(max_size=100), pos=st.integers(max_value=200))
def test_decode_sfixed64(buf, pos):
    try:
        fixed.decode_sfixed64(buf, pos)
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, EncoderException)
        pass
@given(buf=st.binary(max_size=100), pos=st.integers(max_value=200))
def test_decode_double(buf, pos):
    try:
        fixed.decode_double(buf, pos)
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, EncoderException)
        pass

# Varint exception tests
@given(value=st.integers())
def test_encode_uvarint(value):
    try:
        varint.encode_uvarint(value)
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, DecoderException)
        pass

@given(value=st.integers())
def test_encode_varint(value):
    try:
        varint.encode_varint(value)
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, DecoderException)
        pass

@given(value=st.integers())
def test_encode_svarint(value):
    try:
        varint.encode_svarint(value)
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, DecoderException)
        pass

@given(buf=st.binary(max_size=32), pos=st.integers(max_value=64))
def test_decode_uvarint(buf, pos):
    try:
        varint.decode_uvarint(buf, pos)
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, EncoderException)
        pass

@given(buf=st.binary(max_size=32), pos=st.integers(max_value=64))
def test_decode_varint(buf, pos):
    try:
        varint.decode_varint(buf, pos)
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, EncoderException)
        pass

@given(buf=st.binary(max_size=32), pos=st.integers(max_value=64))
def test_decode_svarint(buf, pos):
    try:
        varint.decode_svarint(buf, pos)
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, EncoderException)
        pass

# length_delim exception tests

@given(value=st.binary())
def encode_bytes(value):
    try:
        length_delim.encode_bytes(value) 
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, DecoderException)
        pass

@given(value=st.binary(), pos=st.integers(max_value=2000))
def test_decode_bytes(value, pos):
    try:
        length_delim.decode_bytes(value, pos)
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, EncoderException)
        pass

@given(value=st.binary())
def test_encode_bytes_hex(value):
    try:
        length_delim.encode_bytes_hex(value)
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, DecoderException)
        pass

@given(buf=st.binary(), pos=st.integers(max_value=2000))
def test_decode_bytes_hex(buf, pos):
    try:
        length_delim.decode_bytes_hex(buf, pos)
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, EncoderException)
        pass

@given(value=st.binary(), pos=st.integers(max_value=2000))
def test_decode_string(value, pos):
    try:
        length_delim.decode_string(value, pos)
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, EncoderException)
        pass

@given(buf=st.binary())
def test_decode_message(buf):
    try:
        length_delim.decode_message(buf)
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, EncoderException)
        pass

@given(buf=st.binary())
def test_decode_lendelim_message(buf):
    try:
        length_delim.decode_lendelim_message(buf)
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, EncoderException)
        pass
