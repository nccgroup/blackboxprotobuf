"""Try to test the exception generation by the library. Everything should
throw some form of BlackboxProtobufException."""

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

from hypothesis import given
import hypothesis.strategies as st

from blackboxprotobuf.lib import config
from blackboxprotobuf.lib.types import fixed, varint, length_delim
from blackboxprotobuf.lib.exceptions import (
    BlackboxProtobufException,
    DecoderException,
    EncoderException,
)

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
        length_delim.decode_message(buf, config.Config())
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, EncoderException)
        pass


@given(buf=st.binary())
def test_decode_lendelim_message(buf):
    try:
        length_delim.decode_lendelim_message(buf, config.Config())
    except BlackboxProtobufException as exc:
        assert not isinstance(exc, EncoderException)
        pass
