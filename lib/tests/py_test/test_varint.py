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

from hypothesis import given, example, note, assume
import hypothesis.strategies as st
import strategies
import pytest
import six

from google.protobuf.internal import wire_format, encoder, decoder

from blackboxprotobuf.lib.types import varint
from blackboxprotobuf.lib.exceptions import EncoderException, DecoderException


# Test that for any given bytes, we don't alter them when decoding as a varint
@given(x=st.binary(max_size=10))
@example(x=b"\x80\x01")
@example(x=b"\x80\x81")
@example(x=b"\x81\x80\x80\x80\x80\x80\x80\x80\x01\x00")
@example(x=b"\x80\x80\x80\x80\x80\x80\x80\x80\x81\x00")
@example(x=b"\x80\x80\x80\x80\x80\x80\x80\x80\x81\x80")
def test_varint_idem_uvarint(x):
    try:
        decoded, pos = varint.decode_uvarint(x, 0)
    except DecoderException:
        assume(True)
        return

    encoded = varint.encode_uvarint(decoded)
    assert encoded == x[:pos]


# Test that for any given bytes, we don't alter them when decoding as a varint
@given(x=st.binary(min_size=10, max_size=10))
@example(x=b"\x80\x01")
@example(x=b"\x80\x81")
@example(x=b"\x81\x80\x80\x80\x80\x80\x80\x80\x01\x00")
@example(x=b"\x80\x80\x80\x80\x80\x80\x80\x80\x81\x00")
@example(x=b"\x80\x80\x80\x80\x80\x80\x80\x80\x81\x80")
@example(x=b"\x8d\x9b\xb0\xcc\xcf\xdc\xea\xf4\xf9\x02")
def test_varint_idem_varint(x):
    try:
        decoded, pos = varint.decode_varint(x, 0)
    except DecoderException:
        assume(True)
        return
    encoded = varint.encode_varint(decoded)
    assert encoded == x[:pos]


# Test that for any given bytes, we don't alter them when decoding as a varint
@given(x=st.binary(max_size=10))
@example(x=b"\x80\x01")
@example(x=b"\x80\x81")
@example(x=b"\x81\x80\x80\x80\x80\x80\x80\x80\x01\x00")
@example(x=b"\x80\x80\x80\x80\x80\x80\x80\x80\x81\x00")
@example(
    x=b"\x80\x80\x80\x80\x80\x80\x80\x80\x81\x80"
)  # I think this is overflowing and getting truncated on decode
def test_varint_idem_svarint(x):
    try:
        decoded, pos = varint.decode_svarint(x, 0)
    except DecoderException:
        assume(True)
        return
    encoded = varint.encode_svarint(decoded)
    assert encoded == x[:pos]


# Inverse checks. Ensure a value encoded by bbp decodes to the same value
@given(x=strategies.input_map["uint"])
@example(x=18446744073709551615)
def test_uvarint_inverse(x):
    encoded = varint.encode_uvarint(x)
    decoded, pos = varint.decode_uvarint(encoded, 0)
    assert pos == len(encoded)
    assert decoded == x


@given(x=strategies.input_map["int"])
@example(x=-1143843382522404608)
@example(x=-1)
@example(x=8784740448578833805)
def test_varint_inverse(x):
    encoded = varint.encode_varint(x)
    decoded, pos = varint.decode_varint(encoded, 0)
    assert pos == len(encoded)
    assert decoded == x


@given(x=strategies.input_map["sint"])
def test_svarint_inverse(x):
    encoded = varint.encode_svarint(x)
    decoded, pos = varint.decode_svarint(encoded, 0)
    assert pos == len(encoded)
    assert decoded == x


@given(x=st.integers(min_value=varint.MAX_UVARINT + 1))
def test_bounds_varints(x):
    with pytest.raises(EncoderException):
        varint.encode_uvarint(x)

    with pytest.raises(EncoderException):
        varint.encode_uvarint(-x)

    with pytest.raises(EncoderException):
        varint.encode_varint(x)

    with pytest.raises(EncoderException):
        varint.encode_varint(-x)

    with pytest.raises(EncoderException):
        varint.encode_svarint(x)

    with pytest.raises(EncoderException):
        varint.encode_svarint(-x)


def _gen_append_bytearray(arr):
    def _append_bytearray(x):
        if isinstance(x, (str, int)):
            arr.append(x)
        elif isinstance(x, bytes):
            arr.extend(x)
        else:
            raise EncoderException("Unknown type returned by protobuf library")

    return _append_bytearray


# Test our varint functions against google
@given(x=strategies.input_map["uint"])
def test_uvarint_encode(x):
    encoded_google = bytearray()
    encoder._EncodeVarint(_gen_append_bytearray(encoded_google), x)
    encoded_bbpb = varint.encode_uvarint(x)
    assert encoded_google == encoded_bbpb


@given(x=strategies.input_map["uint"])
def test_uvarint_decode(x):
    buf = bytearray()
    encoder._EncodeVarint(_gen_append_bytearray(buf), x)

    if six.PY2:
        buf = str(buf)
    decoded_google, _ = decoder._DecodeVarint(buf, 0)
    decoded_bbpb, _ = varint.decode_uvarint(buf, 0)
    assert decoded_google == decoded_bbpb


@given(x=strategies.input_map["int"])
def test_varint_encode(x):
    encoded_google = bytearray()
    encoder._EncodeSignedVarint(_gen_append_bytearray(encoded_google), x)
    encoded_bbpb = varint.encode_varint(x)
    assert encoded_google == encoded_bbpb


@given(x=strategies.input_map["int"])
def test_varint_decode(x):
    buf = bytearray()
    encoder._EncodeSignedVarint(_gen_append_bytearray(buf), x)

    if six.PY2:
        buf = bytes(buf)
    decoded_google, _ = decoder._DecodeSignedVarint(buf, 0)
    decoded_bbpb, _ = varint.decode_varint(buf, 0)
    assert decoded_google == decoded_bbpb


@given(x=strategies.input_map["sint"])
def test_svarint_encode(x):
    encoded_google = bytearray()
    encoder._EncodeSignedVarint(
        _gen_append_bytearray(encoded_google), wire_format.ZigZagEncode(x)
    )
    encoded_bbpb = varint.encode_svarint(x)
    assert encoded_google == encoded_bbpb


@given(x=strategies.input_map["sint"])
@example(x=-1)
def test_svarint_decode(x):
    buf = bytearray()
    encoder._EncodeSignedVarint(_gen_append_bytearray(buf), wire_format.ZigZagEncode(x))

    if six.PY2:
        buf = bytes(buf)
    decoded_google_uint, _ = decoder._DecodeVarint(buf, 0)
    decoded_google = wire_format.ZigZagDecode(decoded_google_uint)
    decoded_bbpb, _ = varint.decode_svarint(buf, 0)

    assert decoded_google == decoded_bbpb
