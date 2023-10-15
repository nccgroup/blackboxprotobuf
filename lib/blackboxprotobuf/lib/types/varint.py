"""Classes for encoding and decoding varint types"""

# Copyright (c) 2018-2023 NCC Group Plc
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

import binascii
import struct

from google.protobuf.internal import wire_format, encoder, decoder
import six

from blackboxprotobuf.lib.exceptions import EncoderException, DecoderException

# These are set in decoder.py
# In theory, uvarints and zigzag varints shouldn't have a max
# But this is enforced by protobuf
MAX_UVARINT = (1 << 64) - 1
MAX_SVARINT = (1 << 63) - 1


def _gen_append_bytearray(arr):
    def _append_bytearray(x):
        if isinstance(x, (str, int)):
            arr.append(x)
        elif isinstance(x, bytes):
            arr.extend(x)
        else:
            raise EncoderException("Unknown type returned by protobuf library")

    return _append_bytearray


def encode_uvarint(value):
    """Encode a long or int into a bytearray."""
    output = bytearray()
    if value < 0:
        raise EncoderException(
            "Error encoding %d as uvarint. Value must be positive" % value
        )
    if value > MAX_UVARINT:
        raise EncoderException(
            "Error encoding %d as uvarint. Value must be %s or less"
            % (value, MAX_UVARINT)
        )
    try:
        encoder._EncodeVarint(_gen_append_bytearray(output), value)
    except (struct.error, ValueError) as exc:
        six.raise_from(EncoderException("Error encoding %d as uvarint." % value), exc)

    return output


def decode_uvarint(buf, pos):
    """Decode bytearray into a long."""
    pos_start = pos
    # Convert buffer to string
    if six.PY2:
        buf = str(buf)
    try:
        value, pos = decoder._DecodeVarint(buf, pos)
    except (TypeError, IndexError, decoder._DecodeError) as exc:
        six.raise_from(
            DecoderException(
                "Error decoding uvarint from %s..."
                % binascii.hexlify(buf[pos : pos + 8])
            ),
            exc,
        )
    # Validate that this is a cononical encoding by re-encoding the value
    test_encode = encode_uvarint(value)
    if buf[pos_start:pos] != test_encode:
        raise DecoderException(
            "Error decoding uvarint: Encoding is not standard:\noriginal:  %s\nstandard: %s"
            % (buf[pos_start:pos], test_encode)
        )

    return (value, pos)


def encode_varint(value):
    """Encode a long or int into a bytearray."""
    output = bytearray()
    if abs(value) > MAX_SVARINT:
        raise EncoderException(
            "Error encoding %d as uarint. Value must be %s or less (abs)"
            % (value, MAX_SVARINT)
        )
    try:
        encoder._EncodeSignedVarint(_gen_append_bytearray(output), value)
    except (struct.error, ValueError) as exc:
        six.raise_from(
            EncoderException("Error encoding %d as signed varint." % value), exc
        )
    return output


def decode_varint(buf, pos):
    """Decode bytearray into a long."""
    # Convert buffer to string
    pos_start = pos
    if six.PY2:
        buf = str(buf)
    try:
        value, pos = decoder._DecodeSignedVarint(buf, pos)
    except (TypeError, IndexError, decoder._DecodeError) as exc:
        six.raise_from(
            DecoderException(
                "Error decoding varint from %s..."
                % binascii.hexlify(buf[pos : pos + 8])
            ),
            exc,
        )
    # Validate that this is a cononical encoding by re-encoding the value
    test_encode = encode_varint(value)
    if buf[pos_start:pos] != test_encode:
        raise DecoderException(
            "Error decoding varint: Encoding is not standard:\noriginal:  %s\nstandard: %s"
            % (buf[pos_start:pos], test_encode)
        )
    return (value, pos)


def encode_svarint(value):
    """Zigzag encode the potentially signed value prior to encoding"""
    # zigzag encode value
    if abs(value) > MAX_SVARINT:
        raise EncoderException(
            "Error encoding %d as svarint. Value must be %s or less (abs)"
            % (value, MAX_SVARINT)
        )
    return encode_uvarint(wire_format.ZigZagEncode(value))


def decode_svarint(buf, pos):
    """Decode bytearray into a long."""
    pos_start = pos

    output, pos = decode_uvarint(buf, pos)
    # zigzag encode value
    value = wire_format.ZigZagDecode(output)

    # Validate that this is a cononical encoding by re-encoding the value
    test_encode = encode_svarint(value)
    if buf[pos_start:pos] != test_encode:
        raise DecoderException(
            "Error decoding svarint: Encoding is not standard:\noriginal:  %s\nstandard: %s"
            % (buf[pos_start:pos], test_encode)
        )

    return value, pos
