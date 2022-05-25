"""Classes for encoding and decoding varint types"""

# Copyright (c) 2018-2022 NCC Group Plc
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
    if six.indexbytes(buf, pos - 1) == 0x00 and (pos - pos_start) > 1:
        raise DecoderException(
            "Non standard varint encoding: %r" % binascii.hexlify(buf[pos_start:pos])
        )
    if (pos - pos_start) >= 10 and six.indexbytes(buf, pos - 1) != 0x01:
        # math here might be wrong, but it seems like the max value in uint
        # after it's been masked will have 0x01 as the last byte anything
        # greater (or less) is a non-standard encoding
        raise DecoderException(
            "Non standard signed varint encoding: %r"
            % binascii.hexlify(buf[pos_start:pos])
        )
    return (value, pos)


def encode_varint(value):
    """Encode a long or int into a bytearray."""
    output = bytearray()
    if value > (2 ** 63) or value < -(2 ** 63):
        raise EncoderException("Value %d above maximum varint size" % value)
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
    # Throw an error for a non-canonical representation. It would be nice to be
    # as flexible as possible when possible, but we also want to make sure
    # encode(decode(x)) == x for any x so that mis-parsing bytes as a message
    # doesn't change the bytes. Maybe have a way to turn off these checks via a
    # flag? We shouldn't really ever get a non-canonical representation from a
    # real protobuf representation
    if six.indexbytes(buf, pos - 1) == 0x00 and (pos - pos_start) > 1:
        raise DecoderException(
            "Non standard varint encoding: %r" % binascii.hexlify(buf[pos_start:pos])
        )
    if value < 0 and six.indexbytes(buf, pos - 1) != 0x01:
        # math here might be wrong, but it seems like the max value in uint
        # after it's been masked will have 0x01 as the last byte anything
        # greater (or less) is a non-standard encoding
        raise DecoderException(
            "Non standard signed varint encoding: %r"
            % binascii.hexlify(buf[pos_start:pos])
        )
    return (value, pos)


def encode_svarint(value):
    """Zigzag encode the potentially signed value prior to encoding"""
    # zigzag encode value
    return encode_uvarint(wire_format.ZigZagEncode(value))


def decode_svarint(buf, pos):
    """Decode bytearray into a long."""
    output, pos = decode_uvarint(buf, pos)
    # zigzag encode value
    return wire_format.ZigZagDecode(output), pos
