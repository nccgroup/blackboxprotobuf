"""Classes for encoding and decoding varint types"""
from google.protobuf.internal import wire_format, encoder, decoder
import six

def gen_append_bytearray(arr):
    def append_bytearray(x):
        if isinstance(x, (str,int)):
            arr.append(x)
        elif isinstance(x, bytes):
            arr.extend(x)
        else:
            raise Exception("Unknown type returned by protobuf library")
    return append_bytearray

def encode_uvarint(value):
    """Encode a long or int into a bytearray."""
    output = bytearray()
    encoder._EncodeVarint(gen_append_bytearray(output), value)
    return output

def decode_uvarint(buf, pos):
    """Decode bytearray into a long."""
    # Convert buffer to string
    if six.PY2:
        buf = str(buf)
    value, pos = decoder._DecodeVarint(buf, pos)
    return (value, pos)


def encode_varint(value):
    """Encode a long or int into a bytearray."""
    output = bytearray()
    encoder._EncodeSignedVarint(gen_append_bytearray(output), value)
    return output

def decode_varint(buf, pos):
    """Decode bytearray into a long."""
    # Convert buffer to string
    if six.PY2:
        buf = str(buf)
    value, pos = decoder._DecodeSignedVarint(buf, pos)
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
