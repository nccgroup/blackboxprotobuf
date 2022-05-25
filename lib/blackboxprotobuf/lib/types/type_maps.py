"""Contains various maps for protobuf types, including encoding/decoding
functions, wiretypes and default types
"""

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

from google.protobuf.internal import wire_format
from blackboxprotobuf.lib.types import varint, fixed, length_delim

# Map a blackboxprotobuf type to specific encoder
ENCODERS = {
    "uint": varint.encode_uvarint,
    "int": varint.encode_varint,
    "sint": varint.encode_svarint,
    "fixed32": fixed.encode_fixed32,
    "sfixed32": fixed.encode_sfixed32,
    "float": fixed.encode_float,
    "fixed64": fixed.encode_fixed64,
    "sfixed64": fixed.encode_sfixed64,
    "double": fixed.encode_double,
    "bytes": length_delim.encode_bytes,
    "bytes_hex": length_delim.encode_bytes_hex,
    "string": length_delim.encode_string,
    "packed_uint": length_delim.generate_packed_encoder(varint.encode_uvarint),
    "packed_int": length_delim.generate_packed_encoder(varint.encode_varint),
    "packed_sint": length_delim.generate_packed_encoder(varint.encode_svarint),
    "packed_fixed32": length_delim.generate_packed_encoder(fixed.encode_fixed32),
    "packed_sfixed32": length_delim.generate_packed_encoder(fixed.encode_sfixed32),
    "packed_float": length_delim.generate_packed_encoder(fixed.encode_float),
    "packed_fixed64": length_delim.generate_packed_encoder(fixed.encode_fixed64),
    "packed_sfixed64": length_delim.generate_packed_encoder(fixed.encode_sfixed64),
    "packed_double": length_delim.generate_packed_encoder(fixed.encode_double),
}

# Map a blackboxprotobuf type to specific decoder
DECODERS = {
    "uint": varint.decode_uvarint,
    "int": varint.decode_varint,
    "sint": varint.decode_svarint,
    "fixed32": fixed.decode_fixed32,
    "sfixed32": fixed.decode_sfixed32,
    "float": fixed.decode_float,
    "fixed64": fixed.decode_fixed64,
    "sfixed64": fixed.decode_sfixed64,
    "double": fixed.decode_double,
    "bytes": length_delim.decode_bytes,
    "bytes_hex": length_delim.decode_bytes_hex,
    "string": length_delim.decode_string,
    "packed_uint": length_delim.generate_packed_decoder(varint.decode_uvarint),
    "packed_int": length_delim.generate_packed_decoder(varint.decode_varint),
    "packed_sint": length_delim.generate_packed_decoder(varint.decode_svarint),
    "packed_fixed32": length_delim.generate_packed_decoder(fixed.decode_fixed32),
    "packed_sfixed32": length_delim.generate_packed_decoder(fixed.decode_sfixed32),
    "packed_float": length_delim.generate_packed_decoder(fixed.decode_float),
    "packed_fixed64": length_delim.generate_packed_decoder(fixed.decode_fixed64),
    "packed_sfixed64": length_delim.generate_packed_decoder(fixed.decode_sfixed64),
    "packed_double": length_delim.generate_packed_decoder(fixed.decode_double),
}

WIRETYPES = {
    "uint": wire_format.WIRETYPE_VARINT,
    "int": wire_format.WIRETYPE_VARINT,
    "sint": wire_format.WIRETYPE_VARINT,
    "fixed32": wire_format.WIRETYPE_FIXED32,
    "sfixed32": wire_format.WIRETYPE_FIXED32,
    "float": wire_format.WIRETYPE_FIXED32,
    "fixed64": wire_format.WIRETYPE_FIXED64,
    "sfixed64": wire_format.WIRETYPE_FIXED64,
    "double": wire_format.WIRETYPE_FIXED64,
    "bytes": wire_format.WIRETYPE_LENGTH_DELIMITED,
    "bytes_hex": wire_format.WIRETYPE_LENGTH_DELIMITED,
    "string": wire_format.WIRETYPE_LENGTH_DELIMITED,
    "message": wire_format.WIRETYPE_LENGTH_DELIMITED,
    "group": wire_format.WIRETYPE_START_GROUP,
    "packed_uint": wire_format.WIRETYPE_LENGTH_DELIMITED,
    "packed_int": wire_format.WIRETYPE_LENGTH_DELIMITED,
    "packed_sint": wire_format.WIRETYPE_LENGTH_DELIMITED,
    "packed_fixed32": wire_format.WIRETYPE_LENGTH_DELIMITED,
    "packed_sfixed32": wire_format.WIRETYPE_LENGTH_DELIMITED,
    "packed_float": wire_format.WIRETYPE_LENGTH_DELIMITED,
    "packed_fixed64": wire_format.WIRETYPE_LENGTH_DELIMITED,
    "packed_sfixed64": wire_format.WIRETYPE_LENGTH_DELIMITED,
    "packed_double": wire_format.WIRETYPE_LENGTH_DELIMITED,
}

# Default values to use when decoding each wire type
# length delimited is special and handled in the length_delim module
WIRE_TYPE_DEFAULTS = {
    wire_format.WIRETYPE_VARINT: "int",
    wire_format.WIRETYPE_FIXED32: "fixed32",
    wire_format.WIRETYPE_FIXED64: "fixed64",
    wire_format.WIRETYPE_LENGTH_DELIMITED: None,
    wire_format.WIRETYPE_START_GROUP: None,
    wire_format.WIRETYPE_END_GROUP: None,
}
