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

import six
import struct
from blackboxprotobuf.lib.exceptions import BlackboxProtobufException

if six.PY3:
    from typing import Tuple

# gRPC over HTTP2 spec: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md

HEADER_LEN = 1 + 4


def is_grpc(payload):
    # type: (bytes) -> bool
    if len(payload) < HEADER_LEN:
        return False
    if six.PY2 and isinstance(payload, bytearray):
        payload = bytes(payload)
    compression_byte = six.indexbytes(payload, 0)
    # Change this to support 0x1 once we support compression
    if compression_byte != 0:
        return False
    message_length = struct.unpack_from(">I", payload[1:])[0]
    if len(payload) != HEADER_LEN + message_length:
        return False
    return True


def decode_grpc(payload):
    # type: (bytes) -> Tuple[bytes, str]
    """Decode GRPC. Return the protobuf data"""
    if six.PY2 and isinstance(payload, bytearray):
        payload = bytes(payload)
    if len(payload) < HEADER_LEN:
        raise BlackboxProtobufException(
            "Error decoding GRPC, payload is not long enough: %d" % len(payload)
        )

    compression_byte = six.indexbytes(payload, 0)
    if compression_byte != 0x00:
        if compression_byte == 0x01:
            # Payload is compressed
            # If a payload is compressed, the compression method is specified in the `grpc-encoding` header
            # Options are  "identity" / "gzip" / "deflate" / "snappy" / {custom}
            raise BlackboxProtobufException(
                "Error decoding GRPC. Compressed payloads are not supported"
            )
        else:
            raise BlackboxProtobufException(
                "Error decoding GRPC. First byte must be 0 or 1 to indicate compression"
            )

    message_length = struct.unpack_from(">I", payload[1:])[0]

    if len(payload) != HEADER_LEN + message_length:
        raise BlackboxProtobufException(
            "Error decoding GRPC. Payload length does not match encoded gRPC length"
        )

    data = payload[HEADER_LEN:]

    return data, "grpc"


def encode_grpc(data, encoding="grpc"):
    # type: (bytes, str) -> bytes
    if encoding != "grpc":
        raise BlackboxProtobufException(
            "Error encoding GRPC with encoding %s. GRPC is only supported with no compression"
            % encoding
        )

    payload = bytearray()
    payload.append(0x00)  # No compression
    payload.extend(struct.pack(">I", len(data)))  # Length
    payload.extend(data)

    return payload
