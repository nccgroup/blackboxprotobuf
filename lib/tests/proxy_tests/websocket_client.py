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

import zlib
import Test_pb2
import struct

import websocket

payload_type = "grpc"

message = Test_pb2.TestMessage(testString="test123").SerializeToString()

if payload_type == "gzip":
    message = zlib.compress(message, level=9, wbits=31)
elif payload_type == "grpc":
    # Fake grpc wrapper
    length = len(message)
    old_message = message
    message = bytearray()
    message.append(0x00)
    message.extend(struct.pack(">I", length))
    message.extend(old_message)

ws = websocket.WebSocket()
ws.connect(
    "ws://localhost:8000",
    proxy_type="http",
    http_proxy_host="localhost",
    http_proxy_port="8080",
    http_no_proxy=["test"],
)
print("Connected")
ws.send(bytes(message), websocket.ABNF.OPCODE_BINARY)
print("Sent message")
response_content = ws.recv()

if len(response_content) == 0:
    print("Got an Empty response")
else:
    if payload_type == "gzip":
        response_content = zlib.decompress(response_content, wbits=31)
    elif payload_type == "grpc":
        old_response_content = response_content
        compression_byte = response_content[0]
        assert compression_byte == 0
        length = struct.unpack_from(">I", response_content[1:])[0]
        response_content = old_response_content[5:]
        assert length == len(response_content)

    response_message = Test_pb2.TestMessage()
    response_message.ParseFromString(response_content)

    print(f"Got response message: {response_message}")

ws.close()
