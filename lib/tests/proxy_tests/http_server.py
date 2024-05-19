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

import Test_pb2
from http.server import BaseHTTPRequestHandler, HTTPServer
import zlib
import struct


class TestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        payload_type = self.headers.get("payload_encoding", "none")
        print(f"Got connection with payload encoding: {payload_type}")
        data = self.rfile.read1()
        if payload_type == "gzip":
            data = zlib.decompress(data, wbits=31)
        elif payload_type == "grpc":
            old_data = data
            compression_byte = data[0]
            assert compression_byte == 0
            length = struct.unpack_from(">I", data[1:])[0]
            data = old_data[5:]
            assert length == len(data)
        print("Got data: %s" % data)
        message = Test_pb2.TestMessage()
        message.ParseFromString(data)
        print("Got message: %s" % data)

        output = message.SerializeToString()

        if payload_type == "gzip":
            output = zlib.compress(output, level=9, wbits=31)
        elif payload_type == "grpc":
            # Fake grpc wrapper
            length = len(output)
            old_output = output
            output = bytearray()
            output.append(0x00)
            output.extend(struct.pack(">I", length))
            output.extend(old_output)

        self.send_response(200)
        self.send_header("content-type", "application/protobuf")
        self.send_header("content-length", len(output))
        self.end_headers()
        self.wfile.write(output)


server = HTTPServer(("", 8000), TestHandler)
server.serve_forever()
