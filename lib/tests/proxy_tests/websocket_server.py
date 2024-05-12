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
import zlib
import struct
import asyncio
from websockets.server import serve

payload_type = "grpc"


async def handle_messages(websocket):
    async for message in websocket:
        print(f"Got message: {type(message)} {message}")
        data = message
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

        message.testString += "_server"
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

        await websocket.send(output)


async def main():
    async with serve(handle_messages, "localhost", 8000):
        await asyncio.Future()  # run forever


asyncio.run(main())
