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

import grpc
import Test_pb2
import Test_pb2_grpc

grpc_options = [
    ("grpc.enable_http_proxy", True),
    ("grpc.http_proxy", "http://127.0.0.1:8080"),
]

with open("proxy_cert.pem", "rb") as f:
    ssl_cert = f.read()

credentials = grpc.ssl_channel_credentials(ssl_cert)
with grpc.secure_channel(
    "127.0.0.1:8000", credentials, options=grpc_options
) as channel:
    stub = Test_pb2_grpc.TestServiceStub(channel)
    response = stub.TestRPC(Test_pb2.TestMessage(testString="test123"))
    print("Got response: %s" % response)
