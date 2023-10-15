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

from .types import type_maps


class Config:
    def __init__(self):
        # Map of message type names to typedefs, previously stored at
        # `blackboxprotobuf.known_messages`
        self.known_types = {}

        # Default type for "bytes" like objects that aren't messages or strings
        # Other option is currently just 'bytes_hex'
        self.default_binary_type = "bytes"

        # Change the default type for a wiretype (eg. change ints to be signed
        # by default or fixed fields to always be float)
        self.default_types = {}

        # Configure whether bbpb should try to re-encode fields in the same
        # order they decoded
        # Field order shouldn't matter for real protobufs, but is there to ensure
        # that bytes/string are accidentally valid protobufs don't get scrambled
        # by decoding/re-encoding
        self.preserve_field_order = True

    def get_default_type(self, wiretype):
        default_type = self.default_types.get(wiretype, None)
        if default_type is None:
            default_type = type_maps.WIRE_TYPE_DEFAULTS.get(wiretype, None)

        return default_type


default = Config()
