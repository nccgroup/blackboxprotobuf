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

from hypothesis import given, example, note
import hypothesis.strategies as st
import strategies

from blackboxprotobuf.lib.types import varint

# Inverse checks. Ensure a value encoded by bbp decodes to the same value
@given(x=strategies.input_map["uint"])
def test_uvarint_inverse(x):
    encoded = varint.encode_uvarint(x)
    decoded, pos = varint.decode_uvarint(encoded, 0)
    assert pos == len(encoded)
    assert decoded == x


@given(x=strategies.input_map["int"])
@example(x=-1143843382522404608)
@example(x=-1)
def test_varint_inverse(x):
    encoded = varint.encode_varint(x)
    decoded, pos = varint.decode_varint(encoded, 0)
    assert pos == len(encoded)
    assert decoded == x


@given(x=strategies.input_map["sint"])
def test_svarint_inverse(x):
    encoded = varint.encode_svarint(x)
    decoded, pos = varint.decode_svarint(encoded, 0)
    assert pos == len(encoded)
    assert decoded == x
