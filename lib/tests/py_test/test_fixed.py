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

import math
from hypothesis import given
import hypothesis.strategies as st
import strategies

from blackboxprotobuf.lib.types import fixed


# Inverse checks. Ensure a value encoded by bbp decodes to the same value
@given(x=strategies.input_map["fixed32"])
def test_fixed32_inverse(x):
    encoded = fixed.encode_fixed32(x)
    decoded, pos = fixed.decode_fixed32(encoded, 0)
    assert pos == len(encoded)
    assert decoded == x


@given(x=st.binary(min_size=4))
def test_fixed32_idem(x):
    try:
        value, pos = fixed.decode_fixed32(x, 0)
    except DecoderException:
        assume(True)
        return

    encoded = fixed.encode_fixed32(value)
    assert encoded == x[:pos]


@given(x=strategies.input_map["sfixed32"])
def test_sfixed32_inverse(x):
    encoded = fixed.encode_sfixed32(x)
    decoded, pos = fixed.decode_sfixed32(encoded, 0)
    assert pos == len(encoded)
    assert decoded == x


@given(x=st.binary(min_size=4))
def test_sfixed32_idem(x):
    try:
        value, pos = fixed.decode_sfixed32(x, 0)
    except DecoderException:
        assume(True)
        return

    encoded = fixed.encode_sfixed32(value)
    assert encoded == x[:pos]


@given(x=strategies.input_map["fixed64"])
def test_fixed64_inverse(x):
    encoded = fixed.encode_fixed64(x)
    decoded, pos = fixed.decode_fixed64(encoded, 0)
    assert pos == len(encoded)
    assert decoded == x


@given(x=st.binary(min_size=8))
def test_fixed64_idem(x):
    try:
        value, pos = fixed.decode_fixed64(x, 0)
    except DecoderException:
        assume(True)
        return

    encoded = fixed.encode_fixed64(value)
    assert encoded == x[:pos]


@given(x=strategies.input_map["sfixed64"])
def test_sfixed64_inverse(x):
    encoded = fixed.encode_sfixed64(x)
    decoded, pos = fixed.decode_sfixed64(encoded, 0)
    assert pos == len(encoded)
    assert decoded == x


@given(x=st.binary(min_size=8))
def test_sfixed64_idem(x):
    try:
        value, pos = fixed.decode_sfixed64(x, 0)
    except DecoderException:
        assume(True)
        return

    encoded = fixed.encode_sfixed64(value)
    assert encoded == x[:pos]


@given(x=strategies.input_map["float"])
def test_float_inverse(x):
    encoded = fixed.encode_float(x)
    decoded, pos = fixed.decode_float(encoded, 0)
    assert pos == len(encoded)
    if math.isnan(x):
        assert math.isnan(decoded)
    else:
        assert decoded == x


# Would be nice, but not a default type, so probably ok
# Probably asking for trouble to have a float decode then encode the same
# @given(x=st.binary(min_size=4))
# def test_float_idem(x):
#    try:
#        value, pos = fixed.decode_float(x, 0)
#    except DecoderException:
#        assume(True)
#        return
#
#    encoded = fixed.encode_float(value)
#    assert encoded == x[:pos]


@given(x=strategies.input_map["double"])
def test_double_inverse(x):
    encoded = fixed.encode_double(x)
    decoded, pos = fixed.decode_double(encoded, 0)
    assert pos == len(encoded)
    if math.isnan(x):
        assert math.isnan(decoded)
    else:
        assert decoded == x


# @given(x=st.binary(min_size=8))
# def test_double_idem(x):
#    try:
#        value, pos = fixed.decode_double(x, 0)
#    except DecoderException:
#        assume(True)
#        return
#
#    encoded = fixed.encode_double(value)
#    assert encoded == x[:pos]
