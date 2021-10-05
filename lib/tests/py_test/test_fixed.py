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


@given(x=strategies.input_map["sfixed32"])
def test_sfixed32_inverse(x):
    encoded = fixed.encode_sfixed32(x)
    decoded, pos = fixed.decode_sfixed32(encoded, 0)
    assert pos == len(encoded)
    assert decoded == x


@given(x=strategies.input_map["fixed64"])
def test_fixed64_inverse(x):
    encoded = fixed.encode_fixed64(x)
    decoded, pos = fixed.decode_fixed64(encoded, 0)
    assert pos == len(encoded)
    assert decoded == x


@given(x=strategies.input_map["sfixed64"])
def test_sfixed64_inverse(x):
    encoded = fixed.encode_sfixed64(x)
    decoded, pos = fixed.decode_sfixed64(encoded, 0)
    assert pos == len(encoded)
    assert decoded == x


@given(x=strategies.input_map["float"])
def test_float_inverse(x):
    encoded = fixed.encode_float(x)
    decoded, pos = fixed.decode_float(encoded, 0)
    assert pos == len(encoded)
    if math.isnan(x):
        assert math.isnan(decoded)
    else:
        assert decoded == x


@given(x=strategies.input_map["double"])
def test_double_inverse(x):
    encoded = fixed.encode_double(x)
    decoded, pos = fixed.decode_double(encoded, 0)
    assert pos == len(encoded)
    if math.isnan(x):
        assert math.isnan(decoded)
    else:
        assert decoded == x
