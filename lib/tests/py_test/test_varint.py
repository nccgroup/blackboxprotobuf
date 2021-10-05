from hypothesis import given
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
