import hypothesis.strategies as st
from blackboxprotobuf.lib.types import type_maps

from hypothesis import settings
from hypothesis import database
from datetime import timedelta

settings.register_profile("quick", max_examples=100, database=database.ExampleDatabase("~/.hypothesis-db"))
settings.register_profile("extended", max_examples=1000, database=database.ExampleDatabase("~/.hypothesis-db"))
settings.load_profile("quick")

@st.composite
def message_typedef_gen(draw):
    output = {}
    field_numbers = draw(st.lists(st.integers(min_value=1, max_value=2000).map(str)))
    for field_number in field_numbers:
        field_type = draw(st.sampled_from(message_types))
        output[field_number] = {}
        output[field_number]['type'] = field_type
        if field_type == 'message':
            output[field_number]['message_typedef'] = draw(message_typedef_gen())
    return output

@st.composite
def gen_message_data(draw, type_def):
    output = {}
    for number,field in type_def.items():
        if 'name' in field and field['name'] != "":
            field_label = field["name"]
        else:
            field_label = str(number)

        field_type = field['type']
        strat = input_map[field['type']]
        if field_type == 'message':
            output[field_label] = draw(gen_message_data(field['message_typedef']))
        else:
            output[field_label] = draw(strat)
    return output

@st.composite
def gen_message(draw):
    type_def = draw(message_typedef_gen())
    message = draw(gen_message_data(type_def))
    return type_def, message

# Map types to generators
input_map = {
    'fixed32': st.integers(min_value=0, max_value=(2**32)-1),
    'sfixed32': st.integers(min_value=-(2**16), max_value=2**16),
    'fixed64': st.integers(min_value=0, max_value=(2**64)-1),
    'sfixed64': st.integers(min_value=-(2**32), max_value=2**32),
    'float': st.floats(width=32, allow_nan=False),
    'double': st.floats(width=64, allow_nan=False),
    'uint': st.integers(min_value=0, max_value=2**63),
    'int': st.integers(min_value=-(2**63), max_value=2**63),
    'sint': st.integers(min_value=-(2**63), max_value=2**63),
    'bytes':  st.binary(),
    'bytes_unicode':  st.characters(),
    'message':  gen_message(),
    'group': None
}
input_map.update({
    'packed_uint': st.lists(input_map['uint']),
    'packed_int': st.lists(input_map['int']),
    'packed_sint':st.lists(input_map['sint']),
    'packed_fixed32': st.lists(input_map['fixed32']),
    'packed_sfixed32': st.lists(input_map['sfixed32']),
    'packed_float': st.lists(input_map['float']),
    'packed_fixed64': st.lists(input_map['fixed64']),
    'packed_sfixed64': st.lists(input_map['sfixed64']),
    'packed_double': st.lists(input_map['double']),
})

message_types = [ wiretype for wiretype in type_maps.wiretypes.keys() if wiretype in input_map and input_map[wiretype] is not None ]
