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

import six
import binascii
import hypothesis.strategies as st
import blackboxprotobuf
from blackboxprotobuf.lib.types import varint
from blackboxprotobuf.lib.types import type_maps

from hypothesis import settings
from hypothesis import database
from datetime import timedelta

settings.register_profile(
    "quick",
    max_examples=100,
    database=database.ExampleDatabase(".hypothesis-db"),
    print_blob=True,
)
settings.register_profile(
    "extended",
    max_examples=1000,
    database=database.ExampleDatabase(".hypothesis-db"),
    print_blob=True,
)
settings.register_profile(
    "superextended",
    max_examples=10000,
    database=database.ExampleDatabase(".hypothesis-db"),
    print_blob=True,
)
settings.load_profile("quick")


@st.composite
def message_typedef_gen(draw, max_depth=3, anon=False, types=None, named_fields=True):
    output = {}
    field_numbers = draw(
        st.lists(st.integers(min_value=1, max_value=2000).map(str), min_size=1)
    )
    # pre-generate names so we can be sure they're unique
    field_names = draw(
        st.lists(
            st.from_regex(blackboxprotobuf.NAME_REGEX),
            min_size=len(field_numbers),
            max_size=len(field_numbers),
            unique_by=lambda x: x.lower(),
        )
    )
    if types is None:
        message_types = [
            field_type
            for field_type in type_maps.WIRETYPES.keys()
            if field_type in input_map and input_map[field_type] is not None
        ]
    else:
        message_types = types

    for field_number, field_name in zip(field_numbers, field_names):
        field_number = six.ensure_text(str(field_number))
        if max_depth == 0 and "message" in message_types:
            message_types.remove("message")
        field_type = draw(st.sampled_from(message_types))
        output[field_number] = {}
        output[field_number]["type"] = field_type

        if field_type.startswith("packed"):
            output[field_number]["seen_repeated"] = True
        elif anon and field_type in [
            "message",
            "string",
            "bytes",
        ]:  # repeated fields can't be tested easily with anonymous types due to the type guessing
            output[field_number]["seen_repeated"] = False
        else:
            output[field_number]["seen_repeated"] = draw(st.booleans())

        if field_type == "message":
            output[field_number]["message_typedef"] = draw(
                message_typedef_gen(
                    max_depth=max_depth - 1,
                    anon=anon,
                    types=types,
                    named_fields=named_fields,
                )
            )

        # decide whether to give it a name
        if named_fields and not anon and draw(st.booleans()):
            output[field_number]["name"] = six.ensure_text(field_name)

    return output


@st.composite
def gen_message_data(draw, type_def):
    output = {}
    for number, field in type_def.items():
        if "name" in field and field["name"] != "":
            field_label = field["name"]
        else:
            field_label = six.ensure_text(str(number))

        field_type = field["type"]
        if field_type == "message":
            strat = gen_message_data(field["message_typedef"])
        else:
            strat = input_map[field["type"]]

        if field.get("seen_repeated", False) and not field_type.startswith("packed"):
            output[field_label] = draw(st.lists(strat, min_size=2))
        else:
            output[field_label] = draw(strat)

    return output


@st.composite
# if anon is True, typedef will only have "default" types that it will decode
# to without a typedef
def gen_message(draw, anon=False, named_fields=True):
    allowed_types = None
    if anon:
        allowed_types = list(
            filter(lambda x: x is not None, type_maps.WIRE_TYPE_DEFAULTS.values())
        )
        # add length delim wiretypes
        allowed_types += ["message", "string", "bytes"]
    type_def = draw(
        message_typedef_gen(anon=anon, types=allowed_types, named_fields=named_fields)
    )
    message = draw(gen_message_data(type_def))
    return type_def, message


# Map types to generators
input_map = {
    "fixed32": st.integers(min_value=0, max_value=(2**32) - 1),
    "sfixed32": st.integers(min_value=-(2**31), max_value=(2**31) - 1),
    "fixed64": st.integers(min_value=0, max_value=(2**64) - 1),
    "sfixed64": st.integers(min_value=-(2**63), max_value=(2**63) - 1),
    "float": st.floats(width=32, allow_nan=False),
    "double": st.floats(width=64, allow_nan=False),
    "uint": st.integers(min_value=varint.MIN_UVARINT, max_value=varint.MAX_UVARINT),
    "int": st.integers(min_value=varint.MIN_SVARINT, max_value=varint.MAX_SVARINT),
    "sint": st.integers(min_value=varint.MIN_SVARINT, max_value=varint.MAX_SVARINT),
    "bytes": st.binary(),
    "string": st.text(),
    #'bytes_hex':  st.binary().map(binascii.hexlify),
    "message": gen_message(),
}
input_map.update(
    {
        "packed_uint": st.lists(input_map["uint"], min_size=1),
        "packed_int": st.lists(input_map["int"], min_size=1),
        "packed_sint": st.lists(input_map["sint"], min_size=1),
        "packed_fixed32": st.lists(input_map["fixed32"], min_size=1),
        "packed_sfixed32": st.lists(input_map["sfixed32"], min_size=1),
        "packed_float": st.lists(input_map["float"], min_size=1),
        "packed_fixed64": st.lists(input_map["fixed64"], min_size=1),
        "packed_sfixed64": st.lists(input_map["sfixed64"], min_size=1),
        "packed_double": st.lists(input_map["double"], min_size=1),
        "packed_bytes": st.lists(input_map["bytes"], min_size=1),
        "packed_string": st.lists(input_map["string"], min_size=1),
        "packed_bytes": st.lists(input_map["bytes"], min_size=1),
        #'packed_bytes_hex': st.lists(input_map['bytes_hex'], min_size=1),
    }
)
