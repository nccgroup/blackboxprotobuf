# Type Definitions

Type Definitions (also referred to as typedefs) are the data structure the BBPB
uses to remember metadata about a message and it's fields. It contains the
exact type for each field and other metadata such as the field name.

## Decoding

The typedef is *optional* when decoding a message. Field types and names will be
used during decoding if they are provided, but if there is no typedef or the
typedef doesn't contain metadata for a field, BBPB will choose a default type
based on the field's "wire type" (see Wire Types) below.

The default type guessed by BBPB during decoding may not match the actual type
and is simply a best effort guess. The user may need to use the typedef to
change the type to the correct value.

The decoding function will return a type definition which contains what types
it used to decode each field number in the message. These types are required to
be able to re-encode the message. If a typedef was provided to the decoder, the
decoding function returns a copy of the typedef and adds type values for any
unknown fields.

## Encoding

The typedef is *required* when encoding a message back to a protobuf message.
It contains the data necessary for the encoder to map each message field to the
correct binary representation. If the message has a field that is not in the
typedef, it will raise an exception.

In most cases, the encoder should be provided with the exact type definition
returned by the decoder. Modifying the type definition before encoding could
lead to unexpected errors with data type mismatches and inconsistent encoding.
If you wish to change the type of a field in the message, the message should be
decoded again with the modified typedef.

## Type Definition Format

A type definition is a Python dictionary/JSON object where each key is the
field number and the value is metadata about the field (called the Field
Definition).

For example:

~~~
{
    "1": { "name": "email",
           "type": "string",
         },
    "2": { "name": "uid",
           "type": "int",
         },
    "3": {
           "type": "string",
         }
}
~~~

The field definition may contain the following fields:

### `type` (Required)

The type field is a required field which should contain the BBPB type for this
field. These types map roughly to protobuf types, but may not be an exact
match. 

The following types are valid BBPB types:
- `uint`
- `int`
- `sint`
- `fixed32`
- `sfixed32`
- `float`
- `fixed64`
- `sfixed64`
- `double`
- `bytes`
- `bytes_hex`
- `string`
- `message`
- `packed_uint`
- `packed_int`
- `packed_sint`
- `packed_fixed32`
- `packed_sfixed32`
- `packed_float`
- `packed_fixed64`
- `packed_sfixed64`
- `packed_double`

The latest list of types can also be found in
[type_maps.py](/lib/blackboxprotobuf/lib/types/type_maps.py).

### `name` 

User friendly name for the field which can be used instead of the field number
in decoded messages. If the name is an empty string (`""`), it is ignored.

### `message_typedef` 

Either `message_typedef` or `message_type_name` are required if `type` is
`message`. A type of `message` indicates that this field contains an
sub-message. This field contains the type definition used to encode/decode the
sub-message.

### `message_type_name` 

This field is an alternative to `message_typedef` and should reference another
type definition in `config.known_types`. The type definitions in `known_types`
will be used for this field instead of an embedded type definition. This can
greatly simplify the type definition and allow for type definitions to be
reused between different messages.

### `alt_typedefs`

The `alt_typedefs` field is a dictionary which contains "alternative"
types/type definitions for a `message` type field.

Generally, protobuf does not allow a single field number to have different
types, whether within the same message or across multiple messages of the same
type. However, a common pattern is to embed another protobuf message using the
`bytes` type instead of specific message type. This pattern is promoted by the
`google.protobuf.Any` type, which is described at
<https://protobuf.dev/programming-guides/proto3/#any>.

This means that two protobuf messages encoded with the same message type could
have embedded messages with entirely different types, and BBPB does not have a
way to determine which type was used or predict the type of future messages.

The "technically correct" way to handle these messages is to set the type to
`bytes` and not decode the embedded message, but that's not very useful.
Instead, if BBPB already has a `message_typedef` for a particular field and
that `message_typedef` is not valid to decode an instance of the field, it will
try to use any type definitions in `alt_typedefs`. If no type definitions in
`alt_typedefs` work, BBPB will add a new type definition to `alt_typedefs`.

Alternate type definitions are numbered starting at `1`, where `0` generally
refers to the primary type definition stored in `message_typedef`. In the
decoder output, the alternate type definition number is placed after a `-` in
the field name or number to indicate which definition was used to decode the
field, and therefore which definition should be used to re-encode it.

For example a message with `{"1-2": { ... }}`  indicates that field number `1`
was decoded with `alt_typedefs[2]`. The field name can also be used instead of
the field number, such as `{"user_profile-2": { ... }}`.

In some rare cases, the `alt_typedef` dictionary can contain a string with a
type (such as `string` or `bytes`) instead of a type definition. This should
only happen if a field contained a decodable message when the typedef was
created, but BBPB did not recognize a valid protobuf message on a subsequent
run.

### `field_order`

Field order contains the order in which fields were decoded in a protobuf
sub-message. This helps BBPB avoid accidentally mutating byte fields that are
mistakenly decoded as messages, but should never be required for a legitimate
protobuf message. 

This field can be disabled by setting `config.preserve_field_order` to `False`.

### `example_value_ignored` 

This field may contain an example value from the decoded protobuf message. The
field is only populated to help identify the correct field number in the
typedef to edit and is ignored during encoding and decoding.

## Wire Types

The protobuf binary does not contain exact type information for data fields.
Each encoded field has a field number and a "wire type". The wire type tells
the decoder how to determine the length of the field. This is important for
backwards compatibility, because it allows the decoder to skip fields that it
doesn't recognize and still parse the rest of the message.

For more information see
<https://protobuf.dev/programming-guides/encoding/#structure>.

Protobuf defines the following wire types:

- Varint: Variable length integer representation, one bit of each byte is used
  to signal if it is the last byte
- Fixed 64 bit: 64 bit number, could be an integer or a floating point number
- Fixed 32 bit: 32 bit number, could be an integer or a floating point number
- Length Delimited: Field data is prefixed with a varint containing the data
  length
- Start/End Group: Not a field itself, but groups together fields between the
  tags. Deprecated in favor of sub-messages and not supported by BBPB.


Based on the wiretype, BBPB can make a guess at the correct type for each
field, and also ensure that the field can be re-encoded back to valid protobuf.

## Modifying TypeDefs
### Changing Field Types

The type of an individual field can be corrected by modifying the "type" field
in the typedef using the modified typedef to decode the protobuf data again.
Avoid using the modified typedef directly with the encoder function (instead of
decoding again), as this could produce inconsistent protobuf data.

The modified type must have the same wiretype as the original type in the
typedef, otherwise the typedef will be invalid for the original protobuf data.
For example, you can change an `int` value to `sint` to use zigzag encoding,
but cannot change it to `float` or `double`.

#### Varint Types

The varint wire type is a variable length encoding for integers. One bit of
each byte is used to indicate whether there is another byte or if this is the
final byte.

Varints can map to several BBPB types:

- `int` (default) - can represent positive and negative values
    - negative values are represented using two's complement, which means that
      the highest bit must be set for negative numbers
    - two's complement requires the largest possible number of varint bytes to
      represent negative numbers, making it inefficient if negative values are
      common
    - this is the default because it can represent most unsigned integers
      correctly, even if the original type is `uint`
- `uint` - unsigned integers, can represent larger values than `int`
    - Choose this type if BBPB is decoding to negative numbers when they should
      always be positive
- `sint` - can represent positive and negative values through Zigzag encoding
    - Zigzag encoding maps unsigned integers to signed integers by switching
      between positive and negative values. For example, 0 -> 0, 1 -> -1, 2 ->
      +1, 3 -> -2, ...
    - Represents small negative numbers more efficiently than `int`, as smaller
      values such as `-1` will only requires a single byte to encode instead of
      the varint maximum
    - Choose this type if the decoded numbers are off by ~ 2x from expected
      values or numbers are being decoded as positive when they should be
      negative

Boolean values do not have a dedicated type in BBPB, but are encoded as a varint with a value of 0 for False or 1 for True.

See <https://protobuf.dev/programming-guides/encoding/#varints> and
<https://protobuf.dev/programming-guides/encoding/#int-types> for more
information on varint encoding.

#### Fixed 64 Types

Fixed 64 wiretype indicates that the field is always 64 bits. This can be used
to represent floating point numbers and either signed or unsigned integers.

Valid types are:
- `fixed64` (default) - unsigned 64 bit integer
- `sfixed64` - signed 64 bit integer
- `double` - 64 bit floating point number

The default value is an integer value. `double` might make more sense as a
default choice, but will require further research before changing globally. See
"Changing Default Types" for how to change the default on a per-project basis

#### Fixed 32 Types

Fixed 32 wiretype indicates that the field is always 32 bits. This can be used
to represent floating point numbers and either signed or unsigned integers.

Valid types are:
- `fixed32` (default) - unsigned 32 bit integer
- `sfixed32` - signed 32 bit integer
- `float` - 32 bit floating point number

The default value is an integer value. `float` might make more sense as a
default choice, but will require further research before changing globally. See
"Changing Default Types" for how to change the default on a per-project basis

#### Length Delimited Types

The length delimited wiretype means that the field starts with a varint
representing the length of the field in bytes. This wiretype is the broadest
and can represent a wide variety of field types, including embedded messages,
strings, bytes and packed fields.

Instead of a single default type for length delimited fields, BBPB will first
try to decode the field as a `message`, then fallback to `string` if decoding
fails, and finally fall back to `bytes` if `string` fails.

Valid types are:
- `message` - bytes represent an encoded protobuf message
    - The type definition for the embedded message is stored in the `message_typedef` field.
    - Alternatively, the `message_type_name`field can be used to reference another named typedef without embedding the entire typedef.
- `bytes` - parse field bytes directly as python bytes, can represent any length delimited field
- `bytes_hex` - same as bytes, but encode to a string using hex
- `string` - represents UTF-8 or ASCII strings
- `packed_*` - Packed fields are a more efficient mechanism for representing
  repeated values, such as a list or array, by removing the need for repeated
  tags (varint containing field number and wiretype) when encoding.
    - The following packed types are supported by BBPB:
        - `packed_uint`
        - `packed_int`
        - `packed_sint`
        - `packed_fixed32`
        - `packed_sfixed32`
        - `packed_float`
        - `packed_fixed64`
        - `packed_sfixed64`
        - `packed_double`
    - BBPB does not have a mechanism for detecting packed fields and these
      types must be set explicitly by the user.

See <https://protobuf.dev/programming-guides/encoding/#length-types> for more
information on length delimited encoding.

### Changing Default Types

While editing the type definition can be used to change the types of existing
fields, it's also possible to change the default type used for a particular
wire type. Changing the default type must follow the same rule as type editing:
the wiretype on the new type must be the same as the original wiretype.

The default type for a wiretype can be modified by providing a `Config` object
to the decoder and overriding the default type using the `default_types`
dictionary (in [config.py](/lib/blackboxprotobuf/lib/config.py#L49>)). The key
for the dictionary is the wiretype, which can be found in
[wiretypes.py](/lib/blackboxprotobuf/lib/types/wiretypes.py) and match the
wiretypes at <https://protobuf.dev/programming-guides/encoding/#structure>.

For example:

~~~
config.default_types[wiretypes.FIXED64] = 'double'
~~~

The `default_types` field in `Config` is not used for length delimited types,
because of the special fallback logic for length delimited fields. For these
fields, you can replace the `bytes` fallback type by changing
`default_binary_type` on the [`Config` object](
/lib/blackboxprotobuf/lib/config.py#L45>). However, unlike default types, the
decoder will still try to decode the field as a message or string before
falling back to `default_binary_type`.

The default binary type is primarily intended to allow changing the binary
representation, such as `bytes_hex` instead of `bytes`, but could also be used
to default to trying a packed type.

### Naming Fields

By default, the decoded message will use the field number as a dictionary key.
However, users can add a more readable name to the field by modifying the
"name" field.

The "name" field will be used as the dictionary key in the decoded message. The
encoder will accept either the original field number or the name specified in
the "name" field of the typedef. The field name needs to be unique and should
be alphanumeric with underscores, but cannot start with a number (see regex in
[api.py](/lib/blackboxprotobuf/lib/api.py#L310)).

### Creating Type Definitions And Fields From Scratch

While many workflows with BBPB are designed around editing a type definition
generated by the decoder, it is still possible to manually add new fields or
create new type definitions from scratch.

To add a new protobuf field to an existing typedef, simply add a new key to the
typedef dictionary (either top level dictionary or within a `message_typedef`
dictionary) and add the appropriate `type` field. The `name` field is optional,
but will greatly increase readability.

For example:

~~~
{
    "1": { ... (existing field number) ... },
    "5": {
        "name": "uid",
        "type": "int"
    }
}
~~~

or:

~~~
typedef["5"] = {
    "name": "uid",
    "type": "int
}
~~~

If the `type` is `message`, then either `message_typedef` or
`message_type_name` is also required. `message_typedef` should contain a
dictionary representing the type definition for that field.


If you know the fields of the protobuf from another source, it's possible to
create type definitions from scratch. Simply create a dictionary for the top
level message type definition where each key is a string containing the field
number and the value of each entry is a dictionary containing the field
information.

Each protobuf field is required to have a `type` attribute containing the BBPB
type. The `name` attribute is optional but recommended for readability.

### Cleaning Up Typedefs

If a type definition will be saved for re-use or embedded in code, it can be
cleaned up to improve readability and minimize the size of the definition.

Any field number which has not been modified from the default value can be
removed from the definition or from any `message_typedefs`. To remove a field,
remove the dictionary key and associated value from the typedef dictionary.

All remaining field numbers are required to have a `type` attribute, and any
`message` fields need `message_typedef` or `message_type_name`. 

The `name` attribute is not required and can be removed if empty, but is
recommended otherwise. 

The `alt_typedef` field can be removed if the definitions have not been
customized.

Any other attributes on the typedef can be removed, including:
- `example_value_ignored`
- `field_order`
