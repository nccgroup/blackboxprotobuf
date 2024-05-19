# Blackbox Protobuf Command Line Interface (CLI)

## Description

The Blackbox Protobuf library has an embedded CLI interface which can be invoked
with `python -m blackboxprotobuf` for use in shell scripts, to plug in to other
tools, or easily decode arbitrary protobuf messages.

## Installation

The Blackbox Protobuf library can be installed with:

~~~
pip install bbpb
~~~

The command line interface can then be run with:

~~~
bbpb
~~~

or

~~~
python3 -m blackboxprotobuf
~~~

## Usage

### Examples

Simple Decoder:
~~~
cat test_data | bbpb -r
~~~

Save type for editing:
~~~
cat test_data | bbpb -ot ./saved_type.json
~~~

Decode with type:
~~~
cat test_data | bbpb -it ./saved_type.json
~~~

Decode edit and re-encode:
~~~
cat test_data | bbpb  > message.json
vim message.json
cat message.json | bbpb -e > test_data_out
~~~


### Decoding
The CLI decoding mode (default) will take a protobuf payload and an option type
defintion, and output a JSON object which contains the decoded message and a
type definition.

By default, the binary protobuf message is expected to be provided on stdin.
The input type cannot be provided through stdin and must be saved to file and
provided via the `-it`/`--input-type` argument.

Alternatively, the `-j`/`--json-protobuf` argument allows the protobuf message
and typedef to be pass in as a single JSON object. The input JSON object should
have a `protobuf_data` field which contains the base64 encoded protobuf data, and can
optionally have a `typedef` field with the input type definition. This option
is useful for tools calling the CLI which may not want to save files to disk
for input types.


The default output from the decoder will be a JSON object which contains the
decoded message in the `message` field and the typedef necessary to decode the
message in the `typedef` field.

The output format matches the expected input for the CLI encoder, allowing the
message to be easily edited and re-encoded.

Alternatively, the `-r`/`--raw-decode` argument will provide a simpler output
with just the JSON message and no type definition. This is useful if you don't
want to edit the message, just view it, or are saving the type definition to a
file with `-ot`/`--output-type` argument.


The `-it`/`--input-type` and `-ot`/`--output-type` arguments will have the CLI
read and/or write type definitions to the provided file.

### Encoding

The `-e`/`--encode` argument put the CLI in encoding mode, which takes a JSON
message type definition, and prints an encoded protobuf message to stdin.


By default, the CLI expects a JSON object through stdin which contains a
`message` field with the JSON representation of the message and a `typedef`
field with the type definition. This format should match the output of the CLI
decoder.

The type definition can also be provided through a file specified with the
`-it`/`--input-type` argument. If the type definition is provided through this
argument and there is no `message` field on the input JSON, the encoder will
use the entire input JSON as the message (eg. the output of the decoder with
`-r`/`--raw-decode`).

By default, the CLI will output the encoded protobuf bytes to stdout.

Alternatively, the `-j`/`--json-protobuf` command line flag will output a JSON
payload with `protobuf_data` and `typedef` attributes. The protobuf data field
will contain base64 encoded protobuf data. This format matches the expected
input of the decoder with the `-j`/`--json-protobuf` attribute.

### Editing

The messages and typedefs can be easily edited following the same rules as
other Blackbox Protobuf interfaces.

The JSON message from the decoder can be edited to easily change field values,
before passing the payload back to the encoder. It is possible to add fields if
the field type is defined in the type definition and the added value matches
the type definition.

If you wish to edit the type definition to change field names or types, save
the type definition from the output payload or the `-ot`/`--output-typedef`
argument. Edit the type definition and then perform the decoding step again
with `-it`/`--input-typedef`.

It is not recommended that you edit the typedef from the decoder directly
before passing the message/typedef to the encoder, as this  may cause the
payload to be encoded incorrectly.

### Payload Encoding

The Blackbox Protobuf library tries to automatically handle several "wrapper"
encodings. The library currently supports gzip compression and gRPC headers.
During decoding, the library will attempt to detect these wrappers and unpack
the protobuf payload. If a payload encoding is identified, it is stored in
`payload_encoding` field of the output JSON. The encoder will then re-apply the
wrapper when the payload is encoded.

If the payload encoding is not provided, the encoder will default to "none"
which indicates plain protobuf. The payload encoding is set to "gzip" or "grpc"
for other encoding options.

The payload encoding process can be overridden during decoding or encoding with
the `-pe`/`--payload-encoding` argument.
