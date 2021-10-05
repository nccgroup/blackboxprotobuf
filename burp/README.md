# BlackBox Protobuf Burp Extension

## Description
This is an extension for the intercepting proxy Burp Suite
(<https://portswigger.net/burp/>) that allows encoding and decoding arbitrary
protocol buffer (<https://developers.google.com/protocol-buffers/>) messages
which may be contained in an intercepted request. It is designed to work
without a protobuf definition file (.proto) which may not be available or may
be unusable with existing Burp extensions.

Background information on Protobuf decoding and a breakdown of the type system
and possible type corner cases may be found in the library documentation under:
<https://github.com/nccgroup/blackboxprotobuf/blob/master/lib/README.md>


# Usage
## Installation

1. If Burp Suite is not already installed, download it from <https://portswigger.net/burp/>.
2. Download/Install Jython 2.7+ and configure Burp with the location. See
   <https://portswigger.net/burp/help/extender.html#options_pythonenv>.
3. Clone this repository and then run `git submodule update --init` to install dependencies.
4. Within Burp, navigate to Extender -> Extensions and select "Add".
5. Set "Extension Type" to Python and select the `extender.py` file in the git repository.
6. Click Next and the extension should load.
7. **Note:** [gRPC](https://grpc.io/about/) is supported, but you'll have to enable Burp's HTTP/2 support (under Project Options->HTTP). Also, currently only uncompressed gRPC payloads are supported. If the first byte of the payload is not `0x00`, it's compressed and you'll have to modify the en/decoding code to account for that.


## Editing Messages
A new tab will be added to every message window with a content type of
"x-protobuf" or "application/protobuf" (this is configurable via
`user_funcs.py`). The protobuf message will be parsed to a JSON dictionary with
numbered fields as the key. The values can be modified as long as the new value
is of the same type.

The upper list shows a list of named type definitions that can decode this
message. Selecting one will re-decode the message with the new type.
Blackboxprotobuf will try to remember the last message chosen for that
endpoint. The `new` button will save the current type definition under a new
name.

The "Validate" button verifies that a modified JSON message can be re-encoded.
It's best to use this to validate a message before switching to a different
view or sending the message. If you switch away from the tab with an invalid
payload, it will raise an error and reset to the original value.

The "Edit Type" brings up a window for editing the current message's type
definition in a JSON format. Allowing you to change types or name fields. The
current message will be decoded with the new type upon saving. If you edit the
default type definition for a message, you should use the `New` button to save
it, or it will be forgotten on the next message.

The "Reset Message" button will revert the protobuf message to the original decoded
value. The `Clear Type` button will reset to a new anonymous type definition.

## Editing Types
The type definition for a message can be modified to make protobuf messages
easier to work with. This allows you to change how a message is decoded (eg.
decode a field as an `sint` instead of the default `int`) and allows you to
assigned names to fields to improve readability.

Field numbers should not be modified and types should only be changed to types
within the same wire type. A full list of wiretypes and sub-types can be found
below.

The `example_value_ignored` field in the type definition should contain a value
from the message to make it easier to locate the right field to modify, but the
value itself is ignored when the type definition is parsed.

### Type Reference
* Varint - Variable length integers (up to 8 bytes)
    - `uint` - unsigned, represents positive numbers efficiently, can't
      represent negative numbers
    - `int` - (default) signed, but represents negative numbers inefficiently
    - `sint` - Zig-zag encoding to map unsigned space to signed
* Fixed32 - Always 32 bits
    - `fixed32` - (default) unsigned integer
    - `sfixed32` - signed integer
    - `float` - floating point number
* Fixed64 - Always 64 bits
    - `fixed64` - (default) unsigned integer
    - `sfixed64` - signed integer
    - `double` - floating point number
* Length Delimited - Prefixed by length representing varint
    - `bytes` - (default) Plain data, used for strings as well
    - `message` - (detected) Protobuf message. Can contain a nested type
      definition ('`message_typedef`') or labeled type name
      ('`message_type_name`')
    - `string` - Similar to bytes, but will return a string python type
    - `bytes_hex` - Output binary data as a string of hex characters rather
      than an escaped string
    - `packed_*` - Repeated fields of the same type packed into a buffer. Can
      be combined with any Varint, or fixed wiretype (eg. `packed_fixed32`)
* Group (Start/End)
    - `group` - Deprecated way to group fields. Replaced with nested Protobuf
      Messages. Not supported


## Protobuf Type Editor Tab

Any message definitions saved with a name will be shown in the global "Protobuf
Type Editor Tab". This tab allows type definitions to be created, renamed,
edited and removed without an active request/response.

The "Save All Types"/"Load All Types" buttons can be used to export or import
the type definitions as JSON files. This can ensure the types are safely backed
up or to share them between instances. Named types should persist in the
extension settings between Burp reboots, but if a lot of effort has been put
into customizing definitions, it may be a good idea to back them up regularly.

Finally, the extension will try to import/export `.proto` files. The `.proto`
export will try save all known type definitions into the protobuf type
definition format. You should then be able to import the `.proto` files into
other tools that expect the original type definitions. The import functionality
will attempt to read a `.proto` file and create a Blackbox protobuf type
definition from it. This does not support "import" statements and any files
referenced by the import statement should be imported first. Both import and
export functionality is pretty hacky and may not work for all message types.

## User Functions

Some of the behavior of the extension can be changed through the
`burp/blackboxprotobuf/burp/user_funcs.py` file. Each function is called by the
extension to provide alternative ways to handle a message:

* `detect_protobuf` - Customizes how the extension determines if a
  request/response is a protobuf message. By default, the extension checks for
  a few content-type headers to know when to parse a request/response as
  protobuf. This function can be used to check for other headers, parameters or
  just return True for all messages. Should return `True` if it is protobuf,
  `False` if it isn't, or `None` to fall back to the content-type check.
* `get_protobuf_data` - Customizes the process of retrieving the data from the
  message. By default the extension will retrieve the binary data from the
  message body. This function can be used to get data from other location such
  as a header or parameter. This can also be used to parse non-default
  encodings. Should return the protobuf data.
* `set_protobuf_data` - Customizes how protobuf data is stored back in the
  request/response once it is re-encoded. Should mirror `get_protobuf_data` and
  is only necessary if `get_protobuf_data` is customized.
* `hash_message` - Customizes how the extension identifies which message type
  to use for a request/response. By default, the extension uses a combination
  of the path and whether it is a request or a response. If the application has
  a better indicator, such as a `MessageType` header or parameter, then this
  function can return that as a key. The returned value is just used as a key
  to a dict/hashmap so can be any arbitrary value, but should be a string value
  so that it can be serialized as JSON for persistence.
