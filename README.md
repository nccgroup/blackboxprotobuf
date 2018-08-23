# BlackBox Protobuf Burp Extension

## Description
This is an extension for the intercepting proxy Burp Suite
(<https://portswigger.net/burp/>) that allows encoding and decoding arbitrary
protocol buffer (<https://developers.google.com/protocol-buffers/>) messages
which may be contained in an intercepted request. It is designed to work
without a protobuf definition file (.proto) which may not be available or may
be unusable with existing Burp extensions.

The BlackBox Protobuf library can also be used independently as a Python module
to convert protobuf messages to either JSON or a Python dictionary. It can be
found under the `blackboxprotobuf/lib` directory.

Library documentation, background information on Protobuf decoding and a
breakdown of the type system and possible type corner cases may be found at
<https://github.com/nccgroup/blackboxprotobuf/blob/master/README-LIBRARY.md>


# Usage
## Installation

1. If Burp Suite is not already installed, download it from <https://portswigger.net/burp/>.
2. Download/Install Jython 2.7+ and configure Burp with the location. See
   <https://portswigger.net/burp/help/extender.html#options_pythonenv>.
3. Clone this repository and then run `git submodule update --init` to install dependencies.
4. Within Burp, navigate to Extender -> Extensions and select "Add".
5. Set "Extension Type" to Python and select the `extender.py` file in the git repository.
6. Click Next and the extension should load.


## Editing Messages
A new tab will be added to every message window with a content type of
"x-protobuf" or "application/protobuf" (this can be modified, see below). The
protobuf message will be parsed to a JSON dictionary with numbered fields as
the key. The values can be modified as long as the new value is of the same
type. At the moment, fields may be removed, but not added. Fields will be
reencoded with the same type as it was decoded.

The "Validate" button verifies that the JSON can be reencoded before switching
away from the protobuf tab. If you switch away from the tab with an invalid
payload, it will raise an error and reset.

The "Save Type"/"Load Type" buttons allow message types to be saved/loaded
across editing tabs.

The "Edit Type" brings up a window for editing the current message's type
definition in JSON form. The current message will be decoded with the new type
upon saving.

The "Reset" button will revert the protobuf message to the original decoded
value.

## Editing Types
The type definition for a message can be modified to make protobuf messages
easier to work with. This allows you to change how a message is decoded (eg.
decode a field as an `sint` instead of the default `int`) and allows you to
assigned names to fields to improve readability.

Field numbers should not be modified and types should only be changed to types
within the same wire type. A full list of wiretypes and sub-types can be found
below.

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
    - `packed_*` - Repeated fields of the same type packed into a buffer. Can
      be combined with any Varint, or fixed wiretype (eg. `packed_fixed32`)
* Group (Start/End)
    - `group` - Deprecated way to group fields. Replaced with nested Protobuf
      Messages


### Type Definition Persistence
By default, the extension will remember changes to a type definition and
attempt to reuse the type definition for the same requests. This is currently
based on the HTTP path and whether it is a request or response. This behavior
can be modified with the `hash_message` function in
`blackboxprotobuf/burp/user_funcs.py`. For example, basing the message type on a
URL parameter or header value. These remembered types will be forgotten if they
fail to decode a message.

Types can be explicitly saved/named through the "Save Type" button or in the
type definition editor tab. Named type definitions can then be applied to any
message. These types are not persisted and will disappear when Burp is closed.

Finally, types can be exported to JSON files from the type definition editor
tab for longer term backup or storage.

## Protobuf Detection/Extraction
The plugin currently attempts to detect a protobuf message using the
"Content-Type" header and retrieve the binary from the message body. However,
the use of the protobuf format is not standardized and the location/encoding of
the protobuf data may change from application to application.

Users can write custom functions for detecting protobufs, retrieving protobuf
data from an HTTP message, and setting the re-encoded protobuf data in the HTTP
message. These functions, along with several examples, can be found in
`blackboxprotobuf/burp/user_funcs.py`. The extension must be reloaded after
modifying the file.


# Future Work
- Persistent message type definitions
    - Save across sessions
    - Import/export to proto files
