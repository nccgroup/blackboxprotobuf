# Blackbox Protobuf Mitmproxy Addon

## Description

This directory contains an addon for mitmproxy (<https://mitmproxy.org/>) which
uses the Blackbox Protobuf library to decode and edit proxied protobuf messages.


## Installation

1. Clone the Blackboxprotobuf repository:
   
   ```
   git clone https://github.com/nccgroup/blackboxprotobuf.git
   ```
   
2. Update the submodules which contain dependencies:
   
   ```
   cd blackboxprotobuf/
   git submodule update --init
   ```

3. Run mitmproxy with the addon:
   
   ```
   mitmproxy -s mitmproxy/bbpb.py
   ```

### Alternative Installation

1. Install the `bbpb` python package in the same context as
   `mitmproxy`.
   
   ```
   pip isntall bbpb
   ```
   
   If `mitmproxy` is installed within a virtual environment, then the `bbpb`
   package needs to be install within that virtual environment.

2. Download the `bbpb.py` from <https://github.com/nccgroup/blackboxprotobuf/blob/master/mitmproxy/bbpb.py>

3. Run mitmproxy with the addon script:
   
   ```
   mitmproxy -s mitmproxy/bbpb.py
   ```


## Usage

### Passive Decoding

The Blackbox Protobuf addon provides a content view to automatically decode
protobuf and gRPC messages and websockets displayed in mitmproxy. The content
view will use saved types if available (eg. to name fields or change types),
but will default to an anonymous decoding.

The content view should also work in mitmweb, but commands for editing messages
and types will not be available.

### Persisting Type Data

The addon will remember edited types and the associated endpoints, but this
data will be lost if mitmproxy is shut down or the addon is reloaded.

The `bbpb_project_file` option in the mitmproxy configuration will cause the
addon to load types from the provided file and then automatically write back
any changes. If you have an extensive number of options, it's recommended to
back up the project file regularly to ensure data isn't overwritten.

The types can also be manually saved or loaded using the `:bbpb.project.save`
and `:bbpb.project.load` commands.

### Commands

Message and type editing functionality is provided via mitmproxy commands. 

The commands operate on the currently selected flow.  Most commands take a
`flow_part` argument, which indicates where the desired protobuf payload is in the
message. Currently supported flow parts are:

* `request-body`
* `response-body`
* `websocket-request` (not supported for `bbpb.edit`)
* `websocket-response` (not supported for `bbpb.edit`)

Command arguments support tab completion.

#### `:bbpb.edit`

The `:bbpb.edit` command will open a text editor with the protobuf decoded to
JSON, similar to editing other HTTP messages in mitmproxy. The edited JSON
payload will be re-encoded to protobuf to be replayed or resumed.

The edit command can be used to modify request or response bodies. At the
moment, mitmproxy does not appear to allow websocket messages to be edited
interactively. It may be possible to edit websocket messages programmatically by
registering the `websocket-message` event handler in an addon.

#### `:bbpb.edit_type`

The `:bbpb.edit_type` command will open a text editor to edit the type
definition used for the protobuf data. This can be used to add field names or
change a field's type.

If the endpoint is assigned a named type, then the named type is edited and the
changes will be applied to all other endpoints using the same named type. If
the type is not named, then the edited type definition is remembered just for
that endpoint.

#### `:bbpb.new_type`

The `:bbpb.new_type` command will attach a name to the current type and store
it in `known_types`. A named type can then be applied to multiple endpoints and
you can switch between named types at-will without losing the type definition.

#### `:bbpb.apply_type` 

The `:bbpb.apply_type` command will apply a previously saved named type to the
endpoint/protobuf payload. Applying the type name of `(clear)` will remove the
saved type for this endpoint, causing the decoding to be reset.

Warning: If the current endpoint has an edited type which is not named, the
edited type definition will be lost when a named type is applied.

If the current endpoint is associated with another named type, the named type
will be safe and can be reapplied later.

#### `:bbpb.del_type`

The `:bbpb.del_type` command can be used to remove a named type. Any endpoints associated with that named type will also be reset.

#### `:bbpb.project.save` and `:bbpb.project.load`

These commands will manually save/load a one-off Blackbox Protobuf project JSON
file. This file contains all edited type definitions and all endpoint to type
definition mappings.

## gRPC Note

This addon has been tested with a python gRPC and client and is able to
intercept messages by default. However, in the past mitmproxy has had some
issues with intercepting gRPC connections from certain applications, and would
register connections as PRI methods, or fail to intercept the request.

The issue appears to be that some gRPC implementations use a unique `grpc-exp`
ALPN value which proxies do not know how to handle. One work around that has
worked in the past is cloning mitmproxy and changing if conditions which check
for `h2` to also work for `grpc-exp`.

Another potential solution is the addon modifications described at
<https://github.com/mitmproxy/mitmproxy/issues/3052#issuecomment-1676020354>,
but this has not been tested with the Blackbox Protobuf addon yet.
