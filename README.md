# Blackbox Protobuf

**Blackbox Protobuf now has an official package on PyPi under the name `bbpb`.
The `blackboxprotobuf` package is an older fork**

## Description

Blackbox Protobuf is a set of tools for working with encoded Protocol Buffers
(protobuf) without the matching protobuf definition.

Protobuf is a binary serialization format from Google which can be used as a
more efficient alternative to formats like JSON or XML. Developers can define
the message format in a `.proto` file and use the protobuf compiler to
geneerate message handlers in their language of choice. The protobuf encoding
is binary, and unlike json/xml not human readable or easy to modify by hand.
The format also takes advantage of both sides having the message definition and
strips out much of the type information. This is good for efficiency, but
increases the difficulty analyzing or modifying the network traffic.

Blackbox protobuf is designed to allow working with protocol buffers without
the message definition. It was originally implemented as a Burp extension for
decoding and modifying messages during mobile pentests, but has also been used
for reverse engineering and forensics tooling.

## Tools

This repository contains two applications for working with protocol buffers:

- A jython burp extension in [burp/](https://github.com/nccgroup/blackboxprotobuf/tree/master/burp)
- A python library that can be used in other applications in [lib/](https://github.com/nccgroup/blackboxprotobuf/tree/master/lib)

## Future Tools

Some tooling that may be built on top of blackboxprotobuf in the future:

- mitmproxy addon
- command line interface
- protobuf type discovery tool
