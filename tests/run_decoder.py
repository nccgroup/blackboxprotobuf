#!/usr/bin/env python

import sys
sys.path.insert(0, '../')

import blackboxprotobuf as bbp

typedef = {}

# Take a protobuf binary from stdin and decode it to JSON
protobuf = sys.stdin.read()
json,typedef = bbp.protobuf_to_json(protobuf, typedef)
print(json)
print(typedef)
