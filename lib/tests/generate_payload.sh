#!/bin/bash

protoc --encode=TestMessage payloads/Test.proto < payloads/test_message.in
