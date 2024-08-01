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

import os
import sys
import six
import math
import glob
import shutil
import base64
import struct
import pytest
import logging
import tempfile
import subprocess
import hypothesis
from hypothesis import given, assume, note, settings, HealthCheck
import hypothesis.strategies as st
import google.protobuf.json_format
import strategies
import blackboxprotobuf.lib
import blackboxprotobuf.lib.protofile as protofile
from blackboxprotobuf.lib.types import length_delim
from blackboxprotobuf.lib.config import Config
from blackboxprotobuf.lib.typedef import TypeDef


to_suppress = []
if six.PY3:
    to_suppress = (HealthCheck.function_scoped_fixture,)


@given(
    typedef=strategies.message_typedef_gen(named_fields=False),
    name=st.from_regex(protofile.NAME_REGEX),
)
@settings(suppress_health_check=to_suppress)
def test_proto_export(tmp_path, typedef, name):
    """Check to make sure our generated protofiles don't throw an error"""
    with tempfile.NamedTemporaryFile(
        mode="w", dir=str(tmp_path), suffix=".proto", delete=True
    ) as outfile:
        typedef_map = {name: typedef}

        note(typedef_map)

        # Trying exporting as string first
        protofile.export_proto(typedef_map)

        protofile.export_proto(typedef_map, output_file=outfile)

        py_out = str(tmp_path / "py_out")
        if os.path.exists(py_out):
            shutil.rmtree(py_out)
        os.mkdir(py_out)
        outfile.flush()
        subprocess.check_call(
            "/usr/bin/protoc --python_out ./py_out %s" % os.path.basename(outfile.name),
            shell=True,
            cwd=str(tmp_path),
        )


@given(
    x=strategies.gen_message(named_fields=False),
    name=st.from_regex(protofile.NAME_REGEX),
)
@settings(suppress_health_check=to_suppress)
def test_proto_export_inverse(tmp_path, x, name):
    """Generate a proto file and try to re-import it. This does not cover all
    possible proto files we want to try importing"""
    config = Config()
    typedef, message = x
    name = six.ensure_text(name)
    with tempfile.NamedTemporaryFile(
        mode="r+", dir=str(tmp_path), suffix=".proto", delete=True
    ) as outfile:
        typedef_map = {name: typedef}

        protofile.export_proto(typedef_map, output_file=outfile)
        outfile.flush()

        outfile.seek(0)
        new_typedef_map = protofile.import_proto(config, input_file=outfile)

        config.known_types.update(new_typedef_map)
        # validate
        for name, typedef in new_typedef_map.items():
            blackboxprotobuf.validate_typedef(typedef, config=config)

        def _check_field_types(typedef1, typedef2):
            for field_num in typedef1.keys():
                # make sure we don't drop keys
                assert field_num in typedef2
                assert typedef1[field_num]["type"] == typedef2[field_num]["type"]
                if typedef1[field_num]["type"] == "message":
                    message_typedef1 = None
                    message_typedef2 = None
                    if "message_typedef" in typedef1[field_num]:
                        message_typedef1 = typedef1[field_num]["message_typedef"]
                    elif "message_type_name" in typedef1[field_num]:
                        assert typedef1[field_num]["message_type_name"] in typedef_map
                        message_typedef1 = typedef_map[
                            typedef1[field_num]["message_type_name"]
                        ]
                    if "message_typedef" in typedef2[field_num]:
                        message_typedef2 = typedef2[field_num]["message_typedef"]
                    elif "message_type_name" in typedef2[field_num]:
                        assert (
                            typedef2[field_num]["message_type_name"] in new_typedef_map
                        )
                        message_typedef2 = new_typedef_map[
                            typedef2[field_num]["message_type_name"]
                        ]

                    _check_field_types(message_typedef1, message_typedef2)

        note(typedef_map)
        note(new_typedef_map)
        for name, typedef in typedef_map.items():
            _check_field_types(typedef, new_typedef_map[name])

        note(new_typedef_map[name])
        # try to actually encode a message with the typedef
        encode_forward = length_delim.encode_message(
            message, config, TypeDef.from_dict(typedef_map[name])
        )

        config.known_types = new_typedef_map
        encode_backward = length_delim.encode_message(
            message, config, TypeDef.from_dict(new_typedef_map[name])
        )

        decode_forward, _, _, _ = length_delim.decode_message(
            encode_forward, config, TypeDef.from_dict(new_typedef_map[name])
        )
        decode_backward, _, _, _ = length_delim.decode_message(
            encode_backward, config, TypeDef.from_dict(typedef_map[name])
        )


@pytest.mark.filterwarnings("ignore:Call to deprecated create function.*")
def test_proto_import_examples():
    config = Config()
    # try importing all the examples pulled from protobuf repo
    protofiles = glob.glob("tests/deps/protobuf/src/google/protobuf/*.proto")
    # These files have some mechanism we don't support, mostly imports
    unsupported_files = {
        "tests/deps/protobuf/src/google/protobuf/api.proto",  # import
        "tests/deps/protobuf/src/google/protobuf/unittest_optimize_for.proto",  # import
        "tests/deps/protobuf/src/google/protobuf/type.proto",  # import
        "tests/deps/protobuf/src/google/protobuf/unittest_lite_imports_nonlite.proto",  # import
        "tests/deps/protobuf/src/google/protobuf/unittest_lite.proto",  # group type not supported
        "tests/deps/protobuf/src/google/protobuf/unittest_embed_optimize_for.proto",  # import
        "tests/deps/protobuf/src/google/protobuf/unittest.proto",  # group
        "tests/deps/protobuf/src/google/protobuf/unittest_lazy_dependencies.proto",  # import
    }
    assert len(protofiles) != 0
    for target_file in protofiles:
        if target_file in unsupported_files:
            print("Skipping file: %s" % target_file)
            continue

        print("Testing file: %s" % target_file)
        typedef_map_out = protofile.import_proto(config, input_filename=target_file)
        config.known_types = typedef_map_out
        for name, typedef in typedef_map_out.items():
            logging.debug("known messages: %s" % config.known_types)
            blackboxprotobuf.lib.validate_typedef(typedef, config=config)


@given(
    x=strategies.gen_message(named_fields=False),
    name=st.from_regex(protofile.NAME_REGEX),
)
@settings(suppress_health_check=to_suppress)
@pytest.mark.filterwarnings("ignore:Call to deprecated create function.*")
def test_proto_decode(tmp_path, x, name):
    config = Config()
    typedef, message = x
    """ Export to protobuf and try to decoe a message we encodedd with it """
    with tempfile.NamedTemporaryFile(
        mode="w", dir=str(tmp_path), suffix=".proto", delete=True
    ) as outfile:
        typedef_map = {name: typedef}

        encoded_message = length_delim.encode_message(
            message, config, TypeDef.from_dict(typedef)
        )

        note(typedef_map)
        basename = os.path.basename(outfile.name)

        # Export the protobuf file and compile it
        protofile.export_proto(typedef_map, output_file=outfile, package=basename[:-6])

        py_out = str(tmp_path / "py_out")
        if os.path.exists(py_out):
            shutil.rmtree(py_out)
        os.mkdir(py_out)
        outfile.flush()
        subprocess.check_call(
            "/usr/bin/protoc --python_out ./py_out %s" % basename,
            shell=True,
            cwd=str(tmp_path),
        )

        # Try to import the file
        sys.path.insert(0, str(tmp_path) + "/py_out/")
        # Trim off .proto
        try:
            proto_module = __import__(basename[:-6] + "_pb2")
            del sys.path[0]
        except SyntaxError:
            logging.debug("Caught syntax error in protoc import")
            return

        message_class = getattr(proto_module, name)

        note(encoded_message)
        my_message = message_class()
        my_message.ParseFromString(encoded_message)

        decoded_message = google.protobuf.json_format.MessageToDict(
            my_message, including_default_value_fields=True
        )

        note(message)
        note(decoded_message)
        note(
            google.protobuf.json_format.MessageToJson(
                my_message, including_default_value_fields=True
            )
        )

        def _check_field_match(orig_value, new_value):
            note(type(new_value))
            note(type(orig_value))
            if isinstance(orig_value, six.integer_types) and isinstance(new_value, str):
                assert str(orig_value) == new_value
            elif isinstance(orig_value, bytes):
                assert orig_value == base64.b64decode(new_value)
            elif isinstance(new_value, dict):
                _check_message_match(orig_value, new_value)
            elif isinstance(orig_value, float):
                # normalize floats
                if isinstance(new_value, str):
                    if "Infinity" in new_value:
                        assert math.isinf(orig_value)
                    else:
                        assert new_value == "NaN"
                        assert math.isnan(new_value)

                else:
                    # pack and unpack floats to try and normalize them
                    try:
                        orig_value_packed = struct.pack("<f", orig_value)
                        (orig_value,) = struct.unpack("<f", orig_value_packed)
                        new_value_packed = struct.pack("<f", orig_value)
                        (new_value,) = struct.unpack("<f", orig_value_packed)
                        assert orig_value == new_value
                    except OverflowError:
                        orig_value_packed = struct.pack("<d", orig_value)
                        (orig_value,) = struct.unpack("<d", orig_value_packed)
                        new_value_packed = struct.pack("<d", new_value)
                        (new_value,) = struct.unpack("<d", new_value_packed)
                        assert orig_value == new_value

            else:
                assert orig_value == new_value

        def _check_message_match(message_orig, message_new):
            for field_key, field_value in message_new.items():
                if field_key.startswith("field"):
                    field_key = field_key[5:]
                orig_value = message_orig[field_key]
                if isinstance(field_value, list):
                    if not isinstance(orig_value, list):
                        orig_value = [orig_value]
                    assert len(orig_value) == len(field_value)
                    for orig_value, new_value in zip(orig_value, field_value):
                        _check_field_match(orig_value, new_value)
                else:
                    _check_field_match(orig_value, field_value)

        # Check all the fields match each other
        _check_message_match(message, decoded_message)
