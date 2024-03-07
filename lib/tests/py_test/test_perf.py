import pytest
import blackboxprotobuf


@pytest.mark.skip()
def test_wide():
    typedef = {"1": {"type": "int"}}

    message = {"1": [1] * 10000000}

    encoded = blackboxprotobuf.lib.encode_message(message, typedef)
    decoded, _ = blackboxprotobuf.lib.decode_message(encoded, typedef)


@pytest.mark.skip()
def test_deep():
    config = blackboxprotobuf.lib.config.Config()

    typedef = {
        "1": {"type": "message", "message_type_name": "test"},
        "2": {"type": "int"},
    }
    config.known_types["test"] = typedef
    target_depth = 100
    message = {}
    last_layer = message

    while target_depth:
        new_layer = {"2": 1}
        last_layer["1"] = new_layer
        last_layer = new_layer

        target_depth -= 1

    encoded = blackboxprotobuf.lib.encode_message(message, typedef, config)
    decoded, _ = blackboxprotobuf.lib.decode_message(encoded, typedef, config)


@pytest.mark.skip()
def test_large_multilayer():
    config = blackboxprotobuf.lib.config.Config()

    typedef = {
        "1": {"type": "message", "message_type_name": "test"},
        "2": {"type": "int"},
    }
    config.known_types["test"] = typedef
    target_depth = 10
    message = {}
    last_layer = message

    while target_depth:
        new_layer = {"2": [1] * 10000}
        last_layer["1"] = [new_layer] * 2
        last_layer = new_layer

        target_depth -= 1

    encoded = blackboxprotobuf.lib.encode_message(message, typedef, config)
    decoded, _ = blackboxprotobuf.lib.decode_message(encoded, typedef, config)
