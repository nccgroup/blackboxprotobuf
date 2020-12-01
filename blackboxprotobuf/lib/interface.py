"""Methods for easy encoding and decoding of messages"""

import json
import six
import blackboxprotobuf.lib.types.length_delim
import blackboxprotobuf.lib.types.type_maps
from blackboxprotobuf.lib.exceptions import TypedefException

known_messages = {}

def decode_message(buf, message_type=None):
    """Decode a message to a Python dictionary.
    Returns tuple of (values, types)
    """

    buf = six.ensure_binary(buf)
    if message_type is None or isinstance(message_type, str):
        if message_type not in known_messages:
            message_type = {}
        else:
            message_type = known_messages[message_type]

    value, typedef, _ = blackboxprotobuf.lib.types.length_delim.decode_message(buf, message_type)
    return value, typedef

#TODO add explicit validation of values to message type
def encode_message(value, message_type):
    """Encodes a python dictionary to a message.
    Returns a bytearray
    """
    return blackboxprotobuf.lib.types.length_delim.encode_message(value, message_type)

def protobuf_to_json(*args, **kwargs):
    """Encode to python dictionary and dump to JSON.
    Takes same arguments as decode_message
    """
    value, message_type = decode_message(*args, **kwargs)
    return json.dumps(value, indent=2, encoding='latin1'), message_type

def protobuf_from_json(value, *args, **kwargs):
    """Decode JSON string to JSON and then to protobuf.
    Takes same arguments as encode_message
    """
    return encode_message(json.loads(value), *args, **kwargs)

def validate_typedef(typedef, old_typedef=None, path=None):
    """Validate the typedef format. Optionally validate wiretype of a field
       number has not been changed
    """
    if path is None:
        path = []
    int_keys = set()
    for field_number, field_typedef in typedef.items():
        alt_field_number = None
        if '-' in str(field_number):
            field_number, alt_field_number = field_number.split('-')

        # Validate field_number is a number
        if not str(field_number).isdigit():
            raise TypedefException("Field number must be a digit: %s" % field_number)
        field_number = str(field_number)

        field_path = path[:]
        field_path.append(field_number)

        # Check for duplicate field numbers
        if field_number in int_keys:
            raise TypedefException("Duplicate field number: %s" % field_number, field_path)
        int_keys.add(field_number)

        # Must have a type field
        if "type" not in field_typedef:
            raise TypedefException("Field number must have a type value: %s" % field_number, field_path)
        if alt_field_number is not None:
            if field_typedef['type'] != 'message':
                raise TypedefException(
                    "Alt field number (%s) specified for non-message field: %s"
                    % (alt_field_number, field_number), field_path)

        field_names = set()
        valid_type_fields = ["type", "name", "message_typedef",
                             "message_type_name", "group_typedef",
                             "alt_typedefs"]
        for key, value in field_typedef.items():
            # Check field keys against valid values
            if key not in valid_type_fields:
                raise TypedefException("Invalid field key \"%s\" for field number %s" % (key, field_number), field_path)
            if (key in ["message_typedef", "message_type_name"]
                    and not field_typedef["type"] == "message"):
                raise TypedefException("Invalid field key \"%s\" for field number %s" % (key, field_number), field_path)
            if key == "group_typedef" and not field_typedef["type"] == "group":
                raise TypedefException("Invalid field key \"%s\" for field number %s" % (key, field_number), field_path)

            # Validate type value
            if key == "type":
                if value not in blackboxprotobuf.lib.types.type_maps.wiretypes:
                    raise TypedefException("Invalid type \"%s\" for field number %s" % (value, field_number), field_path)
            # Check for duplicate names
            if key == "name":
                if value in field_names:
                    raise TypedefException(("Duplicate field name \"%s\" for field "
                                            "number %s") % (value, field_number), field_path)
                field_names.add(value)

            # Check if message type name is known
            if key == "message_type_name":
                if value not in known_messages:
                    raise TypedefException(("Message type \"%s\" for field number"
                                            " %s is not known") % (value, field_number), field_path)

            # Recursively validate inner typedefs
            if key in ["message_typedef", "group_typedef"]:
                if old_typedef is None:
                    validate_typedef(value, path=field_path)
                else:
                    #print(old_typedef.keys())
                    validate_typedef(value, old_typedef[field_number][key], path=field_path)
            if key == "alt_typedefs":
                for alt_field_number, alt_typedef in value.items():
                    #TODO validate alt_typedefs against old typedefs?
                    validate_typedef(alt_typedef, path=field_path)


    if old_typedef is not None:
        wiretype_map = {}
        for field_number, value in old_typedef.items():
            wiretype_map[int(field_number)] = blackboxprotobuf.lib.types.type_maps.wiretypes[value['type']]
        for field_number, value in typedef.items():
            field_path = path[:]
            field_path.append(str(field_number))
            if int(field_number) in wiretype_map:
                old_wiretype = wiretype_map[int(field_number)]
                if old_wiretype != blackboxprotobuf.lib.types.type_maps.wiretypes[value["type"]]:
                    raise TypedefException(("Wiretype for field number %s does"
                                            " not match old type definition") % field_number, field_path)
