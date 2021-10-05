"""Methods for easy encoding and decoding of messages"""

import re
import six
import json
import collections
import blackboxprotobuf.lib.protofile
import blackboxprotobuf.lib.types.length_delim
import blackboxprotobuf.lib.types.type_maps
from blackboxprotobuf.lib.exceptions import TypedefException

blackboxprotobuf.known_messages = {}

def decode_message(buf, message_type=None):
    """Decode a message to a Python dictionary.
    Returns tuple of (values, types)
    """

    if isinstance(buf, bytearray):
        buf = bytes(buf)
    buf = six.ensure_binary(buf)
    if message_type is None or isinstance(message_type, str):
        if message_type not in blackboxprotobuf.known_messages:
            message_type = {}
        else:
            message_type = blackboxprotobuf.known_messages[message_type]

    value, typedef, _ = blackboxprotobuf.lib.types.length_delim.decode_message(buf, message_type)
    return value, typedef

#TODO add explicit validation of values to message type
def encode_message(value, message_type):
    """Encodes a python dictionary to a message.
    Returns a bytearray
    """
    return bytes(blackboxprotobuf.lib.types.length_delim.encode_message(value, message_type))

def protobuf_to_json(*args, **kwargs):
    """Encode to python dictionary and dump to JSON.
    Takes same arguments as decode_message
    """
    value, message_type = decode_message(*args, **kwargs)
    value = json_safe_transform(value, message_type, False)
    value = _sort_output(value, message_type)
    _annotate_typedef(message_type, value)
    message_type = _sort_typedef(message_type)
    return json.dumps(value, indent=2), message_type

def protobuf_from_json(json_str, message_type, *args, **kwargs):
    """Decode JSON string to JSON and then to protobuf.
    Takes same arguments as encode_message
    """
    value = json.loads(json_str)
    _strip_typedef_annotations(message_type)
    value = json_safe_transform(value, message_type, True)
    return encode_message(value, message_type, *args, **kwargs)

def export_protofile(message_types, output_filename):
    """ Export the give messages as ".proto" file.
        Expects a dictionary with {message_name: typedef} and a filename to
        write to.
    """
    blackboxprotobuf.lib.protofile.export_proto(message_types, output_filename=output_filename)

def import_protofile(input_filename, save_to_known=True):
    """ import ".proto" files and returns the typedef map
        Expects a filename for the ".proto" file
    """
    new_typedefs = blackboxprotobuf.lib.protofile.import_proto(input_filename=input_filename)
    if save_to_known:
        blackboxprotobuf.known_messages.update(new_typedefs)
    else:
        return new_typedefs
        

NAME_REGEX = re.compile(r'\A[a-zA-Z_][a-zA-Z0-9_]*\Z')
def validate_typedef(typedef, old_typedef=None, path=None):
    """Validate the typedef format. Optionally validate wiretype of a field
       number has not been changed
    """
    if path is None:
        path = []
    int_keys = set()
    field_names = set()
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

        valid_type_fields = ["type", "name", "message_typedef",
                             "message_type_name", "alt_typedefs",
                             "example_value_ignored", "seen_repeated"]
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
                if not NAME_REGEX.match(value):
                    raise TypedefException(("Invalid field name \"%s\" for field "
                                            "number %s. Should match %s") %
                                            (value, field_number, "[a-zA-Z_][a-zA-Z0-9_]*"), field_path)
                if value != '':
                    field_names.add(value)

            # Check if message type name is known
            if key == "message_type_name":
                if value not in blackboxprotobuf.known_messages:
                    raise TypedefException(("Message type \"%s\" for field number"
                                            " %s is not known. Known types: %s") % (value, field_number, blackboxprotobuf.known_messages.keys()), field_path)

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
def json_safe_transform(values, typedef, toBytes):
    """ JSON doesn't handle bytes type well. We want to go through and encode
    every bytes type as latin1 to get a semi readable text """

    name_map = {item['name']: number for number, item in typedef.items() if item.get('name', None)}
    for name, value in values.items():
        alt_number = None
        if '-' in name:
            name, alt_number = name.split("-")
        if name in name_map:
            field_number = name_map[name]
            field_type = typedef[field_number]['type']
            if field_type == 'bytes':
                if toBytes:
                    values[name] = values[name].encode('latin1')
                else:
                    values[name] = values[name].decode('latin1')
            elif field_type == 'message':
                if alt_number is not None:
                    if alt_number not in typedef[field_number]['alt_typedefs']:
                        raise TypedefException(('Provided alt field name/number '
                                               '%s is not valid for field_number %s')
                                               % (alt_field_number, field_number))
                    values[name] = json_safe_transform(value, typedef[field_number]['alt_typedefs'][alt_number], toBytes)
                else:
                    values[name] = json_safe_transform(value, _get_typedef_for_message(typedef[field_number]), toBytes)

    return values

def _get_typedef_for_message(field_typedef):
    assert(field_typedef['type'] == 'message')
    if 'message_typedef' in field_typedef:
        return field_typedef['message_typedef']
    elif field_typedef.get('message_type_name'):
        if field_typedef['message_type_name'] not in blackboxprotobuf.known_messages:
            raise TypedefException("Got 'message_type_name' not in known_messages: %s" % field_typedef['message_type_name'])
        return blackboxprotobuf.known_messages[field_typedef['message_type_name']]
    else:
        raise TypedefException("Got 'message' type without typedef or type name: %s" % field_typedef)

def _sort_output(value, typedef):
    """ Sort output by the field number in the typedef. Helps with readability
    in a JSON dump """
    output_dict = collections.OrderedDict()

    for field_number, field_def in sorted(typedef.items(), key = lambda t: int(t[0])):
        field_name = str(field_number)
        if field_name not in value:
            if 'name' in field_def and field_def['name'] != '':
                field_name = field_def['name']
        if field_name in value:
            if field_def['type'] == 'message':
                output_dict[field_name] = _sort_output(value[field_name], _get_typedef_for_message(field_def))
            else:
                output_dict[field_name] = value[field_name]
    return output_dict

def _sort_typedef(typedef):
    """ Sort output by field number and sub_keys so name then type is first """

    TYPEDEF_KEY_ORDER = ['name', 'type', 'message_type_name', 'example_value_ignored']
    output_dict = collections.OrderedDict()

    for field_number, field_def in sorted(typedef.items(), key = lambda t: int(t[0])):
        output_field_def = collections.OrderedDict()
        field_def = field_def.copy()
        for key in TYPEDEF_KEY_ORDER:
            if key in field_def:
                output_field_def[key] = field_def[key]
                del field_def[key]
        for key, value in field_def.items():

            # TODO handle alt typedefs
            if key == 'message_typedef':
                output_field_def[key] = _sort_typedef(value)
            else:
                output_field_def[key] = value
        output_dict[field_number] = output_field_def
    return output_dict

def _annotate_typedef(typedef, message):
    """ Add values from message into the typedef so it's easier to figure out
    which field when you're editing manually """

    for field_number, field_def in typedef.items():
        field_value = None
        field_name = str(field_number)
        if field_name not in message and field_def['name'] != '':
            field_name = field_def['name']

        if field_name in message:
            field_value = message[field_name]

        # TODO handle alt typedefs
        if field_def['type'] == 'message':
            _annotate_typedef(field_def['message_typedef'], field_value)
        else:
            field_def['example_value_ignored'] = field_value

def _strip_typedef_annotations(typedef):
    """ Remove example values placed by _annotate_typedef """
    for _, field_def in typedef.items():
        if 'example_value_ignored' in field_def:
            del field_def['example_value_ignored']
        if 'message_typedef' in field_def:
            _strip_typedef_annotations(field_def['message_typedef'])
