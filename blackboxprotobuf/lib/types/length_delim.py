"""Module for encoding and decoding length delimited fields"""
import binascii
import copy
import sys
import six
import logging

from google.protobuf.internal import wire_format, encoder, decoder

import blackboxprotobuf.lib.types
from blackboxprotobuf.lib.types import varint
from blackboxprotobuf.lib.exceptions import (
    EncoderException, DecoderException, TypedefException, BlackboxProtobufException)

# Turn on to get debug messages for binary field guessing
#logging.basicConfig(level=logging.DEBUG)

# Number of messages "deep" to keep guessing. Want to cap to prevent edge cases
# where it attempts to parse a non-message binary as a message and it blows up
# the python stack
max_guess_recursion = 5

def decode_guess(buf, pos, depth=0, path=None):
    """Try to decode as an empty message first, then just do as bytes
       Returns the value + the type
       Max recursion should help with edge cases where it keeps guessing deeper
       and deeper into the stack.
    """
    if path is None:
        path = []

    try:
        if depth > max_guess_recursion:
            raise DecoderException(("Maximum guess recursion exceeded during decoding."
                                    " current_depth: %d limit: %d") % (depth, max_guess_recursion))
        return decode_lendelim_message(buf, {}, pos, depth=depth+1, path=path), 'message'
    except DecoderException as exc:
        # This case is normal and expected, but if there is a field that we
        # care about and want to know why it isn't decoding, this could be
        # useful

        logging.debug(("Attempted to decode lengh delimited message at %s, but "
                       "failed to find a message, treating field as binary. "
                       "Exception:\n %r"), "->".join(map(str, path)),
                                             str(exc))
    try:
        # Try to encode the binary as a unicode string
        return decode_string(buf, pos), 'string'
    except DecoderException as exc:
        logging.debug(("Attempted to decode lengh delimited message at %s as "
                       "UTF-8, but could not successfuly decode the string"),
                       "->".join(map(str, path)), str(exc))

    default_type = blackboxprotobuf.lib.types.default_binary_type
    if (blackboxprotobuf.lib.types.wiretypes[default_type]
            != wire_format.WIRETYPE_LENGTH_DELIMITED):
        raise BlackboxProtobufException(
            "Incorrect \'default_type\' specified in wiretypes.py: %s"
            % default_type)
    return blackboxprotobuf.lib.types.decoders[default_type](buf, pos), default_type

def encode_string(value):
    try:
        value = six.ensure_text(value)
    except TypeError as exc:
        six.raise_from(EncoderException("Error encoding string to message: %r" % value), exc)
    return encode_bytes(value)

def encode_bytes(value):
    """Encode varint length followed by the string.
       This should also work to encode incoming string values.
    """
    if isinstance(value, bytearray):
        value = bytes(value)
    try:
        value = six.ensure_binary(value)
    except TypeError as exc:
        six.raise_from(EncoderException("Error encoding bytes to message: %r" % value), exc)
    encoded_length = varint.encode_varint(len(value))
    return encoded_length + value

def decode_bytes(value, pos):
    """Decode varint for the length and then returns that number of bytes"""
    length, pos = varint.decode_varint(value, pos)
    end = pos+length
    try:
        return value[pos:end], end
    except IndexError as exc:
        six.raise_from(DecoderException(
            ("Error decoding bytes. Decoded length %d is longer than bytes"
             " available %d") % (length, len(value)-pos)), exc)

def encode_bytes_hex(value):
    """Encode varint length followed by the string.
       Expects a string of hex characters
    """
    try:
        return encode_bytes(binascii.unhexlify(value))
    except (TypeError, binascii.Error) as exc:
        six.raise_from(EncoderException("Error encoding hex bytestring %s" % value), exc)

def decode_bytes_hex(buf, pos):
    """Decode varint for length and then returns that number of bytes.
       Outputs the bytes as a hex value
    """
    value, pos = decode_bytes(buf, pos)
    return binascii.hexlify(value), pos

def decode_string(value, pos):
    """Decode varint for length and then the bytes"""
    length, pos = varint.decode_varint(value, pos)
    end = pos+length
    try:
        # backslash escaping isn't reversible easily
        return value[pos:end].decode('utf-8'), end
    except (TypeError, UnicodeDecodeError) as exc:
        six.raise_from(DecoderException("Error decoding UTF-8 string %s" % value[pos:end]), exc)


def encode_message(data, typedef, group=False, path=None):
    """Encode a Python dictionary representing a protobuf message
       data - Python dictionary mapping field numbers to values
       typedef - Type information including field number, field name and field type
       This will throw an exception if an unkown value is used as a key
    """
    output = bytearray()
    if path is None:
        path = []

    # TODO Implement path for encoding
    for field_number, value in data.items():
        # Get the field number convert it as necessary
        alt_field_number = None

        if six.PY2:
            string_types = (str, unicode)
        else:
            string_types = str

        if isinstance(field_number, string_types):
            if '-' in field_number:
                field_number, alt_field_number = field_number.split('-')
            # TODO can refactor to cache the name to number mapping
            for number, info in typedef.items():
                if 'name' in info and info['name'] == field_number and field_number != '':
                    field_number = number
                    break
        else:
            field_number = str(field_number)

        field_path = path[:]
        field_path.append(field_number)

        if field_number not in typedef:
            raise EncoderException("Provided field name/number %s is not valid"
                                   % (field_number), field_path)

        field_typedef = typedef[field_number]

        # Get encoder
        if 'type' not in field_typedef:
            raise TypedefException('Field %s does not have a defined type.' % field_number, field_path)

        field_type = field_typedef['type']

        field_encoder = None
        if field_type == 'message':
            innertypedef = None
            # Check for a defined message type
            if alt_field_number is not None:
                if alt_field_number not in field_typedef['alt_typedefs']:
                    raise EncoderException(
                        'Provided alt field name/number %s is not valid for field_number %s'
                        % (alt_field_number, field_number), field_path)
                innertypedef = field_typedef['alt_typedefs'][alt_field_number]
            elif 'message_typedef' in field_typedef:
                innertypedef = field_typedef['message_typedef']
            else:
                if field_typedef['message_type_name'] not in blackboxprotobuf.lib.known_messages:
                    raise TypedefException("Message type (%s) has not been defined"
                                           % field_typedef['message_type_name'], field_path)
                innertypedef = field_typedef['message_type_name']

            field_encoder = lambda data: encode_lendelim_message(data, innertypedef, path=field_path)
        elif field_type == 'group':
            innertypedef = None
            # Check for a defined group type
            if 'group_typedef' not in field_typedef:
                raise TypedefException("Could not find type definition for group field: %s"
                                       % field_number, field_path)
            innertypedef = field_typedef['group_typedef']

            field_encoder = lambda data: encode_group(data, innertypedef, field_number, path=field_path)
        else:
            if field_type not in blackboxprotobuf.lib.types.encoders:
                raise TypedefException('Unknown type: %s' % field_type)
            field_encoder = blackboxprotobuf.lib.types.encoders[field_type]
            if field_encoder is None:
                raise TypedefException('Encoder not implemented for %s' % field_type, field_path)


        # Encode the tag
        tag = encoder.TagBytes(int(field_number), blackboxprotobuf.lib.types.wiretypes[field_type])

        try:
            # Handle repeated values
            if isinstance(value, list) and not field_type.startswith('packed_'):
                for repeated in  value:
                    output += tag
                    output += field_encoder(repeated)
            else:
                output += tag
                output += field_encoder(value)
        except EncoderException as exc:
            exc.set_path(field_path)
            six.reraise(*sys.exc_info())

    return output

def decode_message(buf, typedef=None, pos=0, end=None, group=False, depth=0, path=None):
    """Decode a protobuf message with no length delimiter"""
    if end is None:
        end = len(buf)

    if typedef is None:
        typedef = {}
    else:
        # Don't want to accidentally modify the original
        typedef = copy.deepcopy(typedef)

    if path is None:
        path = []

    output = {}

    while pos < end:
        # Read in a field
        try:
            if six.PY2:
                tag, pos = decoder._DecodeVarint(str(buf), pos)
            else:
                tag, pos = decoder._DecodeVarint(buf, pos)
        except (IndexError, decoder._DecodeError) as exc:
            six.raise_from(DecoderException(
                "Error decoding length from buffer: %r..." %
                (binascii.hexlify(buf[pos : pos+8]))), exc)

        field_number, wire_type = wire_format.UnpackTag(tag)

        # Convert to str
        field_number = str(field_number)
        orig_field_number = field_number

        field_path = path[:]
        field_path.append(field_number)

        if wire_type not in blackboxprotobuf.lib.types.wire_type_defaults:
            raise DecoderException('%d is not a valid wire type at pos %d.' % (wire_type, pos), field_path)

        field_typedef = None
        if field_number in typedef:
            field_typedef = typedef[field_number]
        else:
            field_typedef = {}
            field_typedef['type'] = blackboxprotobuf.lib.types.wire_type_defaults[wire_type]

        field_type = field_typedef['type']

        # If field_type is None, its either an unsupported wire type, length delim or group
        # length delim we have to try and decode first
        field_out = None
        if field_type is None:
            if wire_type == wire_format.WIRETYPE_LENGTH_DELIMITED:
                out, field_type = decode_guess(buf, pos, depth=depth, path=field_path)
                if field_type == 'message':
                    field_out, message_typedef, pos = out
                    field_typedef['message_typedef'] = message_typedef
                else:
                    field_out, pos = out
            elif  wire_type == wire_format.WIRETYPE_END_GROUP:
                # TODO Should probably match the field_number to START_GROUP
                if not group:
                    raise DecoderException( "Found END_GROUP before START_GROUP", field_path)
                # exit out
                return output, typedef, pos
            else:
                raise DecoderException("Could not find default type for wiretype: %d" % wire_type, field_path)
        else:
            if field_type == 'message':
                #TODO probably big enough to factor out
                message_typedef = None
                # Check for a anonymous type
                if 'message_typedef' in field_typedef:
                    message_typedef = field_typedef['message_typedef']
                # Check for type defined by message type name
                elif 'message_type_name' in field_typedef:
                    message_typedef = blackboxprotobuf.lib.known_messages[
                        field_typedef['message_type_name']]

                try:
                    field_out, message_typedef, pos = decode_lendelim_message(
                        buf, message_typedef, pos, path=field_path)
                    # Save type definition
                    field_typedef['message_typedef'] = message_typedef
                except DecoderException as exc:
                    # If this is the root message just fail
                    if pos == 0:
                        six.reraise(*sys.exc_info())
                    logging.debug(
                        ("Encountered exception when decoding message at %s "
                         "with known typdef. Trying alt typedefs and then "
                         "anonymous. Exception: \n%s"),
                        "->".join(map(str, field_path)), str(exc))

                if field_out is None and 'alt_typedefs' in field_typedef:
                    # check for an alternative type definition
                    for alt_field_number, alt_typedef in field_typedef['alt_typedefs'].items():
                        try:
                            field_out, message_typedef, pos = decode_lendelim_message(
                                buf, alt_typedef, pos, path=field_path)
                        except DecoderException as exc:
                            logging.debug(
                                ("Encountered exception when decoding message at %s with alt_typedef %s. Trying anonymous decoding next. Exception:\n%s"),
                                "->".join(map(str, field_path)),
                                str(alt_field_number),
                                str(exc))

                        if field_out is not None:
                            # Found working typedef
                            field_typedef['alt_typedefs'][alt_field_number] = message_typedef
                            field_number = field_number + "-" + alt_field_number
                            break

                if field_out is None:
                    # Still no typedef, try anonymous, and let the error propogate if it fails
                    field_out, message_typedef, pos = \
                        decode_lendelim_message(buf, {}, pos, path=field_path)

                    if 'alt_typedefs' in field_typedef:
                        # get the next higher alt field number
                        alt_field_number = str(
                            max(map(int, field_typedef['alt_typedefs'].keys()))
                            + 1)
                    else:
                        field_typedef['alt_typedefs'] = {}
                        alt_field_number = '1'

                    field_typedef['alt_typedefs'][alt_field_number] = message_typedef
                    field_number = field_number + "-" + alt_field_number
            elif field_type == 'group':
                group_typedef = None
                # Check for a anonymous type
                if 'group_typedef' in field_typedef:
                    group_typedef = field_typedef['group_typedef']
                field_out, group_typedef, pos = \
                    decode_group(buf, group_typedef, pos, depth=depth, path=field_path)
                # Save type definition
                field_typedef['group_typedef'] = group_typedef
            else:
                # Verify wiretype matches
                if blackboxprotobuf.lib.types.wiretypes[field_type] != wire_type:
                    raise DecoderException(
                        "Invalid wiretype for field number %s. %s is not wiretype %s"
                        % (field_number, field_type, wire_type), field_path)

                # Simple type, just look up the decoder
                try:
                    field_out, pos = blackboxprotobuf.lib.types.decoders[field_type](buf, pos)
                except DecoderException as exc:
                    exc.set_path(field_path)
                    six.reraise(*sys.exc_info())
        field_typedef['type'] = field_type
        if 'name' not in field_typedef:
            field_typedef['name'] = ''

        field_key = field_number
        if '-' not in field_number  and 'name' in field_typedef and field_typedef['name'] != '':
            field_key = field_typedef['name']
        # Deal with repeats
        if field_key in output:
            if isinstance(field_out, list):
                if isinstance(output[field_key], list):
                    output[field_key] += field_out
                else:
                    output[field_key] = field_out.append(output[field_key])
            else:
                if isinstance(output[field_key], list):
                    output[field_key].append(field_out)
                else:
                    output[field_key] = [output[field_key], field_out]
        else:
            output[field_key] = field_out
            typedef[orig_field_number] = field_typedef
    if pos > end:
        raise DecoderException(
            "Field sizes are greater than designated length. pos: %d end_pos: %d" % (pos, end))
    # Should never hit here as a group
    if group:
        raise DecoderException("Got START_GROUP with no END_GROUP.")
    return output, typedef, pos

def encode_lendelim_message(data, typedef, path=None):
    """Encode the length before the message"""
    message_out = encode_message(data, typedef, path=path)
    length = varint.encode_varint(len(message_out))
    return length + message_out

def decode_lendelim_message(buf, typedef=None, pos=0, depth=0, path=None):
    """Read in the length and use it as the end"""
    length, pos = varint.decode_varint(buf, pos)
    ret = decode_message(buf, typedef, pos, pos+length, depth=depth, path=path)
    return ret

# Not actually length delim, but we're hijacking the methods anyway
def encode_group(value, typedef, field_number, path=None):
    """Encode a protobuf group type"""
    # Message will take care of the start tag
    # Need to add the end_tag
    output = encode_message(value, typedef, group=True, path=path)
    end_tag = encoder.TagBytes(int(field_number), wire_format.WIRETYPE_END_GROUP)
    output.append(end_tag)
    return output

def decode_group(buf, typedef=None, pos=0, end=None, depth=0, path=None):
    """Decode a protobuf group type"""
    if typedef is None:
        depth = depth+1
    else:
        depth = 0
    if depth > max_guess_recursion:
        raise DecoderException(
            "Maximum guess recursion exceeded. current_depth: %d limit: %d"
            % (depth, max_guess_recursion))
    return decode_message(buf, typedef, pos, end, group=True, depth=depth, path=path)

def generate_packed_encoder(wrapped_encoder):
    """Generate an encoder for a packed type from the base type encoder"""
    def length_wrapper(values):
        """Encode repeat values and prefix with the length"""
        output = bytearray()
        for value in values:
            output += wrapped_encoder(value)
        length = varint.encode_varint(len(output))
        return length + output
    return length_wrapper

def generate_packed_decoder(wrapped_decoder):
    """Generate an decoder for a packer type from a base type decoder"""
    def length_wrapper(buf, pos):
        """Decode repeat values prefixed with the length"""
        length, pos = varint.decode_varint(buf, pos)
        end = pos+length
        output = []
        while pos < end:
            value, pos = wrapped_decoder(buf, pos)
            output.append(value)
        if pos > end:
            raise DecoderException(
                ("Error decoding packed field. Packed length larger than"
                 " buffer: decoded = %d, left = %d")
                % (length, len(buf) - pos))
        return output, pos
    return length_wrapper
