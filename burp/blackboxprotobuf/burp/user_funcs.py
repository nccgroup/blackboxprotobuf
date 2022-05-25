"""These functions provide hooks into the blackboxprotobuf Burp extension,
allowing certain functionality to be customized in order to handle non-standard
applications.
"""

# Copyright (c) 2018-2022 NCC Group Plc
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


# Documentation for Common parameters:
#   content -- Binary content of the request
#   is_request -- boolean, True for a request, False for a response
#   content_info -- RequestInfo or ResponseInfo object, See
#       https://portswigger.net/Burp/extender/api/burp/IRequestInfo.html and
#       https://portswigger.net/Burp/extender/api/burp/IResponseInfo.html
#   helpers -- Burp extension helpers,
#       https://portswigger.net/Burp/extender/api/burp/IExtensionHelpers.html
#   request/request_content_info -- If called on a response, send the
#       corresponding request (useful for retrieving URL parameters)

# Useful functionality:
#    URL parameters:
#        for param in content_info.getParmeters():
#            if param.getName() == 'type':
#                ...
#    Headers:
#        if 'content-type' in content_info.getHeaders():
#            ...
#    Request Body:
#       body = content[content_info.getBodyOffset():].tostring()
#    Setting paramater:
#       import burp.IParameter
#       body = helpers.updateParameter(
#                   content,
#                   helpers.buildParameter('message',
#                                          protobuf_data,
#                                          IParameter.PARAM_URL))


def detect_protobuf(content, is_request, content_info, helpers):
    """Customize protobuf detection with a request or a response. Should return True if it is a protobuf,
    False if it definitely not a protobuf and should not try to decode, or None
    to fallback to the standard content-type header detection.

    This can be used to add protobuf detection based on different headers or
    customer application functionality. You can also use "return True" to try
    to decode every request/response.
    """
    pass


def get_protobuf_data(
    content, is_request, content_info, helpers, request=None, request_content_info=None
):
    """Customize how the protobuf data is retrieved from the request. By
    default, it is assumed the body of the request/response contains a
    protobuf payload and tries to detect if it's compressed.

    This function can be used if the payload is in a non-standard location or
    has a non-standard encoding. It should return the raw protobuf bytes from
    the message.
    """
    pass


def set_protobuf_data(
    protobuf_data,
    content,
    is_request,
    content_info,
    helpers,
    request=None,
    request_content_info=None,
):
    """Customize how the protobuf data is set in request/response. This
    function is used to configure where in the request the protobuf data is
    placed and how it is encoded if the message is modified. For example, this
    could set a query parameter with base64 encoded data if that is what the
    application expects. This function is the mirror to `get_protobuf_data` and
    if one function is modified, then the other should as well.

    This is expected to return bytes representing the HTTP headers and body,
    such as that returned by the `buildHttpMessage` function of the Burp
    helpers
    (https://portswigger.net/burp/extender/api/burp/iextensionhelpers.html#buildHttpMessage)
    """
    pass


def hash_message(
    content, is_request, content_info, helpers, request=None, request_content_info=None
):
    """Blackbox protobuf remembers which type definition to use for each
    request/response by saving them in a dictionary, keyed by a 'message hash'.
    If a message has the same hash, it will try to re-use the same type
    definition. By default, this is the request path and true or false
    depending whether it is a request or response.

    If there isn't a one-to-one mapping of message types to URLs, then this
    function can be used to customize what parts of the request to use for
    identification (eg. a message type header or parameter).

    This function should return a string.
    """
    pass
