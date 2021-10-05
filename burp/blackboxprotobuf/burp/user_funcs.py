"""These functions allow functionality within the Blackbox protobuf extension
   to be customized in order to handle undefined behavior.

    Common parameters:
        content -- Binary content of the request
        is_request -- boolean, True for a request, False for a response
        content_info -- RequestInfo or ResponseInfo object, See
            https://portswigger.net/Burp/extender/api/burp/IRequestInfo.html and
            https://portswigger.net/Burp/extender/api/burp/IResponseInfo.html
        helpers -- Burp extension helpers,
            https://portswigger.net/Burp/extender/api/burp/IExtensionHelpers.html
        request/request_content_info -- If called on a response, send the
            corresponding request (useful for retrieving URL parameters)

    Useful functionality:
        URL parameters:
            for param in content_info.getParmeters():
                if param.getName() == 'type':
                    ...
        Headers:
            if 'content-type' in content_info.getHeaders():
                ...
        Request Body:
            body = content[content_info.getBodyOffset():].tostring()
        Setting paramater:
            import burp.IParameter
            body = helpers.updateParameter(
                        content,
                        helpers.buildParameter('message',
                                               protobuf_data,
                                               IParameter.PARAM_URL))
"""


def detect_protobuf(content, is_request, content_info, helpers):
    """Customize protobuf detection. Passes in request. Should return True,
    False, or None (to use default detection)"""
    pass


def get_protobuf_data(
    content, is_request, content_info, helpers, request=None, request_content_info=None
):
    """Customize how the protobuf data is retrieved from the request. For
    example, in a parameter or encoded."""
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
    """Customize how the protobuf data is set in request/response. For example,
    in a parameter or encoded. Should mirror get_protobuf_data"""
    pass


def hash_message(
    content, is_request, content_info, helpers, request=None, request_content_info=None
):
    """Customize how a request is identified for type definition saving. Two
    requests will use the same type definition if this function returns the
    same value.
    """
    pass
