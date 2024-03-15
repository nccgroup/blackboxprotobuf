# Copyright (c) 2018-2023 NCC Group Plc
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

import inspect
import os
import sys
import logging


try:
    import blackboxprotobuf
except ModuleNotFoundError:
    # two abspath because dirname gives an empty string if we run just bbpb.py
    _BASE_DIR = os.path.abspath(
        os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
        + "/.."
    )
    sys.path.insert(0, _BASE_DIR + "/lib/")
    sys.path.insert(0, _BASE_DIR + "/mitmproxy/")
    sys.path.insert(0, _BASE_DIR + "/mitmproxy/deps/six/")
    import blackboxprotobuf

from blackboxprotobuf.lib import payloads
from blackboxprotobuf.lib.exceptions import BlackboxProtobufException

import json
from collections.abc import Sequence


from mitmproxy import (
    command,
    contentviews,
    ctx,
    http,
    flow,
    types,
    exceptions,
    websocket,
)
from mitmproxy.tools.console import overlay, signals


class BlackboxProtobufAddon:
    def __init__(self):
        self.view = BlackboxProtobufView(self)

        self.bbpb_config = blackboxprotobuf.lib.config.Config()
        self.typedef_lookup = {}
        self.project_file = None

    def load(self, loader):
        contentviews.add(self.view)

        loader.add_option(
            "bbpb_project_file",
            typespec=str,
            default="",
            help="Persist known_types and typedef mappings to a project file. File will be written to automatically, so consider keeping a semi-regular backup",
        )

    def _load_project_file(self, project_file: str | None = None):
        self.project_file = ctx.options.bbpb_project_file

        if not project_file and not self.project_file:
            return

        if not project_file:
            project_file = self.project_file

        if not self.project_file:
            return

        logging.info("Loading project data from file")
        try:
            with open(project_file, "r") as f:
                project_data = json.load(f)

            # We update the existing typedef_lookup and bbpb_confg in case we have existing data
            self.typedef_lookup.update(project_data["typedef_lookup"])
            self.bbpb_config.known_types.update(project_data["known_types"])
        except FileNotFoundError:
            # We haven't written anything, so the file might not exist yet
            pass
        self._refresh_view()

    def _save_project_file(self, project_file: str | None = None):
        if not project_file and not self.project_file:
            return

        if not project_file:
            project_file = self.project_file

        logging.info("Writing project data to file")
        data = {
            "typedef_lookup": self.typedef_lookup,
            "known_types": self.bbpb_config.known_types,
        }
        with open(project_file, "w") as f:
            json.dump(data, f, indent=2)

    def configure(self, updates: set[str]):
        if "bbpb_project_file" in updates:
            self._load_project_file()
            self._save_project_file()

    def done(self):
        contentviews.remove(self.view)

    @command.command("bbpb.edit")
    @command.argument("flow_part", type=types.Choice("bbpb.options.edit_part"))
    def bbpb_edit(self, flow_part: str) -> None:
        flow = ctx.master.view.focus.flow

        if flow_part == "request-body":
            message = flow.request
        elif flow_part == "response-body":
            if not flow.response:
                raise exceptions.CommandError(
                    f"Flow part is response-body, but flow has no response"
                )
            message = flow.response
        else:
            raise exceptions.CommandError(f"Got unknown flow_part: {flow_part}")

        message_hash = _message_hash(message.content, message, flow)

        typedef = self.typedef_lookup.get(message_hash)
        message_json, typedef_out, encoding_alg = _decode_protobuf(
            message.content, typedef, self.bbpb_config
        )

        edited_output = message_json
        while True:
            last_data = message_json
            edited_output = ctx.master.spawn_editor(edited_output)
            if edited_output == last_data:
                # No changes to the message, just cancel
                return
            try:
                protobuf_data = blackboxprotobuf.protobuf_from_json(
                    edited_output, typedef_out
                )
                break
            except Exception as ex:
                logging.error(f"Error while editing typedef: {ex}")

        data = payloads.encode_payload(protobuf_data, encoding_alg)
        message.content = bytes(data)
        self._refresh_view()

    @command.command("bbpb.edit_type")
    @command.argument("flow_part", type=types.Choice("bbpb.options.edit_type_part"))
    def bbpb_edit_type(self, flow_part: str) -> None:
        flow = ctx.master.view.focus.flow

        typedef, message_hash = self._resolve_type(flow_part)

        typedef_json = json.dumps(typedef, indent=2)
        edited_json = typedef_json
        while True:
            last_json = edited_json
            edited_json = ctx.master.spawn_editor(edited_json)
            if edited_json == last_json:
                # cancelling editing
                return
            try:
                new_typedef = json.loads(edited_json)
                blackboxprotobuf.validate_typedef(new_typedef, typedef)
                break
            except Exception as ex:
                logging.error(f"Error while editing typedef: {ex}")

        blackboxprotobuf.lib.api._strip_typedef_annotations(new_typedef)
        known_type = self.typedef_lookup.get(message_hash)
        if isinstance(known_type, str):
            # This is a named typedef, edit the known typedef instead of the saved value
            self.bbpb_config.known_types[known_type] = new_typedef
            self._save_project_file()
        else:
            # Trusting validate_typedef and not going to try to use the typedef to decode again or reencode
            self.typedef_lookup[message_hash] = new_typedef
            self._save_project_file()

        self._refresh_view()

    @command.command("bbpb.apply_type")
    @command.argument("flow_part", type=types.Choice("bbpb.options.edit_type_part"))
    @command.argument("typename", type=types.Choice("bbpb.options.known_types"))
    def bbpb_apply_type(self, flow_part: str, typename: str) -> None:
        flow = ctx.master.view.focus.flow
        if typename not in self.bbpb_config.known_types and typename != "(clear)":
            raise exceptions.CommandError(f"Type {typename} is not a know type")
        flow = ctx.master.view.focus.flow
        if not flow:
            raise exceptions.CommandError("No flow selected.")
        if flow_part.startswith("request") or flow_part.startswith("response"):
            if flow_part == "request-body":
                message = flow.request
            elif flow_part == "response-body":
                if not flow.response:
                    raise exceptions.CommandError(
                        f"Flow part is response-body, but flow has no response"
                    )
                message = flow.response
            message_hash = _message_hash(message.content, message, flow)
            if typename == "(clear)":
                logging.info("popping message hash")
                self.typedef_lookup.pop(message_hash, None)
                self._save_project_file()
                self._refresh_view()
                return

            # Validate that we can decode the message with our new type
            try:
                _decode_protobuf(
                    message.content, typename, self.bbpb_config, fallback=False
                )
            except BlackboxProtobufException as ex:
                raise exceptions.CommandError(
                    f"Error applying type name {typename} to part {flow_part}: {ex}"
                )

        elif flow_part.startswith("websocket"):
            # Websockets don't have a single typedef to edit
            # Instead, we are going to build a typedef based on all the messages
            if flow_part == "websocket-request":
                if not flow.websocket:
                    raise exceptions.CommandError(
                        f"Flow part is websocket-request, but flow is not a websocket"
                    )
                messages = [
                    message
                    for message in flow.websocket.messages
                    if message.from_client
                ]
            elif flow_part == "websocket-response":
                if not flow.websocket:
                    raise exceptions.CommandError(
                        f"Flow part is websocket-response, but flow is not a websocket"
                    )
                messages = [
                    message
                    for message in flow.websocket.messages
                    if not message.from_client
                ]
            if not messages:
                raise exceptions.CommandError(
                    f"Could not find any messages for flow part: {flow_part}"
                )
            message_hash = _message_hash(messages[0].content, messages[0], flow)
            if typename == "(clear)":
                logging.info("popping message hash")
                self.typedef_lookup.pop(message_hash, None)
                self._save_project_file()
                self._refresh_view()
                return
            # Validate that we can decode all messages with our type
            for message in messages:
                try:
                    _decode_protobuf(
                        message.content, typename, self.bbpb_config, fallback=False
                    )
                except BlackboxProtobufException as ex:
                    raise exceptions.CommandError(
                        f"Error applying type name {typename} to part {flow_part}: {ex}"
                    )
        # Success
        self.typedef_lookup[message_hash] = typename
        self._save_project_file()
        self._refresh_view()

    @command.command("bbpb.new_type")
    @command.argument("flow_part", type=types.Choice("bbpb.options.edit_type_part"))
    @command.argument("typename", type=str)
    def bbpb_new_type(self, flow_part: str, typename: str) -> None:
        if typename == "(clear)":
            raise exceptions.CommandError(f"Error: Typename {typename} is not valid.")
        typedef, message_hash = self._resolve_type(flow_part)

        blackboxprotobuf.lib.api._strip_typedef_annotations(typedef)
        self.typedef_lookup[message_hash] = typename
        self.bbpb_config.known_types[typename] = typedef
        self._save_project_file()

        self._refresh_view()

    def _resolve_type(self, flow_part):
        flow = ctx.master.view.focus.flow
        if not flow:
            raise exceptions.CommandError("No flow selected.")
        if flow_part.startswith("request") or flow_part.startswith("response"):
            if flow_part == "request-body":
                message = flow.request
            elif flow_part == "response-body":
                if not flow.response:
                    raise exceptions.CommandError(
                        f"Flow part is response-body, but flow has no response"
                    )
                message = flow.response
            message_hash = _message_hash(message.content, message, flow)
            saved_typedef = self.typedef_lookup.get(message_hash)
            message_json, typedef, encoding_alg = _decode_protobuf(
                message.content, saved_typedef, self.bbpb_config
            )
        elif flow_part.startswith("websocket"):
            # Websockets don't have a single typedef to edit
            # Instead, we are going to build a typedef based on all the messages
            if flow_part == "websocket-request":
                if not flow.websocket:
                    raise exceptions.CommandError(
                        f"Flow part is websocket-request, but flow is not a websocket"
                    )
                messages = [
                    message
                    for message in flow.websocket.messages
                    if message.from_client
                ]
            elif flow_part == "websocket-response":
                if not flow.websocket:
                    raise exceptions.CommandError(
                        f"Flow part is websocket-response, but flow is not a websocket"
                    )
                messages = [
                    message
                    for message in flow.websocket.messages
                    if not message.from_client
                ]
            if not messages:
                raise exceptions.CommandError(
                    f"Could not find any messages for flow part: {flow_part}"
                )
            message_hash = _message_hash(messages[0].content, messages[0], flow)
            saved_typedef = self.typedef_lookup.get(message_hash)
            try:
                typedef = saved_typedef
                message_jsons = []
                for message in messages:
                    message_json, typedef, encoding_alg = _decode_protobuf(
                        message.content, typedef, self.bbpb_config, fallback=False
                    )
                    message_jsons.append(message_json)
            except BlackboxProtobufException:
                typedef = {}
                message_jsons = []
                for message in messages:
                    message_json, typedef, encoding_alg = _decode_protobuf(
                        message.content, typedef, self.bbpb_config, fallback=False
                    )
                    message_jsons.append(message_json)
        else:
            raise exceptions.CommandError(f"Got unknown flow_part: {flow_part}")

        return typedef, message_hash

    @command.command("bbpb.del_type")
    @command.argument("typename", type=types.Choice("bbpb.options.known_types"))
    def bbpb_del_type(self, typename: str) -> None:
        if typename not in self.bbpb_config.known_types:
            raise exceptions.CommandError(f"Error: Type {typename} is not known")
        self.bbpb_config.known_types.pop(typename, None)
        keys_to_remove = [
            key for key, value in self.typedef_lookup.items() if value == typename
        ]
        for key in keys_to_remove:
            self.typedef_lookup.pop(key, None)
        self._save_project_file()
        self._refresh_view()

    @command.command("bbpb.options.edit_part")
    def bbpb_options_edit_part(self) -> Sequence[str]:
        flow = ctx.master.view.focus.flow
        if not flow:
            raise exceptions.CommandError("No flow selected.")

        # Prompts the user for the section to edit
        if flow.response:
            return [
                "request-body",
                "response-body",
            ]
        else:
            return ["request-body"]

    @command.command("bbpb.options.edit_type_part")
    def bbpb_options_edit_type_part(self) -> Sequence[str]:
        flow = ctx.master.view.focus.flow
        if flow.websocket:
            return ["websocket-request", "websocket-response"]
        if flow.response:
            return [
                "request-body",
                "response-body",
            ]
        return ["request-body"]

    @command.command("bbpb.options.known_types")
    def bbpb_options_known_types(self) -> Sequence[str]:
        typenames = list(self.bbpb_config.known_types.keys())
        return typenames + ["(clear)"]

    def _refresh_view(self):
        ctx.master.window.stacks[0].windows["flowview"].body.contentview_changed(None)

    @command.command("bbpb.project.load")
    def bbpb_project_load(self, project_file: str) -> None:
        # TODO would be good to have errors propagated here
        self._load_project_file(project_file)

    @command.command("bbpb.project.save")
    def bbpb_project_save(self, project_file: str) -> None:
        # TODO would be good to have errors propagated here
        self._save_project_file(project_file)


class BlackboxProtobufView(contentviews.View):
    name = "Blackbox Protobuf"

    def __init__(self, addon: BlackboxProtobufAddon):
        self.addon = addon

    def __call__(
        self,
        data: bytes,
        *,
        content_type: str | None = None,
        flow: flow.Flow | None = None,
        http_message: http.Message | None = None,
        **unknown_metadata,
    ) -> contentviews.TViewResult:
        # No support for TCP or UDP flows
        if not isinstance(flow, http.HTTPFlow):
            return None

        if len(data) == 0:
            return

        # message_hash is for looking up the appropiate typedef for this request, based on URL and type of message
        message_hash = _message_hash(data, http_message, flow)

        typedef = self.addon.typedef_lookup.get(message_hash)

        message, typedef_out, encoding_alg = _decode_protobuf(
            data, typedef, self.addon.bbpb_config
        )

        title = "Protobuf"
        if isinstance(typedef, str):
            title += f"  |  Type: {typedef}"
        else:
            title += f"  |  Type: anonymous"

        return title, contentviews.format_text(message)

    def render_priority(
        self,
        data: bytes,
        *,
        content_type: str | None = None,
        flow: flow.Flow | None = None,
        http_message: http.Message | None = None,
        **unknown_metadata,
    ) -> float:
        if content_type:
            if "protobuf" in content_type or "grpc" in content_type:
                return 2
            else:
                return 0
        # We don't know if we can decode protobuf or not, so let's elect
        # ourselves for all websockets
        if flow.websocket:
            return 1
        return 0


# This could be improved by taking is_request from the client for some cases
def _message_hash(
    data: bytes,
    message: http.Message | websocket.WebSocketMessage | None,
    flow: flow.Flow | None,
):
    if isinstance(message, http.Request):
        return f"request|{flow.request.url}"
    elif isinstance(message, http.Response):
        return f"response|{flow.request.url}"
    elif flow.websocket:
        if message is None or not isinstance(message, websocket.WebSocketMessage):
            # TODO this is really hacky and might be wasted cycles if there are
            # a lot of messages
            # Mitmproxy won't give us the WebSocketMessage message type for
            # content views, so we can't tell which direction it's going from
            # just the message.
            try:
                message = next(
                    (m for m in flow.websocket.messages if m.content == data)
                )
            except StopIteration:
                logging.warn(
                    "Message hashing couldn't find matching message in flow.websocket.messages"
                )
                message = None

        # Default to request if we never figured out the message
        if message and not message.from_client:
            return f"websocket-response|{flow.request.url}"
        else:
            return f"websocket-request|{flow.request.url}"
    else:
        logging.warn(
            f"BBPB content view got a view that was not websocket, request or response: {type(http_message)}"
        )
        return None


def _decode_protobuf(data, typedef, config, fallback=True):
    try:
        decoders = payloads.find_decoders(data)
        for decoder in decoders:
            try:
                protobuf_data, encoding_alg = decoder(data)
            except BlackboxProtobufException:
                continue

            try:
                message, typedef_out = blackboxprotobuf.lib.protobuf_to_json(
                    protobuf_data, typedef, config=config
                )

                return message, typedef_out, encoding_alg
            except BlackboxProtobufException as exc:
                if encoding_alg == "none":
                    raise exc
                continue
    except BlackboxProtobufException as exc:
        if typedef and fallback:
            return _decode_protobuf(data, {}, config)
        else:
            raise exc
    raise BlackboxProtobufException(
        'Failed to decode protobuf, but did not catch "none" decoder. This should never be hit'
    )


addons = [BlackboxProtobufAddon()]
