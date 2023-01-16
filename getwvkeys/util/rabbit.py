"""
 This file is part of the GetWVKeys project (https://github.com/GetWVKeys/getwvkeys)
 Copyright (C) 2022 Notaghost, Puyodead1 and GetWVKeys contributors 
 
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published
 by the Free Software Foundation, version 3 of the License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import ast
import asyncio
import json
import threading
import time
import uuid
from time import sleep

import pika
from pika import channel, spec

from getwvkeys import libraries
from getwvkeys.config import RABBITMQ_URI
from getwvkeys.models.Shared import db
from getwvkeys.utils import OPCode, logger


class RpcClient(object):
    """Asynchronous Rpc client."""

    internal_lock = threading.Lock()
    queue = {}

    def __init__(self, rpc_queue, app, library: libraries.Library):
        logger.info("[RabbitMQ] Initializing RPC client")

        self.rpc_queue = rpc_queue
        self.app = app
        self.library = library
        self.connection = pika.BlockingConnection(parameters=pika.URLParameters(RABBITMQ_URI))
        self.channel = self.connection.channel()
        result = self.channel.queue_declare(queue=self.rpc_queue, exclusive=True)
        self.callback_queue = result.method.queue
        thread = threading.Thread(target=self._process_data_events)
        self.temp_queue = []
        thread.setDaemon(True)
        thread.start()

    def _process_data_events(self):
        self.channel.basic_consume(queue=self.rpc_queue, on_message_callback=self._on_response, auto_ack=True)
        while True:
            with self.internal_lock:
                self.connection.process_data_events()
                sleep(0.1)

    def _on_response(self, ch: channel.Channel, method, props: spec.BasicProperties, body):
        if props.correlation_id in self.queue:
            self.queue[props.correlation_id] = body
            return

        # process a global message, aka not a response to a message
        try:
            data = json.loads(body.decode())
            op = data.get("op")
            d = data.get("d")

            print("OPCode {}; d: {}".format(op, json.dumps(d)))

            if op == OPCode.DISABLE_USER.value:
                user_id = d.get("user_id")
                if not user_id:
                    self.publish_error(ch, props, "No user_id found in message")
                    return
                with self.app.app_context():
                    try:
                        libraries.User.disable_user(db, user_id)
                        self.publish_response(ch, props)
                    except Exception as e:
                        self.publish_error(ch, props, "Error disablng user {}: {}".format(user_id, e))
            elif op == OPCode.DISABLE_USER_BULK.value:
                user_ids = d.get("user_ids")
                if not user_ids:
                    self.publish_error(ch, props, "No user_ids found in message")
                    return
                with self.app.app_context():
                    try:
                        libraries.User.disable_users(db, user_ids)
                        self.publish_response(
                            ch,
                            props,
                        )
                    except Exception as e:
                        self.publish_error(ch, props, "Error disablng users: {}".format(e))
            elif op == OPCode.ENABLE_USER.value:
                user_id = d.get("user_id")
                if not user_id:
                    self.publish_error(ch, props, "No user_id found in message")
                    return
                with self.app.app_context():
                    try:
                        libraries.User.enable_user(db, user_id)
                        self.publish_response(
                            ch,
                            props,
                        )
                    except Exception as e:
                        self.publish_error(ch, props, "Error enabling user {}: {}".format(user_id, e))
            elif op == OPCode.KEY_COUNT.value:
                with self.app.app_context():
                    self.publish_response(ch, props, self.library.get_keycount())
            elif op == OPCode.USER_COUNT.value:
                with self.app.app_context():
                    self.publish_response(ch, props, libraries.User.get_user_count())
            elif op == OPCode.SEARCH.value:
                query = d.get("query")
                if not query:
                    self.publish_error(ch, props, "No query found in message")
                    return
                with self.app.app_context():
                    try:
                        results = self.library.search(query)
                        results = self.library.search_res_to_dict(query, results)
                        self.publish_response(ch, props, results)
                    except Exception as e:
                        self.publish_error(ch, props, "Error searching: {}".format(e))
            elif op == OPCode.UPDATE_PERMISSIONS.value:
                user_id = d.get("user_id")
                permissions = d.get("permissions")
                permission_action = d.get("permission_action")
                if not user_id or not permissions:
                    self.publish_error(ch, props, "No user_id or permissions found in message")
                    return
                with self.app.app_context():
                    try:
                        user = libraries.User.get(db, user_id)
                        if not user:
                            self.publish_error(ch, props, "User not found")
                            return

                        print("Old flags: ", user.flags_raw)
                        user = user.update_flags(permissions, permission_action)
                        print("New flags: ", user.flags_raw)
                        self.publish_response(
                            ch,
                            props,
                        )
                    except Exception as e:
                        self.publish_error(ch, props, "Error updating permissions for {}: {}".format(user_id, e))
            elif op == OPCode.QUARANTINE.value:
                # TODO: Implement
                self.publish_error(ch, props, "Not implemented")
            elif op == OPCode.RESET_API_KEY.value:
                user_id = d.get("user_id")
                with self.app.app_context():
                    user = libraries.User.get(db, user_id)
                    if not user:
                        self.publish_error(ch, props, "User not found")
                        return
                    try:
                        user.reset_api_key()
                        self.publish_response(ch, props, "API Key has been reset for user {}".format(user.username))
                    except Exception as e:
                        self.publish_error(ch, props, "Error resetting API Key for {}: {}".format(user.username, str(e)))
            else:
                self.publish_error(ch, props, "Unknown OPCode {}".format(op))
        except json.JSONDecodeError:
            logger.warning("[RabbitMQ] Invalid JSON: %s", body.decode("utf8"))
            self.publish_error(ch, props, "Invalid JSON")

    def send_request(self, payload):
        corr_id = str(uuid.uuid4())
        self.queue[corr_id] = None
        with self.internal_lock:
            self.channel.basic_publish(
                exchange="",
                routing_key="rpc_bot_queue_development",
                properties=pika.BasicProperties(
                    reply_to=self.callback_queue,
                    correlation_id=corr_id,
                ),
                body=payload,
            )
        return corr_id

    def publish_reply(self, ch: channel.Channel, props: spec.BasicProperties, payload):
        """
        Replies to the API queue
        """
        print("publishing reply")
        ch.basic_publish(exchange="", routing_key=props.reply_to, properties=pika.BasicProperties(correlation_id=props.correlation_id), body=str(payload))

    def publish_error(self, ch: channel.Channel, props: spec.BasicProperties, e):
        """
        Publishes an error response to the API queue
        """
        print("publishing error")
        payload = {"op": -1, "d": {"error": True, "message": e}}
        self.publish_reply(ch, props, payload)

    def publish_response(self, ch: channel.Channel, props: spec.BasicProperties, msg=None):
        """
        Publishes a response to the API queue
        """
        print("publishing response")
        payload = {"op": OPCode.REPLY.value, "d": {"error": False, "message": msg}}
        self.publish_reply(ch, props, payload)

    async def get_response(self, corr_id):
        """Get the response from the queue."""
        start_time = time.time()
        while self.queue[corr_id] is None:
            await asyncio.sleep(0.1)
            now = time.time()
            # timeout after 5 seconds
            if now - start_time > 5:
                raise Exception("Timeout")
        msg = self.queue[corr_id]
        msg = msg.decode("utf-8")
        print(msg)
        data = ast.literal_eval(msg)
        op = data.get("op")
        d = data.get("d")
        rmsg = d.get("message")
        if op == OPCode.ERROR.value:
            raise Exception(rmsg)
        return rmsg

    async def publish_packet(self, op: OPCode, data: dict = {}):
        payload = {"op": op.value, "d": data}
        corr_id = self.send_request(json.dumps(payload))
        res = await self.get_response(corr_id)
        return res

    def publish_packet_sync(self, op: OPCode, data: dict = {}):
        payload = {"op": op.value, "d": data}
        corr_id = self.send_request(json.dumps(payload))
        print(corr_id)
