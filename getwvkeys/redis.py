"""
 This file is part of the GetWVKeys project (https://github.com/GetWVKeys/getwvkeys)
 Copyright (C) 2022-2024 Notaghost, Puyodead1 and GetWVKeys contributors 
 
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

import json

import redis

from getwvkeys import config, libraries
from getwvkeys.models.Shared import db
from getwvkeys.utils import OPCode


class Redis:
    def __init__(self, app, library: libraries.Library) -> None:
        self.app = app
        self.library = library
        self.redis = redis.Redis.from_url(config.REDIS_URI, decode_responses=True, encoding="utf8")
        self.p = self.redis.pubsub(ignore_subscribe_messages=True)
        self.p.subscribe(**{"api": self.redis_message_handler})
        self.redis_thread = self.p.run_in_thread(daemon=True)

    def publish_error(self, reply_address, e):
        payload = {"op": -1, "d": {"error": True, "message": e}}
        self.redis.publish(reply_address, json.dumps(payload))

    def publish_response(self, reply_address, msg=None):
        payload = {"op": OPCode.REPLY.value, "d": {"error": False, "message": msg}}
        self.redis.publish(reply_address, json.dumps(payload))

    def redis_message_handler(self, msg):
        try:
            data = json.loads(msg.get("data"))
            op = data.get("op")
            d = data.get("d")
            reply_to = data.get("reply_to")

            print("OPCode {}; d: {}".format(op, json.dumps(d)))

            if op == OPCode.DISABLE_USER.value:
                user_id = d.get("user_id")
                if not user_id:
                    self.publish_error(reply_to, "No user_id found in message")
                    return
                with self.app.app_context():
                    try:
                        libraries.User.disable_user(db, user_id)
                        self.publish_response(reply_to)
                    except Exception as e:
                        self.publish_error(reply_to, "Error disablng user {}: {}".format(user_id, e))
            elif op == OPCode.DISABLE_USER_BULK.value:
                user_ids = d.get("user_ids")
                if not user_ids:
                    self.publish_error(reply_to, "No user_ids found in message")
                    return
                with self.app.app_context():
                    try:
                        libraries.User.disable_users(db, user_ids)
                        self.publish_response(
                            reply_to,
                        )
                    except Exception as e:
                        self.publish_error(reply_to, "Error disablng users: {}".format(e))
            elif op == OPCode.ENABLE_USER.value:
                user_id = d.get("user_id")
                if not user_id:
                    self.publish_error(reply_to, "No user_id found in message")
                    return
                with self.app.app_context():
                    try:
                        libraries.User.enable_user(db, user_id)
                        self.publish_response(
                            reply_to,
                        )
                    except Exception as e:
                        self.publish_error(reply_to, "Error enabling user {}: {}".format(user_id, e))
            elif op == OPCode.KEY_COUNT.value:
                with self.app.app_context():
                    self.publish_response(reply_to, self.library.get_keycount())
            elif op == OPCode.USER_COUNT.value:
                with self.app.app_context():
                    self.publish_response(reply_to, libraries.User.get_user_count())
            elif op == OPCode.SEARCH.value:
                query = d.get("query")
                if not query:
                    self.publish_error(reply_to, "No query found in message")
                    return
                with self.app.app_context():
                    try:
                        results = self.library.search(query)
                        results = self.library.search_res_to_dict(query, results)
                        self.publish_response(reply_to, results)
                    except Exception as e:
                        self.publish_error(reply_to, "Error searching: {}".format(e))
            elif op == OPCode.UPDATE_PERMISSIONS.value:
                user_id = d.get("user_id")
                permissions = d.get("permissions")
                permission_action = d.get("permission_action")
                if not user_id or not permissions:
                    self.publish_error(reply_to, "No user_id or permissions found in message")
                    return
                with self.app.app_context():
                    try:
                        user = libraries.User.get(db, user_id)
                        if not user:
                            self.publish_error(reply_to, "User not found")
                            return

                        print("Old flags: ", user.flags_raw)
                        user = user.update_flags(permissions, permission_action)
                        print("New flags: ", user.flags_raw)
                        self.publish_response(
                            reply_to,
                        )
                    except Exception as e:
                        self.publish_error(reply_to, "Error updating permissions for {}: {}".format(user_id, e))
            elif op == OPCode.QUARANTINE.value:
                # TODO: Implement
                self.publish_error(reply_to, "Not implemented")
            elif op == OPCode.RESET_API_KEY.value:
                user_id = d.get("user_id")
                with self.app.app_context():
                    user = libraries.User.get(db, user_id)
                    if not user:
                        self.publish_error(reply_to, "User not found")
                        return
                    try:
                        user.reset_api_key()
                        self.publish_response(reply_to, "API Key has been reset for user {}".format(user.username))
                    except Exception as e:
                        self.publish_error(reply_to, "Error resetting API Key for {}: {}".format(user.username, str(e)))
            else:
                self.publish_error(reply_to, "Unknown OPCode {}".format(op))
        except json.JSONDecodeError:
            self.publish_error(reply_to, "Invalid JSON")
