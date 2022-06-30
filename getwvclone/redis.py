import json

import redis

from getwvclone import config, libraries
from getwvclone.models.Shared import db
from getwvclone.utils import OPCode


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
                    libraries.User.disable_user(db, user_id)
                    self.publish_response(reply_to)
            elif op == OPCode.DISABLE_USER_BULK.value:
                user_ids = d.get("user_ids")
                if not user_ids:
                    self.publish_error(reply_to, "No user_ids found in message")
                    return
                with self.app.app_context():
                    libraries.User.disable_users(db, user_ids)
                    self.publish_response(
                        reply_to,
                    )
            elif op == OPCode.ENABLE_USER.value:
                user_id = d.get("user_id")
                if not user_id:
                    self.publish_error(reply_to, "No user_id found in message")
                    return
                with self.app.app_context():
                    libraries.User.enable_user(db, user_id)
                    self.publish_response(
                        reply_to,
                    )
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
                    results = self.library.search(query)
                    results = self.library.search_res_to_dict(query, results)
                    self.publish_response(reply_to, results)
            elif op == OPCode.UPDATE_PERMISSIONS.value:
                user_id = d.get("user_id")
                permissions = d.get("permissions")
                permission_action = d.get("permission_action")
                if not user_id or not permissions:
                    self.publish_error(reply_to, "No user_id or permissions found in message")
                    return
                with self.app.app_context():
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
            elif op == OPCode.QUARANTINE.value:
                # TODO: Implement
                self.publish_error(reply_to, "Not implemented")
            else:
                self.publish_error(reply_to, "Unknown OPCode {}".format(op))
        except json.JSONDecodeError:
            self.publish_error(reply_to, "Invalid JSON")
