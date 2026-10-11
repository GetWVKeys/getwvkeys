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
import logging
import time
from concurrent.futures import ThreadPoolExecutor

import redis
from werkzeug.exceptions import NotFound

from getwvkeys import config, libraries
from getwvkeys.models.Shared import db
from getwvkeys.user import FlaskUser
from getwvkeys.utils import OPCode

logger = logging.getLogger("getwvkeys")


# ops that don't modify anything, these can be handled in parallel
READ_OPS = {OPCode.KEY_COUNT.value, OPCode.USER_COUNT.value, OPCode.SEARCH.value}


class IPCError(Exception):
    """An error whose message is sent back to the requester as is"""


def _require(d: dict, key: str):
    value = d.get(key)
    if not value:
        raise IPCError("No {} found in message".format(key))
    return value


class Redis:
    def __init__(self, app, library: libraries.Library) -> None:
        self.app = app
        self.library = library
        self.handlers = {
            OPCode.DISABLE_USER.value: self.disable_user,
            OPCode.DISABLE_USER_BULK.value: self.disable_users,
            OPCode.ENABLE_USER.value: self.enable_user,
            OPCode.KEY_COUNT.value: self.key_count,
            OPCode.USER_COUNT.value: self.user_count,
            OPCode.SEARCH.value: self.search,
            OPCode.UPDATE_PERMISSIONS.value: self.update_permissions,
            OPCode.QUARANTINE.value: self.quarantine,
            OPCode.RESET_API_KEY.value: self.reset_api_key,
        }
        # requests are handled off the pubsub thread so a slow request doesn't block the others.
        # writes stay on a single thread so they're applied in the order they were sent (ex: disable then enable)
        self.read_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="redis-ipc-read")
        self.write_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="redis-ipc-write")
        self.redis = redis.Redis.from_url(config.REDIS_URI, decode_responses=True, encoding="utf8")
        self.p = self.redis.pubsub(ignore_subscribe_messages=True)
        self.p.subscribe(**{"api": self.redis_message_handler})
        self.redis_thread = self.p.run_in_thread(daemon=True, exception_handler=self.pubsub_exception_handler)

    def pubsub_exception_handler(self, e, pubsub, thread):
        # without a handler, any exception kills the pubsub thread and IPC stops responding
        logger.exception("Error in redis pubsub thread", exc_info=e)
        time.sleep(1)

    def publish_error(self, reply_address, e):
        payload = {"op": -1, "d": {"error": True, "message": e}}
        self.redis.publish(reply_address, json.dumps(payload))

    def publish_response(self, reply_address, msg=None):
        payload = {"op": OPCode.REPLY.value, "d": {"error": False, "message": msg}}
        self.redis.publish(reply_address, json.dumps(payload))

    def redis_message_handler(self, msg):
        try:
            op = json.loads(msg.get("data")).get("op")
        except Exception:
            op = None
        executor = self.read_executor if op in READ_OPS else self.write_executor
        executor.submit(self.handle_message, msg)

    def handle_message(self, msg):
        # exceptions raised in an executor are stored on the discarded future, so log them here instead
        try:
            self._handle_message(msg)
        except Exception:
            logger.exception("Unhandled error processing IPC message")

    def _handle_message(self, msg):
        try:
            data = json.loads(msg.get("data"))
        except (json.JSONDecodeError, TypeError):
            logger.warning("Received invalid JSON over IPC: {}".format(msg.get("data")))
            return
        if not isinstance(data, dict) or not data.get("reply_to"):
            # there is no reply address, so there's nobody to send an error to
            logger.warning("Received IPC message without a reply address: {}".format(data))
            return

        op = data.get("op")
        d = data.get("d") or {}
        reply_to = data.get("reply_to")
        logger.debug("OPCode {}; d: {}".format(op, json.dumps(d)))

        handler = self.handlers.get(op)
        if handler is None:
            self.publish_error(reply_to, "Unknown OPCode {}".format(op))
            return

        try:
            with self.app.app_context():
                self.publish_response(reply_to, handler(d))
        except IPCError as e:
            self.publish_error(reply_to, str(e))
        except Exception as e:
            logger.exception("Error handling OPCode {}".format(OPCode(op).name))
            self.publish_error(reply_to, "Error handling {}: {}".format(OPCode(op).name, e))

    def disable_user(self, d):
        user_id = _require(d, "user_id")
        try:
            FlaskUser.disable_user(db, user_id)
        except NotFound:
            # not an error, the discord user just never registered on the site
            return "User {} is not registered".format(user_id)

    def disable_users(self, d):
        return FlaskUser.disable_users(db, _require(d, "user_ids"))

    def enable_user(self, d):
        user_id = _require(d, "user_id")
        try:
            FlaskUser.enable_user(db, user_id)
        except NotFound:
            # not an error, the discord user just hasn't registered on the site yet
            return "User {} is not registered".format(user_id)

    def key_count(self, d):
        # the cache is kept up to date by the background task in main.py
        return self.library.get_cached_keycount()

    def user_count(self, d):
        return FlaskUser.get_user_count()

    def search(self, d):
        query = _require(d, "query")
        results = self.library.search(query)
        return self.library.search_res_to_dict(query, results)

    def update_permissions(self, d):
        user_id = d.get("user_id")
        permissions = d.get("permissions")
        permission_action = d.get("permission_action")
        if not user_id or not permissions:
            raise IPCError("No user_id or permissions found in message")

        user = FlaskUser.get(db, user_id)
        if not user:
            raise IPCError("User not found")

        old_flags = user.flags_raw
        user = user.update_flags(permissions, permission_action)
        logger.info("Updated flags for {}: {} -> {}".format(user_id, old_flags, user.flags_raw))

    def quarantine(self, d):
        # TODO: Implement
        raise IPCError("Not implemented")

    def reset_api_key(self, d):
        user = FlaskUser.get(db, _require(d, "user_id"))
        if not user:
            raise IPCError("User not found")
        user.reset_api_key()
        return "API Key has been reset for user {}".format(user.username)
