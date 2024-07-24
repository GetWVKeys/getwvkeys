import base64
import logging
import secrets
from typing import Union

import requests
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from werkzeug.exceptions import BadRequest, Forbidden, NotFound

from getwvkeys import config
from getwvkeys.models.APIKey import APIKey as APIKeyModel
from getwvkeys.models.Device import Device
from getwvkeys.models.User import User
from getwvkeys.utils import Bitfield, FlagAction, UserFlags

logger = logging.getLogger("getwvkeys")


class FlaskUser(UserMixin):
    def __init__(self, db: SQLAlchemy, user: User):
        self.db = db
        self.id = user.id
        self.username = user.username
        self.discriminator = user.discriminator
        self.avatar = user.avatar
        self.public_flags = user.public_flags
        self.api_key = user.api_key
        self.flags_raw = user.flags
        self.flags = Bitfield(user.flags)
        self.user_model = user

    def get_user_devices(self):
        return [{"code": x.code, "info": x.info} for x in self.user_model.devices]

    def patch(self, data):
        disallowed_keys = ["id", "username", "discriminator", "avatar", "public_flags", "api_key"]

        for key, value in data.items():
            # Skip attributes that cant be changed
            if key in disallowed_keys:
                logger.warning("{} cannot be updated".format(key))
                continue
            # change attribute
            setattr(self.user_model, key, value)
        # save changes
        self.db.session.commit()
        # get a new user object
        return FlaskUser(self.db, self.user_model)

    def to_json(self, api_key=False):
        return {
            "id": self.id,
            "username": self.username,
            "discriminator": self.discriminator,
            "avatar": self.avatar,
            "public_flags": self.public_flags,
            "api_key": self.api_key if api_key else None,
            "flags": self.flags_raw,
        }

    def update_flags(self, flags: Union[int, Bitfield], action: FlagAction):
        # get bits from bitfield if it is one
        if isinstance(flags, Bitfield):
            flags = flags.bits

        if action == FlagAction.ADD.value:
            self.user_model.flags = self.flags.add(flags)
        elif action == FlagAction.REMOVE.value:
            self.user_model.flags = self.flags.remove(flags)
        else:
            raise BadRequest("Unknown flag action")

        self.db.session.commit()
        return FlaskUser(self.db, self.user_model)

    def reset_api_key(self):
        api_key = secrets.token_hex(32)
        self.user_model.api_key = api_key

        # check if we already have the key recorded in the history, if not (ex: accounts created before implementation), add it
        a = APIKeyModel.query.filter_by(user_id=self.user_model.id, api_key=api_key)
        if not a:
            history_entry = APIKeyModel(user_id=self.user_model.id, api_key=api_key)
            self.db.session.add(history_entry)

        self.db.session.commit()

    def delete_device(self, code) -> str:
        # Start a new session
        session = self.db.session

        # Query the device by code
        device = session.query(Device).filter_by(code=code).first()
        if not device:
            raise NotFound("Device not found")

        # Check if the device is associated with the user
        if device in self.user_model.devices:
            association_query = text("DELETE FROM user_device WHERE user_id = :user_id AND device_code = :device_code")
            session.execute(association_query, {"user_id": self.user_model.id, "device_code": device.code})
            session.commit()

            # Check if the device is still associated with any other users
            count_query = text("SELECT COUNT(*) FROM user_device WHERE device_code = :device_code")
            device_users_count = session.execute(count_query, {"device_code": device.code}).scalar()

            if device_users_count == 0:
                # If no other users are associated, delete the device
                session.delete(device)
                session.commit()
                return "Device deleted"
            else:
                return "Device unlinked"
        else:
            raise NotFound("You do not have this device associated with your profile")

    @staticmethod
    def get(db: SQLAlchemy, user_id: str):
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return None

        return FlaskUser(db, user)

    @staticmethod
    def create(db: SQLAlchemy, userinfo: dict):
        api_key = secrets.token_hex(32)
        user = User(
            id=userinfo.get("id"),
            username=userinfo.get("username"),
            discriminator=userinfo.get("discriminator"),
            avatar=userinfo.get("avatar"),
            public_flags=userinfo.get("public_flags"),
            api_key=api_key,
        )
        history_entry = APIKeyModel(user_id=user.id, api_key=api_key)
        db.session.add(history_entry)
        db.session.add(user)
        db.session.commit()

    @staticmethod
    def update(db: SQLAlchemy, userinfo: dict):
        user = User.query.filter_by(id=userinfo.get("id")).first()
        if not user:
            return None

        user.username = userinfo.get("username")
        user.discriminator = userinfo.get("discriminator")
        user.avatar = userinfo.get("avatar")
        user.public_flags = userinfo.get("public_flags")
        db.session.commit()

    @staticmethod
    def user_is_in_guild(token):
        url = "https://discord.com/api/users/@me/guilds"
        headers = {"Authorization": f"Bearer {token}"}
        r = requests.get(url, headers=headers)
        if not r.ok:
            raise Exception(f"Failed to get user guilds: [{r.status_code}] {r.text}")
        guilds = r.json()
        is_in_guild = any(guild.get("id") == config.GUILD_ID for guild in guilds)
        return is_in_guild

    @staticmethod
    def user_is_verified(token):
        url = f"https://discord.com/api/users/@me/guilds/{config.GUILD_ID}/member"
        headers = {
            "Authorization": f"Bearer {token}",
        }
        r = requests.get(url, headers=headers)
        if not r.ok:
            raise Exception(f"Failed to get guild member: [{r.status_code}] {r.text}")
        data = r.json()
        return any(role == config.VERIFIED_ROLE_ID for role in data.get("roles"))

    @staticmethod
    def is_api_key_bot(api_key):
        """checks if the api key is from the bot"""
        bot_key = base64.b64encode(
            "{}:{}".format(config.OAUTH2_CLIENT_ID, config.OAUTH2_CLIENT_SECRET).encode()
        ).decode("utf8")
        return api_key == bot_key

    @staticmethod
    def get_user_by_api_key(db: SQLAlchemy, api_key):
        user = User.query.filter_by(api_key=api_key).first()
        if not user:
            return None

        return FlaskUser(db, user)

    def is_blacklist_exempt(self):
        return self.flags.has(UserFlags.BLACKLIST_EXEMPT)

    def check_status(self, ignore_suspended=False):
        if self.flags.has(UserFlags.SUSPENDED) == 1 and not ignore_suspended:
            raise Forbidden("Your account has been suspended.")

    def has_device(self, device_code: str):
        return any(device.code == device_code for device in self.user_model.devices)

    @staticmethod
    def is_api_key_valid(db: SQLAlchemy, api_key: str):
        # allow the bot to pass
        if FlaskUser.is_api_key_bot(api_key):
            return True

        user = FlaskUser.get_user_by_api_key(db, api_key)
        if not user:
            return False

        # if the user is suspended, throw forbidden
        user.check_status()

        return True

    @staticmethod
    def disable_user(db: SQLAlchemy, user_id: str):
        user = User.query.filter_by(id=user_id).first()
        if not user:
            raise NotFound("User not found")
        flags = Bitfield(user.flags)
        flags.add(UserFlags.SUSPENDED)
        user.flags = flags.bits
        db.session.commit()

    @staticmethod
    def disable_users(db: SQLAlchemy, user_ids: list):
        print("Request to disable {} users: {}".format(len(user_ids), ", ".join([str(x) for x in user_ids])))
        if len(user_ids) == 0:
            raise BadRequest("No data to update or update is not allowed")

        for user_id in user_ids:
            try:
                FlaskUser.disable_user(db, user_id)
            except NotFound:
                continue

    @staticmethod
    def enable_user(db: SQLAlchemy, user_id):
        user = User.query.filter_by(id=user_id).first()
        if not user:
            raise NotFound("User not found")
        flags = Bitfield(user.flags)
        flags.remove(UserFlags.SUSPENDED)
        user.flags = flags.bits
        db.session.commit()

    @staticmethod
    def get_user_count():
        return User.query.count()
