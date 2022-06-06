import base64
import json
import logging
import secrets
import time
from typing import Union
from urllib.parse import urlsplit

import requests
import yaml
from flask import jsonify, render_template
from flask_login import UserMixin
from werkzeug.exceptions import BadRequest, Forbidden

from getwvclone import config
from getwvclone.utils import CachedKey, DatabaseManager, extract_kid_from_pssh

logger = logging.getLogger("getwvkeys")


class Library:
    def __init__(self, db: DatabaseManager):
        self.db = db

    store_request = {}

    def cache_keys(self, cached_keys: list[CachedKey]):
        for cached_key in cached_keys:
            self.cache_key(cached_key)

    def cache_key(self, cached_key: CachedKey):
        self.db.execute(
            "REPLACE INTO `keys_` (`kid`, `added_at`, `added_by`, `license_url`, `key_`) VALUES (?,?,?,?,?)",
            (cached_key.kid, cached_key.added_at, cached_key.added_by, cached_key.license_url, cached_key.key),
        )

    def get_keycount(self) -> int:
        self.db.execute("SELECT COUNT(*) FROM `keys_`")
        result = self.db.fetchone()[0]
        return result

    def search(self, query: str) -> list:
        if "-" in query:
            query = query.replace("-", "")
        self.db.execute("SELECT `kid`, `added_at`, `license_url`, `key_` FROM `keys_` WHERE `kid` = ?", (query,))
        results = self.db.fetchall()
        return results

    def search_res_to_dict(self, kid: str, data: list[tuple[str, int, Union[str, None], str]]):
        """
        Converts a list of tuples from search method to a list of dicts
        """
        results = {"kid": kid, "keys": list()}
        for result in data:
            license_url = result[2]
            if license_url:
                s = urlsplit(result[2])
                license_url = "{}://{}".format(s.scheme, s.netloc)
            results["keys"].append(
                {
                    "added_at": result[1],
                    # We shouldnt return the license url as that could have sensitive information it in still
                    "license_url": license_url,
                    "key": result[3],
                }
            )
        return results

    def cdm_selector(self, blob_id: str) -> dict[str, str]:
        self.db.execute("SELECT `client_id_blob_filename`,`device_private_key` FROM `cdms` WHERE `code` = ?", (blob_id,))
        data_result = self.db.fetchone()
        if not data_result:
            raise Exception("No CDM found matching the blob_id")
        data = {"session_id_type": "android", "security_level": "3", "client_id_blob_filename": data_result[0], "device_private_key": data_result[1]}
        return data

    def update_cdm(self, client_id_blob, device_private_key, uploaded_by) -> str:
        from getwvclone.pywidevine.cdm.formats import wv_proto2_pb2

        def get_blob_id(blob):
            blob_ = base64.b64decode(blob)
            ci = wv_proto2_pb2.ClientIdentification()
            ci.ParseFromString(blob_)
            return str(ci.ClientInfo[5]).split("Value: ")[1].replace("\n", "").replace('"', "")

        blob_id = get_blob_id(client_id_blob)
        self.db.execute(
            "INSERT IGNORE INTO `cdms` (`client_id_blob_filename`, `device_private_key`, `code`, `uploaded_by`) VALUES (?,?,?,?)", (client_id_blob, device_private_key, blob_id, uploaded_by)
        )
        return blob_id

    def dev_append(keys: list, access: str, user_id: str):
        if access not in config.APPENDERS:
            raise Exception("You are not allowed to add to database")

        cached_keys = list()

        for entry in keys:
            (added_at, licese_url, key) = (entry.get("time", int(time.time())), entry.get("license_url", None), entry.get("key"))
            (kid, _) = key.split(":")
            cached_keys.append(CachedKey(kid, added_at, user_id, licese_url, key))

        Library.cache_keys(cached_keys)
        return jsonify({"error": False, "message": "Added {} keys".format(len(keys))}), 201


class Pywidevine:
    def __init__(self, library: Library, proxy, license_url, pssh, headers, buildinfo, cache=False, response=None, challenge=False, user_id=None):
        self.library = library
        self.license_url = license_url
        self.pssh = pssh
        self.kid = None
        self.headers = headers
        self.buildinfo = buildinfo
        self.cache = cache
        self.time = int(time.time())
        self.content_keys: list[CachedKey] = list()
        self.challenge = challenge
        self.response = response
        self.user_id = user_id
        if isinstance(proxy, dict):
            self.proxy = proxy
        else:
            self.proxy = {}
        self.store_request = {}

        # extract KID from pssh
        try:
            self.kid = extract_kid_from_pssh(self.pssh)
            if isinstance(self.kid, list):
                self.kid = self.kid[0]
        except Exception as e:
            logger.exception(e)
            raise e

    def _cache_keys(self):
        self.library.cache_keys(self.content_keys)

        results = {"kid": self.kid, "license_url": self.license_url, "added_at": self.time, "keys": list()}
        for key in self.content_keys:
            # s = urlsplit(self.license_url)
            # license_url = "{}//{}".format(s.scheme, s.netloc)
            results["keys"].append(key.key)

        return results

    @staticmethod
    def yamldomagic(headers):
        try:
            return (
                {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (Ktesttemp, like Gecko) " "Chrome/90.0.4430.85 Safari/537.36"}
                if headers == ""
                else yaml.safe_load(headers)
            )
        except Exception as e:
            raise BadRequest("Wrong headers:\n" + str(e))

    @staticmethod
    def post_data(license_url, headers, challenge, proxy):
        r = requests.post(url=license_url, data=challenge, headers=headers, proxies=proxy, timeout=10, verify=False)
        if r.status_code != 200:
            raise Exception(f"Error {r.status_code}:\n" + r.text)

        return base64.b64encode(r.content)

    def main(self, library: Library, curl=False):
        # Cached
        if self.cache:
            result = self.library.search(self.pssh)
            cached = self.library.search_res_to_dict(self.kid, result)
            if cached:
                if not curl:
                    return render_template("cache.html", results=cached)
                else:
                    return jsonify(cached)

        # Headers
        try:
            self.headers = json.loads(self.headers)
        except (Exception,):
            self.headers = self.yamldomagic(self.headers)

        from getwvclone.pywidevine.cdm import deviceconfig

        wvdecrypt = WvDecrypt(self.pssh, deviceconfig.DeviceConfig(library, self.buildinfo))
        challenge = wvdecrypt.create_challenge()

        decode = self.post_data(self.license_url, self.headers, challenge, self.proxy)

        wvdecrypt.decrypt_license(decode)
        for _, y in enumerate(wvdecrypt.get_content_key()):
            (kid, _) = y.split(":")
            self.content_keys.append(CachedKey(kid, self.time, self.user_id, self.license_url, y))

        # caching
        data = self._cache_keys()
        if curl:
            return jsonify(data)
        return render_template("success.html", page_title="Success", results=data)

    def api(self, library: Library):
        if self.cache:
            cached = self.library.search(self.pssh)
            resp = jsonify(cached)
            resp.headers["X-Cached"] = True
            return resp
        if self.response is None:
            from getwvclone.pywidevine.cdm import deviceconfig

            wvdecrypt = WvDecrypt(self.pssh, deviceconfig.DeviceConfig(library, self.buildinfo))
            challenge = wvdecrypt.create_challenge()
            if len(Library.store_request) > 30:
                self.store_request = {}
            Library.store_request[self.pssh] = wvdecrypt

            res = base64.b64encode(challenge).decode()
            return res
        else:
            if self.pssh not in Library.store_request:
                raise BadRequest("PSSH CHALLENGE WAS NOT GENERATED FIRST")
            wvdecrypt = Library.store_request[self.pssh]
            wvdecrypt.decrypt_license(self.response)
            for _, y in enumerate(wvdecrypt.get_content_key()):
                (kid, _) = y.split(":")
                self.content_keys.append(CachedKey(kid, self.time, self.user_id, self.license_url, y))
            output = self._cache_keys()
            return output


class WvDecrypt:
    def __init__(self, pssh_b64, device):
        from getwvclone.pywidevine.cdm import cdm

        self.cdm = cdm.Cdm()
        self.session = self.cdm.open_session(pssh_b64, device)

    def create_challenge(self):
        challenge = self.cdm.get_license_request(self.session)
        return challenge

    def decrypt_license(self, license_b64):
        if self.cdm.provide_license(self.session, license_b64) == 1:
            raise ValueError

    def set_server_certificate(self, certificate_b64):
        if self.cdm.set_service_certificate(self.session, certificate_b64) == 1:
            raise ValueError

    def get_content_key(self):
        content_keys = []
        for key in self.cdm.get_keys(self.session):
            if key.type == "CONTENT":
                kid = key.kid.hex()
                key = key.key.hex()
                content_keys.append("{}:{}".format(kid, key))

        return content_keys

    def get_signing_key(self):
        for key in self.cdm.get_keys(self.session):
            if key.type == "SIGNING":
                kid = key.kid.hex()
                key = key.key.hex()

                signing_key = "{}:{}".format(kid, key)
                return signing_key


class User(UserMixin):
    def __init__(self, db: DatabaseManager, id, username, discriminator, avatar, public_flags, api_key, disabled, is_admin):
        self.db = db
        self.id = id
        self.username = username
        self.discriminator = discriminator
        self.avatar = avatar
        self.public_flags = public_flags
        self.api_key = api_key
        self.disabled = disabled
        self.is_admin = is_admin

    def get_user_cdms(self):
        cdms = []
        self.db.execute("SELECT code FROM `cdms` WHERE `uploaded_by` = ?", (self.id,))
        results = self.db.fetchall()

        for result in results:
            cdms.append(result[0])
        return cdms

    def patch(self, data):
        # loop keys in data dict and create a sql statement
        disallowed_keys = ["id", "username", "discriminator", "avatar", "public_flags", "api_key"]
        values = []
        sql = "UPDATE users SET "
        for key, value in data.items():
            if key.lower() in disallowed_keys:
                continue
            sql += f"{key} = ?, "
            values.append(value)
        if len(values) == 0:
            raise BadRequest("No data to update or update is not allowed")
        sql = sql[:-2]
        sql += f" WHERE id = {self.id}"

        self.db.execute(sql, values)

    def to_json(self, api_key=False):
        return {
            "id": self.id,
            "username": self.username,
            "discriminator": self.discriminator,
            "avatar": self.avatar,
            "public_flags": self.public_flags,
            "api_key": self.api_key if api_key else None,
            "disabled": self.disabled,
            "is_admin": self.is_admin,
        }

    @staticmethod
    def get(db: DatabaseManager, user_id):
        db.execute("SELECT * FROM `users` WHERE `id` = ?", (user_id,))
        user = db.fetchone()
        if not user:
            return None

        user = User(db, id=user[0], username=user[1], discriminator=user[2], avatar=user[3], public_flags=user[4], api_key=user[5], disabled=user[6], is_admin=user[7])
        return user

    @staticmethod
    def create(db: DatabaseManager, userinfo):
        api_key = secrets.token_hex(32)
        db.execute(
            "INSERT INTO `users` (`id`, `username`, `discriminator`, `avatar`, `public_flags`, `api_key`) VALUES (?, ?, ?, ?, ?, ?)",
            (userinfo.get("id"), userinfo.get("username"), userinfo.get("discriminator"), userinfo.get("avatar"), userinfo.get("public_flags"), api_key),
        )

    @staticmethod
    def update(db: DatabaseManager, userinfo):
        db.execute(
            "UPDATE `users` SET `username` = ?, `discriminator` = ?, `avatar` = ?, `public_flags` = ? WHERE `id` = ?",
            (userinfo.get("username"), userinfo.get("discriminator"), userinfo.get("avatar"), userinfo.get("public_flags"), userinfo.get("id")),
        )

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
        bot_key = base64.b64encode("{}:{}".format(config.OAUTH2_CLIENT_ID, config.OAUTH2_CLIENT_SECRET).encode()).decode("utf8")
        return api_key == bot_key

    @staticmethod
    def get_user_by_api_key(db: DatabaseManager, api_key):
        db.execute("SELECT * FROM `users` WHERE `api_key` = ?", (api_key,))
        user = db.fetchone()
        if not user:
            return None

        user = User(db, id=user[0], username=user[1], discriminator=user[2], avatar=user[3], public_flags=user[4], api_key=user[5], disabled=user[6], is_admin=user[7])
        return user

    @staticmethod
    def is_api_key_valid(db: DatabaseManager, api_key):
        # allow the bot to pass
        if User.is_api_key_bot(api_key):
            return True
        db.execute("SELECT `id`, `disabled`, `is_admin` FROM `users` WHERE `api_key` = ?", (api_key,))
        user = db.fetchone()
        if not user:
            return False

        disabled = user[1]
        role = user[2]  # TODO: Use role where fit

        # if the user is suspended, throw forbidden
        if disabled == 1:
            raise Forbidden("Your account has been suspended.")

        # if we require admin, and the user is not admin, throw forbidden
        # if require_admin and role == 0:
        #     raise Forbidden("You do not have permission to do this.")

        return True

    @staticmethod
    def disable_user(db: DatabaseManager, user_id):
        # update the user record to set disabled to 1
        db.execute("UPDATE `users` SET `disabled` = ? WHERE `id` = ?", (1, user_id))

    @staticmethod
    def disable_users(db: DatabaseManager, user_ids):
        print("Request to disable {} users: {}".format(len(user_ids), ", ".join([str(x) for x in user_ids])))
        if len(user_ids) == 0:
            raise BadRequest("No data to update or update is not allowed")
        a = ["`id` = ?"] * len(user_ids)
        sql = "UPDATE `users` SET `disabled` = ? WHERE " + " OR ".join(a)

        db.execute(sql, (1, *user_ids))

    @staticmethod
    def enable_user(db: DatabaseManager, user_id):
        # update the user record to set disabled to 0
        db.execute("UPDATE `users` SET `disabled` = ? WHERE `id` = ?", (0, user_id))

    @staticmethod
    def get_user_count(db: DatabaseManager):
        count = db.execute("SELECT COUNT(*) FROM `users`").fetchone()[0]
        return count
