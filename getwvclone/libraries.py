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
from flask_sqlalchemy import SQLAlchemy
from werkzeug.exceptions import BadRequest, Forbidden, NotFound

from getwvclone import config
from getwvclone.models.CDM import CDM as CDMModel
from getwvclone.models.Key import Key as KeyModel
from getwvclone.models.User import User as UserModel
from getwvclone.utils import (
    Bitfield,
    CachedKey,
    FlagAction,
    UserFlags,
    extract_kid_from_pssh,
)

logger = logging.getLogger("getwvkeys")

common_privacy_cert = (
    "CAUSxwUKwQIIAxIQFwW5F8wSBIaLBjM6L3cqjBiCtIKSBSKOAjCCAQoCggEBAJntWzsyfateJO/DtiqVtZhSCtW8y"
    "zdQPgZFuBTYdrjfQFEEQa2M462xG7iMTnJaXkqeB5UpHVhYQCOn4a8OOKkSeTkwCGELbxWMh4x+Ib/7/up34QGeHl"
    "eB6KRfRiY9FOYOgFioYHrc4E+shFexN6jWfM3rM3BdmDoh+07svUoQykdJDKR+ql1DghjduvHK3jOS8T1v+2RC/TH"
    "hv0CwxgTRxLpMlSCkv5fuvWCSmvzu9Vu69WTi0Ods18Vcc6CCuZYSC4NZ7c4kcHCCaA1vZ8bYLErF8xNEkKdO7Dev"
    "Sy8BDFnoKEPiWC8La59dsPxebt9k+9MItHEbzxJQAZyfWgkCAwEAAToUbGljZW5zZS53aWRldmluZS5jb20SgAOuN"
    "HMUtag1KX8nE4j7e7jLUnfSSYI83dHaMLkzOVEes8y96gS5RLknwSE0bv296snUE5F+bsF2oQQ4RgpQO8GVK5uk5M"
    "4PxL/CCpgIqq9L/NGcHc/N9XTMrCjRtBBBbPneiAQwHL2zNMr80NQJeEI6ZC5UYT3wr8+WykqSSdhV5Cs6cD7xdn9"
    "qm9Nta/gr52u/DLpP3lnSq8x2/rZCR7hcQx+8pSJmthn8NpeVQ/ypy727+voOGlXnVaPHvOZV+WRvWCq5z3CqCLl5"
    "+Gf2Ogsrf9s2LFvE7NVV2FvKqcWTw4PIV9Sdqrd+QLeFHd/SSZiAjjWyWOddeOrAyhb3BHMEwg2T7eTo/xxvF+YkP"
    "j89qPwXCYcOxF+6gjomPwzvofcJOxkJkoMmMzcFBDopvab5tDQsyN9UPLGhGC98X/8z8QSQ+spbJTYLdgFenFoGq4"
    "7gLwDS6NWYYQSqzE3Udf2W7pzk4ybyG4PHBYV3s4cyzdq8amvtE/sNSdOKReuHpfQ="
)


class Library:
    def __init__(self, db: SQLAlchemy):
        self.db = db

    store_request = {}

    def cache_keys(self, cached_keys: list[CachedKey]):
        for cached_key in cached_keys:
            self.cache_key(cached_key)

    def cache_key(self, cached_key: CachedKey):
        k = KeyModel(kid=cached_key.kid, added_at=cached_key.added_at, added_by=cached_key.added_by, license_url=cached_key.license_url, key_=cached_key.key)
        self.db.session.merge(k)
        self.db.session.commit()

    def get_keycount(self) -> int:
        return KeyModel().query.count()

    def search(self, query: str) -> list:
        if query.startswith("AAAA"):
            # Try to parse the query as a PSSH and extract a KID
            try:
                query = extract_kid_from_pssh(query)
            except Exception as e:
                logger.exception(e)
                raise e
        if "-" in query:
            query = query.replace("-", "")
        return KeyModel.query.filter_by(kid=query).all()

    def search_res_to_dict(self, kid: str, keys: list[KeyModel]) -> dict:
        """
        Converts a list of Keys from search method to a list of dicts
        """
        results = {"kid": kid, "keys": list()}
        for key in keys:
            license_url = key.license_url
            if license_url:
                s = urlsplit(key.license_url)
                license_url = "{}://{}".format(s.scheme, s.netloc)
            results["keys"].append(
                {
                    "added_at": key.added_at,
                    # We shouldnt return the license url as that could have sensitive information it in still
                    "license_url": license_url,
                    "key": key.key_,
                }
            )
        return results

    def cdm_selector(self, code: str) -> dict:
        cdm = CDMModel.query.filter_by(code=code).first()
        if not cdm:
            raise NotFound("CDM not found")
        return cdm.to_json()

    def update_cdm(self, client_id_blob, device_private_key, uploaded_by) -> str:
        from getwvclone.pywidevine.cdm.formats import wv_proto2_pb2

        def get_blob_id(blob):
            blob_ = base64.b64decode(blob)
            ci = wv_proto2_pb2.ClientIdentification()
            ci.ParseFromString(blob_)
            return str(ci.ClientInfo[5]).split("Value: ")[1].replace("\n", "").replace('"', "")

        code = get_blob_id(client_id_blob)
        cdm = CDMModel(client_id_blob_filename=client_id_blob, device_private_key=device_private_key, code=code, uploaded_by=uploaded_by)
        self.db.session.add(cdm)
        self.db.session.commit()
        return code

    def add_keys(keys: list, user_id: str):
        cached_keys = list()

        for entry in keys:
            (added_at, licese_url, key) = (entry.get("time", int(time.time())), entry.get("license_url", None), entry.get("key"))
            (kid, _) = key.split(":")
            cached_keys.append(CachedKey(kid, added_at, user_id, licese_url, key))

        Library.cache_keys(cached_keys)
        return jsonify({"error": False, "message": "Added {} keys".format(len(keys))}), 201


class Pywidevine:
    def __init__(
        self,
        library: Library,
        user_id,
        # TODO: we really shouldn't do this, but vinetrimmer doesn't send license urls without modifications
        license_url="VINETRIMMER",
        pssh=None,
        proxy={},
        headers={},
        buildinfo=None,
        cache=False,
        response=None,
        challenge=False,
        server_certificate=None,
        session_id=None,
        disable_privacy=False,
    ):
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
        self.server_certificate = server_certificate
        self.proxy = proxy
        if isinstance(self.proxy, str):
            try:
                self.proxy = json.loads(self.proxy)
            except json.JSONDecodeError:
                self.proxy = {}
        self.store_request = {}
        self.session_id = session_id

        # extract KID from pssh
        if self.pssh:
            try:
                self.kid = extract_kid_from_pssh(self.pssh)
            except Exception as e:
                logger.exception(e)
                raise e

    def _cache_keys(self, vt=False):
        self.library.cache_keys(self.content_keys)

        # return a list of dicts containing kid and key, this is what vinetrimmer expects
        if vt:
            results = list()
            for entry in self.content_keys:
                k = entry.key.split(":")
                results.append(
                    {
                        "kid": k[0],
                        "key": k[1],
                    }
                )
            return results

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
            result = self.library.search(self.kid)
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
        if self.server_certificate:
            wvdecrypt.set_server_certificate(self.server_certificate)
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
            results = self.library.search_res_to_dict(self.kid, cached)
            resp = jsonify(results)
            resp.headers["X-Cached"] = True
            return resp
        if self.response is None:
            from getwvclone.pywidevine.cdm import deviceconfig

            wvdecrypt = WvDecrypt(self.pssh, deviceconfig.DeviceConfig(library, self.buildinfo))
            if self.server_certificate:
                wvdecrypt.set_server_certificate(self.server_certificate)
            challenge = wvdecrypt.create_challenge()
            if len(Library.store_request) > 60:
                self.store_request.popitem()
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

    def vinetrimmer(self, library: Library):
        # TODO: implement cache
        # if self.cache:
        #    return self.library.search(self.pssh)
        if self.response is None:
            from getwvclone.pywidevine.cdm import deviceconfig

            wvdecrypt = WvDecrypt(self.pssh, deviceconfig.DeviceConfig(library, self.buildinfo))
            challenge = wvdecrypt.create_challenge()
            if len(Library.store_request) > 60:
                self.store_request.popitem()
            self.session_id = wvdecrypt.session.hex()
            Library.store_request[self.session_id] = wvdecrypt

            res = base64.b64encode(challenge).decode()
            return {"challenge": res, "session_id": self.session_id}
        else:
            if self.session_id not in Library.store_request:
                raise BadRequest("PSSH CHALLENGE WAS NOT GENERATED FIRST")
            wvdecrypt = Library.store_request[self.session_id]
            wvdecrypt.decrypt_license(self.response)
            for _, y in enumerate(wvdecrypt.get_content_key()):
                (kid, _) = y.split(":")
                self.content_keys.append(CachedKey(kid, self.time, self.user_id, self.license_url, y))
            keys = self._cache_keys(vt=True)
            return {
                "keys": keys,
            }


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
    def __init__(self, db: SQLAlchemy, user: UserModel):
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

    def get_user_cdms(self):
        cdms = CDMModel.query.filter_by(uploaded_by=self.id).all()
        return [x.code for x in cdms]

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
        return User(self.db, self.user_model)

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
        return User(self.db, self.user_model)

    @staticmethod
    def get(db: SQLAlchemy, user_id: str):
        user = UserModel.query.filter_by(id=user_id).first()
        if not user:
            return None

        return User(db, user)

    @staticmethod
    def create(db: SQLAlchemy, userinfo: dict):
        api_key = secrets.token_hex(32)
        user = UserModel(
            id=userinfo.get("id"),
            username=userinfo.get("username"),
            discriminator=userinfo.get("discriminator"),
            avatar=userinfo.get("avatar"),
            public_flags=userinfo.get("public_flags"),
            api_key=api_key,
        )
        db.session.add(user)
        db.session.commit()

    @staticmethod
    def update(db: SQLAlchemy, userinfo: dict):
        user = UserModel.query.filter_by(id=userinfo.get("id")).first()
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
        bot_key = base64.b64encode("{}:{}".format(config.OAUTH2_CLIENT_ID, config.OAUTH2_CLIENT_SECRET).encode()).decode("utf8")
        return api_key == bot_key

    @staticmethod
    def get_user_by_api_key(db: SQLAlchemy, api_key):
        user = UserModel.query.filter_by(api_key=api_key).first()
        if not user:
            return None

        return User(db, user)

    def check_status(self):
        if self.flags.has(UserFlags.SUSPENDED) == 1:
            raise Forbidden("Your account has been suspended.")

    @staticmethod
    def is_api_key_valid(db: SQLAlchemy, api_key: str):
        # allow the bot to pass
        if User.is_api_key_bot(api_key):
            return True

        user = User.get_user_by_api_key(db, api_key)
        if not user:
            return False

        # if the user is suspended, throw forbidden
        user.check_status()

        return True

    @staticmethod
    def disable_user(db: SQLAlchemy, user_id: str):
        user = UserModel.query.filter_by(id=user_id).first()
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
                User.disable_user(db, user_id)
            except NotFound:
                continue

    @staticmethod
    def enable_user(db: SQLAlchemy, user_id):
        user = UserModel.query.filter_by(id=user_id).first()
        if not user:
            raise NotFound("User not found")
        flags = Bitfield(user.flags)
        flags.remove(UserFlags.SUSPENDED)
        user.flags = flags.bits
        db.session.commit()

    @staticmethod
    def get_user_count():
        return UserModel.query.count()
