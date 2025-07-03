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

import base64
import hashlib
import json
import logging
import secrets
import time
import uuid
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

import requests
import yaml
from flask import jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from pyplayready.cdm import Cdm as PlayreadyCdm
from pyplayready.device import Device as PlayreadyDevice
from pyplayready.exceptions import (
    InvalidInitData,
    InvalidLicense,
    InvalidSession,
    TooManySessions,
)
from pyplayready.system.pssh import PSSH as PlayreadyPSSH
from requests.exceptions import ProxyError
from sqlalchemy import func
from werkzeug.exceptions import (
    BadRequest,
    InternalServerError,
    NotFound,
    NotImplemented,
)

from getwvkeys import config
from getwvkeys.models.APIKey import APIKey as APIKeyModel
from getwvkeys.models.CDM import CDM as CDMModel
from getwvkeys.models.Key import Key as KeyModel
from getwvkeys.models.PRD import PRD
from getwvkeys.models.User import User as UserModel
from getwvkeys.pywidevine.cdm import deviceconfig
from getwvkeys.utils import (
    CachedKey,
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

wv_sessions = dict()
pr_sessions: dict[str, PlayreadyCdm] = dict()


def get_random_cdm():
    if len(config.DEFAULT_CDMS) == 0:
        raise Exception("No CDMS configured")
    return secrets.choice(config.DEFAULT_CDMS)


def get_random_prd():
    if len(config.DEFAULT_PRDS) == 0:
        raise Exception("No PRDs configured")
    return secrets.choice(config.DEFAULT_PRDS)


def is_custom_buildinfo(buildinfo):
    return next((True for entry in config.EXTERNAL_API_BUILD_INFOS if entry["buildinfo"] == buildinfo), False)


def is_user_prd(device: str):
    return next((False for entry in config.DEFAULT_PRDS if entry["code"] == device), False)


class Library:
    def __init__(self, db: SQLAlchemy):
        self.db = db

    sessions = {}

    def cache_keys(self, cached_keys: list[CachedKey]):
        for cached_key in cached_keys:
            self.cache_key(cached_key)

    def cache_key(self, cached_key: CachedKey):
        # add key to the cache only if kid and key_ are not already in the cache
        if not KeyModel.query.filter_by(kid=cached_key.kid, key_=cached_key.key).first():
            k = KeyModel(
                kid=cached_key.kid,
                added_at=cached_key.added_at,
                added_by=cached_key.added_by,
                license_url=cached_key.license_url,
                key_=cached_key.key,
            )
            self.db.session.add(k)
            self.db.session.commit()

    def get_keycount(self) -> int:
        return self.db.session.query(func.count(KeyModel.kid)).scalar()
        # return KeyModel().query.count()

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
        from getwvkeys.pywidevine.cdm.formats import wv_proto2_pb2

        def get_blob_id(blob):
            blob_ = base64.b64decode(blob)
            ci = wv_proto2_pb2.ClientIdentification()
            ci.ParseFromString(blob_)
            return str(ci.ClientInfo[5]).split("Value: ")[1].replace("\n", "").replace('"', "")

        code = get_blob_id(client_id_blob)
        cdm = CDMModel(
            client_id_blob_filename=client_id_blob,
            device_private_key=device_private_key,
            code=code,
            uploaded_by=uploaded_by,
        )
        self.db.session.add(cdm)
        self.db.session.commit()
        return code

    def upload_prd(self, prd_data: str, user_id: str) -> str:
        user = UserModel.query.filter_by(id=user_id).first()
        if not user:
            raise NotFound("User not found")

        # used to check if the prd is valid
        try:
            prd = PlayreadyDevice.loads(prd_data)
        except Exception as e:
            logger.exception(e)
            raise BadRequest(f"Invalid PRD")

        prd_raw = base64.b64decode(prd_data)

        # calculate the hash of the prd
        prd_hash = hashlib.sha256(prd_raw).hexdigest()

        # get device
        device = PRD.query.filter_by(hash=prd_hash).first()
        if not device:
            device = PRD(uploaded_by=user.id, prd=prd_data, hash=prd_hash)
            self.db.session.add(device)
            user.prds.append(device)
            self.db.session.commit()
        elif device not in user.prds:
            # add device to user if its not already there
            user.prds.append(device)
            self.db.session.commit()
        else:
            raise BadRequest("PRD already uploaded, please use the existing hash found on the profile page.")

        return device.hash

    def add_keys(self, keys: list, user_id: str):
        cached_keys = list()

        for entry in keys:
            (added_at, licese_url, key) = (
                entry.get("time", int(time.time())),
                entry.get("license_url", "MANUAL ENTRY"),
                entry.get("key"),
            )
            (kid, _) = key.split(":")
            cached_keys.append(CachedKey(kid, added_at, user_id, licese_url, key))

        self.cache_keys(cached_keys)
        return jsonify({"error": False, "message": "Added {} keys".format(len(keys))}), 201

    def get_prd_by_hash(self, hash: str):
        return PRD.query.filter_by(hash=hash).first()


class BaseService:
    def __init__(self, library: Library):
        self.library = library

    @staticmethod
    def yamldomagic(headers):
        try:
            return (
                {
                    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (Ktesttemp, like Gecko) "
                    "Chrome/90.0.4430.85 Safari/537.36"
                }
                if headers == ""
                else yaml.safe_load(headers)
            )
        except Exception as e:
            raise BadRequest(f"Wrong headers: {str(e)}")


class MainService:
    @staticmethod
    def main(**kwargs):
        library = kwargs.pop("library")
        buildinfo = kwargs.pop("buildinfo")

        d = library.get_prd_by_hash(buildinfo)
        if d:
            print("Detected a Playready device")
            to_pop = [
                "server_certificate",
                "disable_privacy",
            ]
            for key in to_pop:
                kwargs.pop(key, None)
            return Playready(library=library, device_hash=buildinfo, **kwargs)

        to_pop = [
            "downgrade",
        ]
        for key in to_pop:
            kwargs.pop(key, None)
        return Pywidevine(library=library, buildinfo=buildinfo, **kwargs)


class Pywidevine(BaseService):
    def __init__(
        self,
        library: Library,
        user_id,
        buildinfo,
        # TODO: we really shouldn't do this, but vinetrimmer doesn't send license urls without modifications
        license_url="VINETRIMMER",
        pssh=None,
        proxy={},
        headers={},
        force=False,
        response=None,
        challenge=False,
        server_certificate=None,
        session_id=None,
        disable_privacy=False,
        is_web=False,
    ):
        super().__init__(library)
        self.library = library
        self.license_url = license_url
        self.pssh = pssh
        self.kid = None
        self.headers = headers
        self.buildinfo = buildinfo
        self.force = force
        self.time = int(time.time())
        self.content_keys: list[CachedKey] = list()
        self.challenge = challenge
        self.response = response
        self.user_id = user_id
        self.server_certificate = server_certificate
        self.proxy = proxy
        if self.proxy and isinstance(self.proxy, str):
            self.proxy = {"http": self.proxy, "https": self.proxy}
        self.store_request = {}
        self.session_id = session_id
        self.is_web = is_web

        # extract KID from pssh
        if self.pssh:
            try:
                self.kid = extract_kid_from_pssh(self.pssh)
            except Exception as e:
                logger.exception(e)
                raise BadRequest(f"Failed to extract KID from PSSH: {e}")

    @staticmethod
    def post_data(license_url, headers, data, proxy):
        try:
            r = requests.post(url=license_url, data=data, headers=headers, proxies=proxy, timeout=10, verify=False)
            if r.status_code != 200:
                raise BadRequest(f"Failed to get license: {r.status_code} {r.reason}")

            return base64.b64encode(r.content).decode()
        except ProxyError as e:
            raise BadRequest(f"Proxy error: {e.args[0].reason}")
        except ConnectionError as e:
            raise BadRequest(f"Connection error: {e.args[0].reason}")

    def external_license(self, method, params, web=False):
        entry = next((entry for entry in config.EXTERNAL_API_BUILD_INFOS if entry["buildinfo"] == self.buildinfo), None)
        if not entry:
            raise BadRequest("Invalid buildinfo")
        api = entry["url"]
        payload = {"method": method, "params": params, "token": entry["token"]}
        r = requests.post(api, headers=self.headers, json=payload, proxies=self.proxy)
        if r.status_code != 200:
            if "message" in r.text:
                raise Exception(f"Error: {r.json()['message']}")
            raise Exception(f"Unknown Error: [{r.status_code}] {r.text}")
        if method == "GetChallenge":
            d = r.json()
            if entry["version"] == 2:
                challenge = d["message"]["challenge"]
                self.session_id = d["message"]["session_id"]
            else:
                challenge = d["challenge"]
                self.session_id = d["session_id"]
            if not web:
                return jsonify({"challenge": challenge, "session_id": self.session_id})
            return challenge
        elif method == "GetKeys":
            d = r.json()
            if entry["version"] == 2:
                keys = d["message"]["keys"]
            else:
                keys = d["keys"]
            for x in keys:
                kid = x["kid"]
                key = x["key"]
                self.content_keys.append(
                    CachedKey(kid, self.time, self.user_id, self.license_url, "{}:{}".format(kid, key))
                )
        elif method == "GetKeysX":
            raise NotImplemented()
        else:
            raise Exception("Unknown method")

    def run(self, curl=False):
        # Search for cached keys first
        if not self.force:
            result = self.library.search(self.pssh)
            if result and len(result) > 0:
                cached = self.library.search_res_to_dict(self.kid, result)
                if not curl and self.is_web:
                    return render_template("cache.html", results=cached)
                r = jsonify(cached)
                r.headers.add_header("X-Cache", "HIT")
                return r, 302

        if self.response is None:
            # Headers
            # TODO: better parsing
            try:
                self.headers = json.loads(self.headers)
            except (Exception,):
                self.headers = self.yamldomagic(self.headers)

            # if is_custom_buildinfo(self.buildinfo):
            #     if not self.server_certificate:
            #         try:
            #             self.server_certificate = self.post_data(
            #                 self.license_url, self.headers, base64.b64decode("CAQ="), self.proxy
            #             )
            #         except Exception as e:
            #             raise BadRequest(
            #                 f"Failed to retrieve server certificate: {e}. Please provide a server certificate manually."
            #             )
            #     params = {
            #         "init": self.pssh,
            #         "cert": self.server_certificate,
            #         "raw": False,
            #         "licensetype": "STREAMING",
            #         "device": "api",
            #     }
            #     return self.external_license("GetChallenge", params)

            # challenge generation
            wvdecrypt = WvDecrypt(self.pssh, deviceconfig.DeviceConfig(self.library, self.buildinfo))

            # set server certificate if provided
            if self.server_certificate:
                wvdecrypt.set_server_certificate(self.server_certificate)

            # get the challenge
            challenge = wvdecrypt.create_challenge()

            if curl or self.is_web:
                try:
                    license_response = self.post_data(self.license_url, self.headers, challenge, self.proxy)

                    wvdecrypt.decrypt_license(license_response)
                    for _, y in enumerate(wvdecrypt.get_content_key()):
                        (kid, _) = y.split(":")
                        self.content_keys.append(CachedKey(kid, self.time, self.user_id, self.license_url, y))

                    # caching
                    data = self._cache_keys()

                    wvdecrypt.close_session()

                    if curl:
                        return jsonify(data)

                    return render_template("success.html", page_title="Success", results=data)
                except Exception as e:
                    raise BadRequest(f"Failed to get license: {e}")
            else:
                if len(wv_sessions) > config.MAX_SESSIONS:
                    # remove the oldest session
                    wv_sessions.pop(next(iter(wv_sessions)))

                # store the session
                self.session_id = wvdecrypt.session.hex()
                wv_sessions[self.session_id] = wvdecrypt
                return jsonify({"challenge": base64.b64encode(challenge).decode(), "session_id": self.session_id})
        else:
            # if is_custom_buildinfo(self.buildinfo):
            #     params = {"cdmkeyresponse": self.response, "session_id": self.session_id}
            #     self.external_license("GetKeys", params=params)
            #     output = self._cache_keys()
            #     return jsonify(output)

            # get the session
            wvdecrypt: WvDecrypt = wv_sessions.get(self.session_id)
            if not wvdecrypt:
                raise BadRequest("Session not found, did you generate a challenge first?")

            # decrypt the license
            wvdecrypt.decrypt_license(self.response)

            for _, y in enumerate(wvdecrypt.get_content_key()):
                (kid, _) = y.split(":")
                self.content_keys.append(CachedKey(kid, self.time, self.user_id, self.license_url, y))

            # caching
            output = self._cache_keys()

            # close the session
            wvdecrypt.close_session()

            return jsonify(output)

    def vinetrimmer(self, library: Library):
        if self.response is None:
            wvdecrypt = WvDecrypt(self.pssh, deviceconfig.DeviceConfig(library, self.buildinfo))
            challenge = wvdecrypt.create_challenge()
            if len(wv_sessions) > config.MAX_SESSIONS:
                # remove the oldest session
                wv_sessions.pop(next(iter(wv_sessions)))
            self.session_id = wvdecrypt.session.hex()
            wv_sessions[self.session_id] = wvdecrypt

            res = base64.b64encode(challenge).decode()
            return {"challenge": res, "session_id": self.session_id}
        else:
            if self.session_id not in wv_sessions:
                raise BadRequest("Session not found, did you generate a challenge first?")
            wvdecrypt = wv_sessions[self.session_id]
            wvdecrypt.decrypt_license(self.response)
            for _, y in enumerate(wvdecrypt.get_content_key()):
                (kid, _) = y.split(":")
                self.content_keys.append(CachedKey(kid, self.time, self.user_id, self.license_url, y))
            keys = self._cache_keys(vt=True)
            # close the session
            wvdecrypt.close_session()
            return {"keys": keys, "session_id": self.session_id}

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

        results = {
            "kid": self.kid,
            "license_url": self.license_url,
            "added_at": self.time,
            "keys": list(),
            "session_id": self.session_id,
        }
        for key in self.content_keys:
            # s = urlsplit(self.license_url)
            # license_url = "{}//{}".format(s.scheme, s.netloc)
            results["keys"].append(key.key)

        return results


class Playready(BaseService):
    def __init__(
        self,
        library: Library,
        user_id,
        device_hash,
        # TODO: we really shouldn't do this, but vinetrimmer doesn't send license urls without modifications
        license_url="VINETRIMMER",
        pssh=None,
        proxy={},
        headers={},
        force=False,
        response=None,
        challenge=False,
        session_id=None,
        downgrade=False,
        is_web=False,
    ):
        super().__init__(library)
        self.library = library
        self.license_url = license_url
        self.pssh: PlayreadyPSSH = PlayreadyPSSH(pssh)
        self.kid = None
        self.headers = headers
        self.device = device_hash
        self.force = force
        self.time = int(time.time())
        self.content_keys: list[CachedKey] = list()
        self.license_request = challenge
        self.license_response = response
        self.user_id = user_id
        self.proxy = proxy
        if self.proxy and isinstance(self.proxy, str):
            self.proxy = {"http": self.proxy, "https": self.proxy}
        self.store_request = {}
        self.session_id = session_id
        self.downgrade = downgrade
        self.is_web = is_web

        if pssh:
            kids = [x.read_attributes()[0] for x in self.pssh.wrm_headers]
            kid = kids[0][0].value
            decoded_kid = base64.b64decode(kid)
            self.kid = str(uuid.UUID(bytes_le=decoded_kid))

    @staticmethod
    def post_data(license_url, headers, data, proxy):
        try:
            r = requests.post(
                url=license_url,
                data=data,
                headers=headers,
                proxies=proxy,
                timeout=10,
            )
            if r.status_code != 200:
                raise BadRequest(f"Failed to get license: {r.status_code} {r.reason}")

            try:
                ET.fromstring(r.text)
                return r.text
            except Exception:
                raise BadRequest(f"Invalid response: {r.text}")
        except ProxyError as e:
            raise BadRequest(f"Proxy error: {e.args[0].reason}")
        except ConnectionError as e:
            raise BadRequest(f"Connection error: {e.args[0].reason}")

    def external_license(self, method, params, web=False):
        entry = next((entry for entry in config.EXTERNAL_API_BUILD_INFOS if entry["buildinfo"] == self.buildinfo), None)
        if not entry:
            raise BadRequest("Invalid buildinfo")
        api = entry["url"]
        payload = {"method": method, "params": params, "token": entry["token"]}
        r = requests.post(api, headers=self.headers, json=payload, proxies=self.proxy)
        if r.status_code != 200:
            if "message" in r.text:
                raise Exception(f"Error: {r.json()['message']}")
            raise Exception(f"Unknown Error: [{r.status_code}] {r.text}")
        if method == "GetChallenge":
            d = r.json()
            if entry["version"] == 2:
                challenge = d["message"]["challenge"]
                self.session_id = d["message"]["session_id"]
            else:
                challenge = d["challenge"]
                self.session_id = d["session_id"]
            if not web:
                return jsonify({"challenge": challenge, "session_id": self.session_id})
            return challenge
        elif method == "GetKeys":
            d = r.json()
            if entry["version"] == 2:
                keys = d["message"]["keys"]
            else:
                keys = d["keys"]
            for x in keys:
                kid = x["kid"]
                key = x["key"]
                self.content_keys.append(
                    CachedKey(kid, self.time, self.user_id, self.license_url, "{}:{}".format(kid, key))
                )
        elif method == "GetKeysX":
            raise NotImplemented()
        else:
            raise Exception("Unknown method")

    def run(self, curl=False):
        # Search for cached keys first
        if not self.force and self.kid:
            result = self.library.search(self.kid)
            if result and len(result) > 0:
                cached = self.library.search_res_to_dict(self.kid, result)
                if not curl and self.is_web:
                    return render_template("cache.html", results=cached)
                r = jsonify(cached)
                r.headers.add_header("X-Cache", "HIT")
                return r, 302

        if self.license_response is None:
            # Headers
            # TODO: better parsing
            try:
                self.headers = json.loads(self.headers)
            except (Exception,):
                self.headers = self.yamldomagic(self.headers)

            # if is_custom_buildinfo(self.buildinfo):
            #     if not self.server_certificate:
            #         try:
            #             self.server_certificate = self.post_data(
            #                 self.license_url, self.headers, base64.b64decode("CAQ="), self.proxy
            #             )
            #         except Exception as e:
            #             raise BadRequest(
            #                 f"Failed to retrieve server certificate: {e}. Please provide a server certificate manually."
            #             )
            #     params = {
            #         "init": self.pssh,
            #         "cert": self.server_certificate,
            #         "raw": False,
            #         "licensetype": "STREAMING",
            #         "device": "api",
            #     }
            #     challenge = self.external_license("GetChallenge", params, web=True)

            #     # post challenge to license server
            #     license = self.post_data(self.license_url, self.headers, base64.b64decode(challenge), self.proxy)

            #     params = {"cdmkeyresponse": license, "session_id": self.session_id}
            #     self.external_license("GetKeys", params=params, web=True)

            #     # caching
            #     data = self._cache_keys()
            #     if curl:
            #         return jsonify(data)
            #     return render_template("success.html", page_title="Success", results=data)

            device = self.library.get_prd_by_hash(self.device)
            if not device:
                raise NotFound("PRD not found")

            cdm = pr_sessions.get(self.session_id)
            if not cdm:
                device = PlayreadyDevice.loads(device.prd)
                cdm = PlayreadyCdm.from_device(device)

            try:
                self.session_id = cdm.open().hex()
                pr_sessions[self.session_id] = cdm
            except TooManySessions as e:
                raise InternalServerError("Too many open sessions, please try again in a few minutes")

            try:
                wrm_headers = self.pssh.get_wrm_headers(self.downgrade)
                license_request = cdm.get_license_challenge(
                    session_id=bytes.fromhex(self.session_id), wrm_header=wrm_headers
                )
            except InvalidInitData as e:
                logger.exception(e)
                raise BadRequest("Invalid init data")
            except Exception as e:
                logger.exception(e)
                raise BadRequest("Playready exception: " + str(e))

            if curl or self.is_web:
                try:
                    license_response = self.post_data(self.license_url, self.headers, license_request, self.proxy)
                    cdm.parse_license(session_id=bytes.fromhex(self.session_id), licence=license_response)
                except InvalidSession as e:
                    logger.exception(e)
                    raise BadRequest("Invalid session")
                except InvalidLicense as e:
                    logger.exception(e)
                    raise BadRequest("Invalid License")
                except Exception as e:
                    logger.exception(e)
                    raise BadRequest("Playready exception: " + str(e))

                try:
                    keys = cdm.get_keys(session_id=bytes.fromhex(self.session_id))
                except ValueError as e:
                    logger.exception(e)
                    raise BadRequest("Failed to get keys")

                for key in keys:
                    self.content_keys.append(
                        CachedKey(key.key_id.hex, self.time, self.user_id, self.license_url, key.key.hex())
                    )

                # caching
                data = self._cache_keys()

                # close the session
                cdm.close(session_id=bytes.fromhex(self.session_id))

                if curl:
                    return jsonify(data)

                return render_template("success.html", page_title="Success", results=data)
            else:
                return jsonify({"challenge": license_request, "session_id": self.session_id})
        else:
            # get session
            cdm = pr_sessions.get(self.session_id)
            if not cdm:
                raise BadRequest("Session not found, did you generate a challenge first?")

            try:
                cdm.parse_license(session_id=bytes.fromhex(self.session_id), licence=self.license_response)
            except InvalidLicense as e:
                logger.exception(e)
                raise BadRequest("Invalid license")
            except InvalidSession as e:
                logger.exception(e)
                raise BadRequest("Invalid session")
            except Exception as e:
                logger.exception(e)
                raise BadRequest("Playready exception: " + str(e))

            try:
                keys = cdm.get_keys(session_id=bytes.fromhex(self.session_id))
            except InvalidSession as e:
                logger.exception(e)
                raise BadRequest("Invalid session")
            except ValueError as e:
                logger.exception(e)
                raise BadRequest("Failed to get keys")

            for key in keys:
                self.content_keys.append(
                    CachedKey(key.key_id.hex, self.time, self.user_id, self.license_url, key.key.hex())
                )

            # caching
            output = self._cache_keys()

            # close the session
            cdm.close(session_id=bytes.fromhex(self.session_id))

            return jsonify(output)

    def _cache_keys(self):
        self.library.cache_keys(self.content_keys)

        results = {
            "license_url": self.license_url,
            "added_at": self.time,
            "keys": list(),
            "session_id": self.session_id,
        }
        for key in self.content_keys:
            # s = urlsplit(self.license_url)
            # license_url = "{}//{}".format(s.scheme, s.netloc)
            results["keys"].append(f"{key.kid}:{key.key}")

        return results


class WvDecrypt:
    def __init__(self, pssh_b64, device):
        from getwvkeys.pywidevine.cdm import cdm

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

    def close_session(self):
        self.cdm.close_session(self.session)
