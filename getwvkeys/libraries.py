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
import json
import logging
import secrets
import time
from typing import Dict, Union

import requests
import yaml
from flask import jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from pywidevine import PSSH, Cdm, Device, DeviceTypes
from pywidevine.exceptions import (
    InvalidContext,
    InvalidInitData,
    InvalidLicenseMessage,
    InvalidLicenseType,
    InvalidSession,
    SignatureMismatch,
    TooManySessions,
)
from requests.exceptions import ProxyError
from werkzeug.exceptions import (
    BadRequest,
    InternalServerError,
    NotFound,
    NotImplemented,
)

from getwvkeys import config
from getwvkeys.models.Device import Device as DeviceModel
from getwvkeys.models.Device import generate_device_code
from getwvkeys.models.Key import Key as KeyModel
from getwvkeys.models.User import User

# from getwvkeys.pywidevine.cdm import deviceconfig
from getwvkeys.utils import (
    CachedKey,
    extract_kid_from_pssh,
    get_blob_id,
    search_res_to_dict,
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

sessions: dict[tuple[str, str], Cdm] = dict()

# increase max number of sessions
Cdm.MAX_NUM_OF_SESSIONS = config.MAX_SESSIONS


def get_random_device_key():
    if len(config.DEFAULT_DEVICES) == 0:
        raise Exception("No Devices configured")
    return secrets.choice(config.DEFAULT_DEVICES)


def is_custom_device_key(code):
    return next((True for entry in config.EXTERNAL_API_DEVICES if entry["code"] == code), False)


class GetWVKeys:
    def __init__(self, db: SQLAlchemy):
        self.db = db

    sessions = {}

    def cache_keys(self, cached_keys: list[CachedKey]):
        for cached_key in cached_keys:
            self.cache_key(cached_key)

    def cache_key(self, cached_key: CachedKey):
        k = KeyModel(
            kid=cached_key.kid,
            added_at=cached_key.added_at,
            added_by=cached_key.added_by,
            license_url=cached_key.license_url,
            key_=cached_key.key,
        )
        self.db.session.merge(k)
        self.db.session.commit()

    def get_keycount(self) -> int:
        return KeyModel().query.count()

    def search(self, query: Union[PSSH, str]) -> list:
        if isinstance(query, PSSH):
            query = query.key_ids[0].hex()
        elif "-" in query:
            query = query.replace("-", "")

        return KeyModel.query.filter_by(kid=query).all()

    def device_selector(self, code: str) -> dict:
        device = DeviceModel.query.filter_by(code=code).first()
        if not device:
            raise NotFound("DeviceModel not found")
        return device.to_json()

    def get_device_by_code(self, code: str) -> DeviceModel:
        device = DeviceModel.query.filter_by(code=code).first()
        if not device:
            raise NotFound("DeviceModel not found")
        return device

    def upload_device(self, client_id_blob: str, device_private_key: str, user_id: str) -> str:
        user = User.query.filter_by(id=user_id).first()
        if not user:
            raise NotFound("User not found")
        # calculate the device code
        code = generate_device_code(client_id_blob, device_private_key)

        # get device
        device = DeviceModel.query.filter_by(code=code).first()
        if not device:
            # create device
            info = get_blob_id(client_id_blob)
            wvd = Device(
                type_=DeviceTypes.ANDROID,
                security_level=3,  # TODO: let user specify?
                flags=None,
                private_key=base64.b64decode(device_private_key),
                client_id=base64.b64decode(client_id_blob),
            )
            device = DeviceModel(uploaded_by=user.id, wvd=base64.b64encode(wvd.dumps()).decode(), code=code, info=info)
            self.db.session.add(device)
            user.devices.append(device)
            self.db.session.commit()
        elif device not in user.devices:
            # add device to user if its not already there
            user.devices.append(device)
            self.db.session.commit()
        else:
            raise Exception("DeviceModel already uploaded, please use the existing code found on the profile page.")

        return device.code

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


class Pywidevine:
    def __init__(
        self,
        gwvk: GetWVKeys,
        user_id,
        device_code: str,
        # TODO: we really shouldn't do this, but vinetrimmer doesn't send license urls without modifications
        license_url="VINETRIMMER",
        pssh=None,
        proxy={},
        headers={},
        force=False,
        license_response=None,
        license_request=False,
        service_certificate=None,
        session_id=None,
        disable_privacy=False,
    ):
        self.gwvk = gwvk
        self.license_url = license_url
        self.headers = headers
        self.device_code = device_code
        self.force = force
        self.time = int(time.time())
        self.content_keys: list[CachedKey] = list()
        self.license_request = license_request
        self.license_response = license_response
        self.user_id = user_id
        self.service_certificate = service_certificate
        self.proxy = proxy
        if self.proxy and isinstance(self.proxy, str):
            self.proxy = {"http": self.proxy, "https": self.proxy}
        self.store_request = {}
        self.session_id = bytes.fromhex(session_id) if session_id else None
        self.disable_privacy = disable_privacy

        try:
            self.pssh = PSSH(pssh) if pssh else None
        except Exception as e:
            logger.exception(e)
            raise BadRequest(f"Failed to parse PSSH: {e}")

    def _cache_keys(self, dv=False):
        self.gwvk.cache_keys(self.content_keys)

        # format for devine
        # TODO:
        if dv:
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
            "kid": self.pssh.key_ids[0].hex,
            "license_url": self.license_url,
            "added_at": self.time,
            "keys": list(),
            "session_id": self.session_id.hex(),
        }
        for key in self.content_keys:
            # s = urlsplit(self.license_url)
            # license_url = "{}//{}".format(s.scheme, s.netloc)
            results["keys"].append(key.key)

        return results

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

    @staticmethod
    def post_data(license_url: str, headers: dict[str, str] | None, data: bytes, proxy: dict[str, str] | None):
        try:
            r = requests.post(url=license_url, data=data, headers=headers, proxies=proxy, timeout=10, verify=False)
            if r.status_code != 200:
                raise BadRequest(f"Failed to get license: {r.status_code} {r.reason}")
            return base64.b64encode(r.content).decode()
        except ProxyError as e:
            raise BadRequest(f"Proxy error: {e.args[0].reason}")
        except ConnectionError as e:
            raise BadRequest(f"Connection error: {e.args[0].reason}")

    # def external_license(self, method, params, web=False):
    #     entry = next((entry for entry in config.EXTERNAL_API_DEVICES if entry["device_code"] == self.device_code), None)
    #     if not entry:
    #         raise BadRequest("Invalid device code")
    #     api = entry["url"]
    #     payload = {"method": method, "params": params, "token": entry["token"]}
    #     r = requests.post(api, headers=self.headers, json=payload, proxies=self.proxy)
    #     if r.status_code != 200:
    #         if "message" in r.text:
    #             raise Exception(f"Error: {r.json()['message']}")
    #         raise Exception(f"Unknown Error: [{r.status_code}] {r.text}")
    #     if method == "GetChallenge":
    #         d = r.json()
    #         if entry["version"] == 2:
    #             challenge = d["message"]["challenge"]
    #             self.session_id = d["message"]["session_id"]
    #         else:
    #             challenge = d["challenge"]
    #             self.session_id = d["session_id"]
    #         if not web:
    #             return jsonify({"challenge": challenge, "session_id": self.session_id})
    #         return challenge
    #     elif method == "GetKeys":
    #         d = r.json()
    #         if entry["version"] == 2:
    #             keys = d["message"]["keys"]
    #         else:
    #             keys = d["keys"]
    #         for x in keys:
    #             kid = x["kid"]
    #             key = x["key"]
    #             self.content_keys.append(
    #                 CachedKey(kid, self.time, self.user_id, self.license_url, "{}:{}".format(kid, key))
    #             )
    #     elif method == "GetKeysX":
    #         raise NotImplemented()
    #     else:
    #         raise Exception("Unknown method")

    def main(self, curl=False):
        # Search for cached keys first
        if not self.force:
            result = self.gwvk.search(self.pssh)
            if result and len(result) > 0:
                cached = search_res_to_dict(self.pssh.key_ids[0].hex(), result)
                if not curl:
                    return render_template("cache.html", results=cached)
                r = jsonify(cached)
                r.headers.add_header("X-Cache", "HIT")
                return r, 302

        # Headers
        # TODO: better parsing
        try:
            self.headers = json.loads(self.headers)
        except (Exception,):
            self.headers = self.yamldomagic(self.headers)

        # if is_custom_device_key(self.device_code):
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

        device = self.gwvk.get_device_by_code(self.device_code)

        cdm = sessions.get((self.user_id, self.device_code))
        if not cdm:
            device = Device.loads(device.wvd)
            cdm = sessions[(self.user_id, self.device_code)] = Cdm.from_device(device)

        try:
            self.session_id = cdm.open()
        except TooManySessions as e:
            raise InternalServerError("Too many open sessions, please try again in a few minutes")

        privacy_mode = False

        if self.service_certificate:
            cdm.set_service_certificate(session_id=self.session_id, certificate=self.service_certificate)
            privacy_mode = True
        # elif not self.disable_privacy:
        #     cdm.set_service_certificate(session_id=session_id, certificate=common_privacy_cert)
        #     privacy_mode = True

        try:
            license_request = cdm.get_license_challenge(
                session_id=self.session_id, pssh=self.pssh, license_type="STREAMING", privacy_mode=privacy_mode
            )
        except InvalidInitData as e:
            logger.exception(e)
            raise BadRequest("Invalid init data")
        except InvalidLicenseType as e:
            logger.exception(e)
            raise BadRequest("Invalid license type")

        license_response = self.post_data(self.license_url, self.headers, license_request, self.proxy)

        try:
            cdm.parse_license(session_id=self.session_id, license_message=license_response)
        except InvalidLicenseMessage as e:
            logger.exception(e)
            raise BadRequest("Invalid license message")
        except InvalidContext as e:
            logger.exception(e)
            raise BadRequest("Invalid context")
        except SignatureMismatch as e:
            logger.exception(e)
            raise BadRequest("Signature mismatch")

        try:
            keys = cdm.get_keys(session_id=self.session_id, type_="CONTENT")
        except ValueError as e:
            logger.exception(e)
            raise BadRequest("Failed to get keys")

        for key in keys:
            self.content_keys.append(CachedKey(key.kid.hex, self.time, self.user_id, self.license_url, key.key.hex()))

        # caching
        data = self._cache_keys()
        # close the session
        cdm.close(session_id=self.session_id)
        if curl:
            return jsonify(data)
        return render_template("success.html", page_title="Success", results=data)

    def api(self):
        # Search for cached keys first
        if not self.force:
            result = self.gwvk.search(self.pssh)
            if result and len(result) > 0:
                cached = search_res_to_dict(self.kid, result)
                r = jsonify(cached)
                r.headers.add_header("X-Cache", "HIT")
                return r, 302

        device = self.gwvk.get_device_by_code(self.device_code)

        if self.license_response is None:
            # TODO: I dont remember what this shit was for?
            # if is_custom_device_key(self.device_code):
            #     if not self.service_certificate:
            #         try:
            #             self.service_certificate = self.post_data(
            #                 self.license_url, self.headers, base64.b64decode("CAQ="), self.proxy
            #             )
            #         except Exception as e:
            #             raise BadRequest(
            #                 f"Failed to retrieve server certificate: {e}. Please provide a server certificate manually."
            #             )
            #     params = {
            #         "init": self.pssh,
            #         "cert": self.service_certificate,
            #         "raw": False,
            #         "licensetype": "STREAMING",
            #         "device": "api",
            #     }
            #     return self.external_license("GetChallenge", params)

            # remove the oldest session
            if len(sessions) > config.MAX_SESSIONS:
                sessions.pop(next(iter(sessions)))

            cdm = sessions.get((self.user_id, self.device_code))
            if not cdm:
                device = Device.loads(device.wvd)
                cdm = sessions[(self.user_id, self.device_code)] = Cdm.from_device(device)

            try:
                self.session_id = cdm.open()
            except TooManySessions as e:
                raise InternalServerError("Too many open sessions, please try again in a few minutes")

            privacy_mode = False

            if self.service_certificate:
                cdm.set_service_certificate(session_id=self.session_id, certificate=self.service_certificate)
                privacy_mode = True
            # elif not self.disable_privacy:
            #     cdm.set_service_certificate(session_id=session_id, certificate=common_privacy_cert)
            #     privacy_mode = True

            try:
                license_request = cdm.get_license_challenge(
                    session_id=self.session_id, pssh=self.pssh, license_type="STREAMING", privacy_mode=privacy_mode
                )
            except InvalidInitData as e:
                logger.exception(e)
                raise BadRequest("Invalid init data")
            except InvalidLicenseType as e:
                logger.exception(e)
                raise BadRequest("Invalid license type")

            return jsonify(
                {"challenge": base64.b64encode(license_request).decode(), "session_id": self.session_id.hex()}
            )

        # TODO: I dont remember what this shit was for?
        # if is_custom_device_key(self.device_code):
        #     params = {"cdmkeyresponse": self.license_response, "session_id": self.session_id.hex()}
        #     self.external_license("GetKeys", params=params)
        #     output = self._cache_keys()
        #     return jsonify(output)

        # license parsing

        # get session
        cdm = sessions.get((self.user_id, self.device_code))
        if not cdm:
            raise BadRequest("Session not found, did you generate a challenge first?")

        try:
            cdm.parse_license(session_id=self.session_id, license_message=self.license_response)
        except InvalidLicenseMessage as e:
            logger.exception(e)
            raise BadRequest("Invalid license message")
        except InvalidContext as e:
            logger.exception(e)
            raise BadRequest("Invalid context")
        except SignatureMismatch as e:
            logger.exception(e)
            raise BadRequest("Signature mismatch")

        try:
            keys = cdm.get_keys(session_id=self.session_id, type_="CONTENT")
        except ValueError as e:
            logger.exception(e)
            raise BadRequest("Failed to get keys")

        for key in keys:
            self.content_keys.append(CachedKey(key.kid.hex, self.time, self.user_id, self.license_url, key.key.hex()))

        # caching
        output = self._cache_keys()
        # close the session
        cdm.close(session_id=self.session_id)
        return jsonify(output)

    # def vinetrimmer(self, library: Library):
    #     if self.response is None:
    #         wvdecrypt = WvDecrypt(self.pssh, deviceconfig.DeviceConfig(library, self.device_code))
    #         challenge = wvdecrypt.create_challenge()
    #         if len(sessions) > config.MAX_SESSIONS:
    #             # remove the oldest session
    #             sessions.pop(next(iter(sessions)))
    #         self.session_id = wvdecrypt.session.hex()
    #         sessions[self.session_id] = wvdecrypt

    #         res = base64.b64encode(challenge).decode()
    #         return {"challenge": res, "session_id": self.session_id}
    #     else:
    #         if self.session_id not in sessions:
    #             raise BadRequest("Session not found, did you generate a challenge first?")
    #         wvdecrypt = sessions[self.session_id]
    #         wvdecrypt.decrypt_license(self.response)
    #         for _, y in enumerate(wvdecrypt.get_content_key()):
    #             (kid, _) = y.split(":")
    #             self.content_keys.append(CachedKey(kid, self.time, self.user_id, self.license_url, y))
    #         keys = self._cache_keys(vt=True)
    #         # close the session
    #         wvdecrypt.close_session()
    #         return {"keys": keys, "session_id": self.session_id}
