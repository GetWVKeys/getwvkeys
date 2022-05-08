import shelve
import requests
import base64
import json
from flask import render_template, Response
import time
import yaml

try:
    requests.packages.urllib3.disable_warnings()
    requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
    requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
except AttributeError:
    # no pyopenssl support used / needed / available
    pass


class Library:
    store_request = {}

    def __init__(self):
        self.database = shelve.open("database")

    def cached_number(self):
        return len(self.database)

    def match(self, pssh):
        if '-' in pssh:
            pssh = pssh.replace('-', '')
        if len(pssh) == 32:
            return self.database[pssh]
        r = requests.post(url='https://integration.widevine.com/_/pssh_decode', data=pssh)
        res = r.text.replace(')]}\'', '')
        for bkids in json.loads(res)['keyIds']:
            kid = base64.b64decode(bkids).hex()
            if kid in self.database:
                return self.database[kid]
        return

    @staticmethod
    def cdm_selector(blob_id):
        cdms = shelve.open("cdm")
        cdm = cdms[blob_id] if blob_id in cdms else None
        cdms.close()
        return cdm

    @staticmethod
    def update_cdm(blobs, key):
        from pywidevine.cdm.formats import wv_proto2_pb2

        def get_blob_id(blob):
            blob_ = base64.b64decode(blob)
            ci = wv_proto2_pb2.ClientIdentification()
            ci.ParseFromString(blob_)
            return str(ci.ClientInfo[5]).split("Value: ")[1].replace("\n", "").replace('"', "")

        def update(blob_id, blob_base, key_base):
            cdms = shelve.open("cdm")
            data = {
                "session_id_type": "android",
                "security_level": "3",
                "client_id_blob_filename": blob_base,
                "device_private_key": key_base
            }
            cdms[blob_id] = data
            cdms.close()

        update(get_blob_id(blobs), blob_base=blobs, key_base=key)

        return get_blob_id(blobs)

    def cache_keys(self, data):
        for keys in data['keys']:
            for key in keys:
                self.database[keys[key].split(':')[0]] = data


class Pywidevine:
    def __init__(self, password, license_, pssh, headers, buildinfo, cache=False, response=None, challenge=False):
        self.password = password
        self.license = license_
        self.pssh = pssh
        self.headers = headers
        self.buildinfo = buildinfo
        self.cache = cache
        self.time = str(time.ctime())
        self.content_key = []
        self.challenge = challenge
        self.response = response
        self.config = self.config()
        self.proxy = self.config['proxy']
        self.store_request = {}

    @staticmethod
    def config():
        config = open('config.json', 'r')
        return json.loads(config.read())

    @staticmethod
    def defaul_cdms():
        config = json.loads(open('config.json', 'r').read())
        return config['default_cdms']

    def logs(self):
        data = {
            "pssh": self.pssh,
            "time": self.time,
            "keys": self.content_key
        }
        Library().cache_keys(data)
        return data

    def check_password(self):
        for password in self.config['Passwords']:
            if self.password in password:
                return False
        return True

    @staticmethod
    def yamldomagic(headers):
        try:
            return {
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (Ktesttemp, like Gecko) '
                              'Chrome/90.0.4430.85 Safari/537.36'
            } if headers == "" else yaml.safe_load(headers)
        except Exception as e:
            raise Exception("Wrong headers:\n" + str(e))

    @staticmethod
    def post_data(license_url, headers, challenge, proxy):
        r = requests.post(url=license_url, data=challenge,
                          headers=headers, proxies=proxy, timeout=10, verify=False)
        if r.status_code != 200:
            raise Exception("Error404:\n" + r.text)

        return base64.b64encode(r.content)

    def main(self):
        # Cached
        if self.cache:
            cached = Library().match(self.pssh)
            if cached:
                return render_template("cache.html", cache=cached)
        # Password
        if self.check_password():
            return render_template("error.html", error="Wrong Password")
        # Headers
        try:
            self.headers = json.loads(self.headers)
        except (Exception,):
            self.headers = self.yamldomagic(self.headers)

        from pywidevine.cdm import deviceconfig
        wvdecrypt = WvDecrypt(self.pssh, deviceconfig.DeviceConfig(self.buildinfo))
        challenge = wvdecrypt.create_challenge()

        decode = self.post_data(self.license, self.headers, challenge, self.proxy)

        wvdecrypt.decrypt_license(decode)
        for x, y in enumerate(wvdecrypt.get_content_key()):
            self.content_key.append({'key': y})

        # caching
        self.logs()

        return render_template("success.html", page_title='Success', keys=self.content_key, time=self.time,
                               license=self.license, pssh=self.pssh, headers=self.headers)

    def api(self):
        if self.check_password():
            resp = Response("Wrong Password")
            resp.headers['password'] = "wrong"
            return resp

        if self.cache:
            cached = Library().match(self.pssh)
            resp = Response(json.dumps(cached))
            resp.headers['cached'] = True
            return resp
        if self.response is None:
            from pywidevine.cdm import deviceconfig
            wvdecrypt = WvDecrypt(self.pssh, deviceconfig.DeviceConfig(self.buildinfo))
            challenge = wvdecrypt.create_challenge()
            if len(Library.store_request) > 30:
                self.store_request = {}
            Library.store_request[self.pssh] = wvdecrypt

            res = base64.b64encode(challenge).decode()
            return res
        else:
            if self.pssh not in Library.store_request:
                raise Exception("PSSH CHALLENGE WAS NOT GENERATED FIRST")
            wvdecrypt = Library.store_request[self.pssh]
            wvdecrypt.decrypt_license(self.response)
            for x, y in enumerate(wvdecrypt.get_content_key()):
                self.content_key.append({'key': y})
            output = self.logs()
            return output


class WvDecrypt:
    def __init__(self, pssh_b64, device):
        from pywidevine.cdm import cdm
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
            if key.type == 'CONTENT':
                kid = key.kid.hex()
                key = key.key.hex()
                content_keys.append('{}:{}'.format(kid, key))

        return content_keys

    def get_signing_key(self):
        for key in self.cdm.get_keys(self.session):
            if key.type == 'SIGNING':
                kid = key.kid.hex()
                key = key.key.hex()

                signing_key = '{}:{}'.format(kid, key)
                return signing_key
