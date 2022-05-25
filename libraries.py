import sqlite3
import requests
import base64
import json
from flask import render_template, Response
import time
import yaml
import random


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
        self.database = self.connect_database()
        self.cdm = self.connect_cdm()

    @staticmethod
    def connect_database():
        conn = sqlite3.connect('database.db', isolation_level=None)
        return conn.cursor()

    @staticmethod
    def close_database(conn):
        conn.close()

    @staticmethod
    def connect_cdm():
        conn = sqlite3.connect('cdms.db', isolation_level=None)
        return conn.cursor()

    @staticmethod
    def close_cdm(conn):
        conn.close()

    def cache_keys(self, data):
        for keys in data['keys']:
            for key in keys:

                # self.database[keys[key].split(':')[0]] = data
                self.database.execute(
                    "INSERT OR REPLACE INTO DATABASE (pssh,headers,KID,proxy,time,license,keys) VALUES (?,?,?,?,?,?,?)",
                    (data['pssh'], json.dumps(data['headers']), key,
                     json.dumps(data['proxy']), data['time'], data['license'], json.dumps(data['keys'])))

    def cached_number(self):
        database_result = self.database.execute("SELECT COUNT(*) FROM DATABASE ")
        cache = database_result.fetchall()
        return cache[0][0]

    def match(self, pssh):
        if "-" in pssh:
            pssh = pssh.replace("-", "")
        sql = f'SELECT * FROM DATABASE WHERE PSSH = "{pssh}" or KID = "{pssh}"'
        database_result = self.database.execute(sql)
        result = database_result.fetchall()
        if result:
            data = {
                "pssh": result[0][1],
                "time": result[0][4],
                "keys": eval(result[0][6]),
            }
        else:
            data = {}
        return data

    def cdm_selector(self, blob_id):

        sql = f'SELECT * FROM CDMS WHERE CODE = "{blob_id}"'
        database = self.cdm.execute(sql)
        data_result = database.fetchall()
        if not data_result:
            raise Exception("NO CDM FOUND")
        data = {
            "session_id_type": "android",
            "security_level": "3",
            "client_id_blob_filename": data_result[0][2],
            "device_private_key": data_result[0][3]
        }
        return data

    def update_cdm(self, blobs, key):
        from pywidevine.cdm.formats import wv_proto2_pb2

        def get_blob_id(blob):
            blob_ = base64.b64decode(blob)
            ci = wv_proto2_pb2.ClientIdentification()
            ci.ParseFromString(blob_)
            return str(ci.ClientInfo[5]).split("Value: ")[1].replace("\n", "").replace('"', "")

        ID = get_blob_id(blobs)
        self.cdm.execute(
            "INSERT OR REPLACE INTO CDMS (client_id_blob_filename,device_private_key,CODE) VALUES (?,?,?)",
            (blobs, key, ID))
        return ID

    def dev_append(self, pssh, keys: dict, access):
        # testing PSSH
        config = Pywidevine.config()

        if access not in config['appenders']:
            raise Exception("You are not allowed to add to database")

        try:
            base64.b64decode(pssh)
            from pywidevine.cdm import deviceconfig
            WvDecrypt(pssh, deviceconfig.DeviceConfig(random.choice(Pywidevine.config()['default_cdms'])))
        except Exception as e:
            raise Exception(f"PSSH ERROR {str(e)}")
        data = {
            "pssh": pssh,
            "time": str(time.ctime()),
            "keys": keys,
        }
        for key in keys:
            if len(key['key'].split(":")[0]) != 32:
                raise Exception("wrong key length")
            self.database.execute(
                "INSERT OR REPLACE INTO DATABASE (pssh,headers,KID,proxy,time,license,keys) VALUES (?,?,?,?,?,?,?)",
                (data['pssh'], "", key['key'].split(":")[0], "", data['time'], "", str(data['keys']))
            )
        response = {
            "response": "added"
        }
        return json.dumps(response)


class Pywidevine:
    def __init__(self, proxy, license_, pssh, headers, buildinfo, cache=False, response=None, challenge=False):

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
        if isinstance(proxy, dict):
            self.proxy = proxy
        else:
            self.proxy = {}
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
            "keys": self.content_key,
            "headers": self.headers,
            "proxy": self.proxy,
            "license": self.license
        }
        Library().cache_keys(data)
        return data

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
            raise Exception(f"Error {r.status_code}:\n" + r.text)

        return base64.b64encode(r.content)

    def main(self, curl=False):
        # Cached

        if self.cache:
            cached = Library().match(self.pssh)
            if cached:
                if not curl:
                    return render_template("cache.html", cache=cached)
                else:
                    return json.dumps(cached)

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
        data = self.logs()
        if curl:
            return json.dumps(data)
        return render_template("success.html", page_title='Success', keys=self.content_key, time=self.time,
                               license=self.license, pssh=self.pssh, headers=self.headers)

    def api(self):
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
