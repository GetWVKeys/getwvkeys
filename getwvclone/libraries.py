import base64
import json
import random
import secrets
import sqlite3
import time

import requests
import yaml
from flask import Response, render_template
from flask_login import UserMixin
from werkzeug.exceptions import BadRequest, Forbidden

from config import APPENDERS, DEFAULT_CDMS, GUILD_ID, VERIFIED_ROLE_ID
from instance.config import OAUTH2_CLIENT_ID, OAUTH2_CLIENT_SECRET


class Library:
    store_request = {}

    def __init__(self):
        pass

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
        database = self.connect_database()
        for keys in data['keys']:
            # for key in keys:
            # self.database[keys[key].split(':')[0]] = data
            key = keys.get("key")
            (kid, _) = key.split(':')
            database.execute(
                "INSERT OR IGNORE INTO DATABASE (pssh,headers,KID,proxy,time,license,keys) VALUES (?,?,?,?,?,?,?)",
                (data['pssh'], json.dumps(data['headers']), kid,
                    json.dumps(data['proxy']), data['time'], data['license'], json.dumps(data['keys'])))
        self.close_database(database)

    def cached_number(self):
        db = self.connect_database()
        count = db.execute("SELECT COUNT(*) FROM DATABASE").fetchone()[0]
        self.close_database(db)
        return count

    @staticmethod
    def search(query):
        if "-" in query:
            query = query.replace("-", "")
        database = Library.connect_database()
        database.execute(
            "SELECT keys FROM DATABASE WHERE PSSH = ? or KID = ?", (query, query))
        results = database.fetchall()
        return results

    def match(self, pssh):
        database = self.connect_database()
        if "-" in pssh:
            pssh = pssh.replace("-", "")
        sql = f'SELECT * FROM DATABASE WHERE PSSH = "{pssh}" or KID = "{pssh}"'
        database_result = database.execute(sql)
        result = database_result.fetchall()
        if result:
            data = {
                "pssh": result[0][1],
                "time": result[0][4],
                "keys": eval(result[0][6]),
                # "headers": result[0][2],
                # "proxy": result[0][3],
                # "license": result[0][5]
            }
        else:
            data = {}
        self.close_database(database)
        return data

    def cdm_selector(self, blob_id):
        cdm = self.connect_cdm()
        sql = f'SELECT * FROM CDMS WHERE CODE = "{blob_id}"'
        database = cdm.execute(sql)
        data_result = database.fetchall()
        if not data_result:
            raise Exception("NO CDM FOUND")
        data = {
            "session_id_type": "android",
            "security_level": "3",
            "client_id_blob_filename": data_result[0][2],
            "device_private_key": data_result[0][3]
        }
        self.close_cdm(cdm)
        return data

    def update_cdm(self, blobs, key, uploader):
        from pywidevine.cdm.formats import wv_proto2_pb2

        def get_blob_id(blob):
            blob_ = base64.b64decode(blob)
            ci = wv_proto2_pb2.ClientIdentification()
            ci.ParseFromString(blob_)
            return str(ci.ClientInfo[5]).split("Value: ")[1].replace("\n", "").replace('"', "")

        blob_id = get_blob_id(blobs)
        cdm = self.connect_cdm()
        cdm.execute(
            "INSERT OR IGNORE INTO CDMS (client_id_blob_filename,device_private_key,CODE, uploaded_by) VALUES (?,?,?, ?)",
            (blobs, key, blob_id, uploader))
        self.close_cdm(cdm)
        return blob_id

    def dev_append(self, pssh, keys: dict, access):
        # testing PSSH
        if access not in APPENDERS:
            raise Exception("You are not allowed to add to database")

        try:
            base64.b64decode(pssh)
            from pywidevine.cdm import deviceconfig
            WvDecrypt(pssh, deviceconfig.DeviceConfig(
                random.choice(DEFAULT_CDMS)))
        except Exception as e:
            raise Exception(f"PSSH ERROR {str(e)}")
        data = {
            "pssh": pssh,
            "time": str(time.ctime()),
            "keys": json.dumps(keys),
        }

        for key in keys:
            if len(key['key'].split(":")[0]) != 32:
                raise Exception("wrong key length")
            database = self.connect_database()
            database.execute(
                "INSERT OR IGNORE INTO DATABASE (pssh,headers,KID,proxy,time,license,keys) VALUES (?,?,?,?,?,?,?)",
                (data['pssh'], "", key['key'].split(":")[0],
                 "", data['time'], "", json.dumps(data['keys']))
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
        if isinstance(proxy, dict):
            self.proxy = proxy
        else:
            self.proxy = {}
        self.store_request = {}

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
        wvdecrypt = WvDecrypt(
            self.pssh, deviceconfig.DeviceConfig(self.buildinfo))
        challenge = wvdecrypt.create_challenge()

        decode = self.post_data(
            self.license, self.headers, challenge, self.proxy)

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
            wvdecrypt = WvDecrypt(
                self.pssh, deviceconfig.DeviceConfig(self.buildinfo))
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


class User(UserMixin):
    def __init__(self, id, username, discriminator, avatar, public_flags, api_key, status, is_admin):
        self.id = id
        self.username = username
        self.discriminator = discriminator
        self.avatar = avatar
        self.public_flags = public_flags
        self.api_key = api_key
        self.status = status
        self.is_admin = is_admin

    def get_user_cdms(self):
        cdms = []
        cursor = Library.connect_cdm()
        cursor.execute("SELECT * FROM cdms WHERE uploaded_by = ?", (self.id,))
        results = cursor.fetchall()
        Library.close_cdm(cursor)

        for result in results:
            cdms.append(result[4])
        return cdms

    def patch(self, data):
        # loop keys in data dict and create a sql statement
        disallowed_keys = ["id", "username", "discriminator",
                           "avatar", "public_flags", "api_key"]
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

        db = Library.connect_cdm()
        db.execute(sql, values)
        Library.close_cdm(db)

    def to_json(self, api_key=False):
        return {
            "id": self.id,
            "username": self.username,
            "discriminator": self.discriminator,
            "avatar": self.avatar,
            "public_flags": self.public_flags,
            "api_key": self.api_key if api_key else None,
            "status": self.status,
            "is_admin": self.is_admin
        }

    @staticmethod
    def get(user_id):
        db = Library.connect_cdm()
        user = db.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if not user:
            return None

        user = User(
            id=user[0], username=user[1], discriminator=user[2], avatar=user[
                3], public_flags=user[4], api_key=user[5], status=user[6], is_admin=user[7]
        )
        Library.close_cdm(db)
        return user

    @staticmethod
    def create(userinfo):
        db = Library.connect_cdm()
        api_key = secrets.token_hex(32)
        db.execute(
            "INSERT INTO users (id, username, discriminator, avatar, public_flags, api_key) VALUES (?, ?, ?, ?, ?, ?)",
            (userinfo.get("id"), userinfo.get("username"), userinfo.get(
                "discriminator"), userinfo.get("avatar"), userinfo.get("public_flags"), api_key)
        )
        Library.close_cdm(db)

    @staticmethod
    def update(userinfo):
        db = Library.connect_cdm()
        db.execute("UPDATE users SET username = ?, discriminator = ?, avatar = ?, public_flags = ? WHERE id = ?", (userinfo.get(
            "username"), userinfo.get("discriminator"), userinfo.get("avatar"), userinfo.get("public_flags"), userinfo.get("id")))
        Library.close_cdm(db)

    @staticmethod
    def user_is_in_guild(token):
        url = "https://discord.com/api/users/@me/guilds"
        headers = {
            "Authorization": f"Bearer {token}"
        }
        r = requests.get(url, headers=headers)
        if not r.ok:
            raise Exception(
                f"Failed to get user guilds: [{r.status_code}] {r.text}")
        guilds = r.json()
        is_in_guild = any(guild.get("id") == GUILD_ID for guild in guilds)
        return is_in_guild

    @staticmethod
    def user_is_verified(token):
        url = f"https://discord.com/api/users/@me/guilds/{GUILD_ID}/member"
        headers = {
            "Authorization": f"Bearer {token}",
        }
        r = requests.get(url, headers=headers)
        if not r.ok:
            raise Exception(
                f"Failed to get guild member: [{r.status_code}] {r.text}")
        data = r.json()
        return any(role == VERIFIED_ROLE_ID for role in data.get("roles"))

    @staticmethod
    def is_api_key_bot(api_key):
        """checks if the api key is from the bot"""
        bot_key = base64.b64encode("{}:{}".format(
            OAUTH2_CLIENT_ID, OAUTH2_CLIENT_SECRET).encode()).decode("utf8")
        return api_key == bot_key

    @staticmethod
    def get_user_by_api_key(api_key):
        db = Library.connect_cdm()
        user = db.execute(
            "SELECT * FROM users WHERE api_key = ?", (api_key,)
        ).fetchone()
        if not user:
            return None

        user = User(
            id=user[0], username=user[1], discriminator=user[2], avatar=user[
                3], public_flags=user[4], api_key=user[5], status=user[6], is_admin=user[7]
        )
        Library.close_cdm(db)
        return user

    @staticmethod
    def is_api_key_valid(api_key):
        # allow the bot to pass
        if User.is_api_key_bot(api_key):
            return True
        db = Library.connect_cdm()
        user = db.execute(
            "SELECT id, status, is_admin FROM users WHERE api_key = ?", (
                api_key,)
        ).fetchone()
        Library.close_cdm(db)
        if not user:
            return False

        status = user[1]
        role = user[2]  # TODO: Use role where fit

        # if the user is suspended, throw forbidden
        if status == 1:
            raise Forbidden("Your account has been suspended.")

        # if we require admin, and the user is not admin, throw forbidden
        # if require_admin and role == 0:
        #     raise Forbidden("You do not have permission to do this.")

        return True

    @staticmethod
    def disable_user(user_id):
        db = Library.connect_cdm()
        # update the user record to set user_status to 1
        db.execute("UPDATE users SET status = ? WHERE id = ?", (1, user_id))
        Library.close_cdm(db)

    @staticmethod
    def disable_users(user_ids):
        print("Request to disable {} users: {}".format(
            len(user_ids), ", ".join([str(x) for x in user_ids])))
        if len(user_ids) == 0:
            raise BadRequest("No data to update or update is not allowed")
        a = ["id = ?"] * len(user_ids)
        sql = "UPDATE users SET status = ? WHERE " + " OR ".join(a)

        db = Library.connect_cdm()
        db.execute(sql, (1, *user_ids))
        Library.close_cdm(db)

    @staticmethod
    def enable_user(user_id):
        db = Library.connect_cdm()
        # update the user record to set user_status to 0
        db.execute("UPDATE users SET status = ? WHERE id = ?", (0, user_id))
        Library.close_cdm(db)

    @staticmethod
    def get_user_count():
        db = Library.connect_cdm()
        count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        Library.close_cdm(db)
        return count
