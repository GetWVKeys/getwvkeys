"""
 This file is part of the GetWVKeys project (https://github.com/GetWVKeys/getwvkeys)
 Copyright (C) 2022 Notaghost, Puyodead1 and GetWVKeys contributors 
 
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import base64
import json
import sys

import requests

version = "4.2"
API_URL = "__getwvkeys_api_url__"

# Change your headers here
def headers():
    return {"Connection": "keep-alive", "accept": "*/*"}


# CHANGE THIS FUNCTION TO PARSE LICENSE URL RESPONSE
def post_request(arg, challenge):
    r = requests.post(arg.url, headers=arg.headers, data=challenge, timeout=10)
    if arg.verbose:
        # printing the raw license data can break terminals
        print("[+] License response:\n", base64.b64encode(r.content).decode("utf-8"))
    if not r.ok:
        print("[-] Failed to get license: [{}] {}".format(r.status_code, r.text))
        exit(1)
    return r.content


# Do Not Change Anything in this class
class GetWVKeysApi:
    def __init__(self, arg) -> None:
        # dynamic injection of the API url
        self.baseurl = "https://getwvkeys.cc" if API_URL == "__getwvkeys_api_url__" else API_URL
        self.api_url = self.baseurl + "/pywidevine"
        self.args = arg
        self.args.headers = headers()

    def generate_request(self):
        if self.args.verbose:
            print("[+] Generating License Request ")
        data = {"pssh": self.args.pssh, "buildInfo": self.args.buildinfo, "cache": self.args.cache, "license_url": self.args.url}
        header = {"X-API-Key": args.auth, "Content-Type": "application/json"}
        r = requests.post(self.api_url, json=data, headers=header)
        if not r.ok:
            if "error" in r.text:
                # parse the response as a json error
                error = json.loads(r.text)
                print("[-] Failed to generate license request: [{}] {}".format(error.get("code"), error.get("message")))
                exit(1)
            print("[-] Failed to generate license request: [{}] {}".format(r.status_code, r.text))
            exit(1)

        data = r.json()

        if r.headers.get("X-Cached"):
            if args.verbose:
                print(json.dumps(data, indent=4))
            print("\n" * 5)
            print("[+] Keys:")
            for k in data["keys"]:
                print("--key {}".format(k["key"]))
            input("[+] Press Enter To Continue with request")
            self.args.cache = False
            return self.generate_request()

        self.session_id = data["session_id"]
        challenge = data["challenge"]

        if self.args.verbose:
            print("[+] License Request Generated\n", challenge)
            print("[+] Session ID:", self.session_id)

        return base64.b64decode(challenge)

    def decrypter(self, license_response):
        if self.args.verbose:
            print("[+] Decrypting with License Request and Response ")
        data = {
            "pssh": self.args.pssh,
            "response": license_response,
            "license_url": self.args.url,
            "headers": self.args.headers,
            "buildInfo": self.args.buildinfo,
            "cache": self.args.cache,
            "session_id": self.session_id,
        }
        header = {"X-API-Key": args.auth, "Content-Type": "application/json"}
        r = requests.post(self.api_url, json=data, headers=header)
        if not r.ok:
            if "error" in r.text:
                # parse the response as a json error
                error = json.loads(r.text)
                print("[-] Failed to decrypt license: [{}] {}".format(error.get("code"), error.get("message")))
                exit(1)
            print("[-] Failed to decrypt license: [{}] {}".format(r.status_code, r.text))
            exit(1)
        return r.json()

    def main(self):
        license_request = self.generate_request()
        if args.verbose:
            print("[+] Sending License URL Request")
        license_response = post_request(args, license_request)
        decrypt_response = self.decrypter(base64.b64encode(license_response).decode())
        keys = decrypt_response["keys"]
        session_id = decrypt_response["session_id"]

        if args.verbose:
            print(json.dumps(decrypt_response, indent=4))
            print("Decryption Session ID:", session_id)
        print("\n" * 5)
        print("[+] Keys:")
        for k in keys:
            print("--key {}".format(k))


if __name__ == "__main__":
    getwvkeys_api_key = "__getwvkeys_api_key__"
    print(f"\n{' ' * 6}pywidevine-api {version}\n{' ' * 7} from getwvkeys \n\n")

    parser = argparse.ArgumentParser()
    parser.add_argument("-url", help="License URL")
    parser.add_argument("-pssh", help="PSSH")
    parser.add_argument("-auth", help="GetWVKeys API Key")
    parser.add_argument("--verbose", "-v", help="increase output verbosity", action="store_true")
    parser.add_argument("--cache", "-c", help="Cache On. default is OFF", default=False, action="store_true")
    parser.add_argument("--buildinfo", "-b", default="", help="Buildinfo", required=False)

    args = parser.parse_args()
    args.auth = getwvkeys_api_key if getwvkeys_api_key != "__getwvkeys_api_key__" else args.auth

    while (args.url is None or args.pssh is None) or (args.url == "" or args.pssh == ""):
        args.url = input("Enter License URL: ")
        args.pssh = input("Enter PSSH: ")
        if not args.auth:
            args.auth = input("Enter GetWVKeys API Key: ")

    if len(sys.argv) == 1:
        parser.print_help()
        print()
        args.buildinfo = ""
        args.verbose = False

    try:
        start = GetWVKeysApi(args)
        start.main()
    except Exception as e:
        raise
