import base64
import json

import requests
import argparse
import sys
import re
from urllib.parse import urlparse

version = "2.01"


# Do Not Change Anything in this class
class VdoCipher:
    def __init__(self, arg) -> None:
        self.baseurl = "http://getwvkeys.cc/"
        self.api_url = self.baseurl + "/pywidevine"
        self.args = arg
        self.args.license_url = "https://license.vdocipher.com/auth"
        self.json_payloads = {"token": self.args.auth}
        self.kid_key = ""
        self.idx = eval(
            base64.urlsafe_b64decode(
                (
                    eval(
                        base64.urlsafe_b64decode(self.args.auth.encode("utf-8")).decode(
                            "utf-8"
                        )
                    )["playbackInfo"]
                ).encode("utf-8")
            ).decode("utf-8")
        )["videoId"]
        self.mpd, self.title = self.iddetail()
        self.ref = "https://" + urlparse(self.mpd).netloc
        self.args.pssh = self.psshgen()
        self.headers = self.args.headers = self.header()

    def header(self):
        headers = {
            "user-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36",
            "authority": "license.vdocipher.com",
            "connection": "Keep-Alive",
            "vdo-ref": eval(
                base64.urlsafe_b64decode(self.args.auth.encode("utf-8")).decode("utf-8")
            )["href"],
            "origin": self.ref,
            "referer": self.ref + "/",
            "accept": "*/*",
            "accept-language": "en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7",
            "cache-control": "no-cache",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "cross-site",
            "sec-ch-ua": '" Not A;Brand";v="99", "Chromium";v="100", "Microsoft Edge";v="100"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }
        hsx = dict(sorted(headers.items()))
        # print(hsx)
        if self.args.verbose:
            print("Headers:", json.dumps(headers))
        return hsx

    def psshgen(self):
        response2 = requests.get(
            self.mpd,
            headers={
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/99.0.4844.84 Safari/537.36",
            },
        ).text
        pssh = re.findall(r"pssh>(.*)</cenc", response2)[0]
        return pssh

    def iddetail(self):
        response = requests.get(
            f"https://dev.vdocipher.com/api/meta/{self.idx}",
            headers={
                "authority": "dev.vdocipher.com",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/99.0.4844.84 Safari/537.36",
            },
        ).json()
        mpd = response["dash"]["manifest"]
        title = response["title"]
        return mpd, title

    def generate_request_decrypt(self, license_response=None):
        if self.args.verbose:
            print("Generating License Request ")
        data = {
            "pssh": self.args.pssh,
            "buildInfo": self.args.buildinfo,
            "Challenge": True,
            "cache": self.args.cache,
        }

        if license_response:
            data["response"] = license_response
            data["license"] = self.args.license_url
            data["headers"] = self.headers
            data["cache"] = False
            data.pop("Challenge")

        # print(data)
        r = requests.post(self.api_url, json=data)
        #  print(r.text)
        r.raise_for_status()

        if "cached" in r.headers:
            print("\n\nCached:-> \n")
            print("\n".join([f'--key {key["key"]}' for key in r.json()["keys"]]))
            self.kid_key = " ".join([f'--key {key["key"]}' for key in r.json()["keys"]])
            return 0

        if self.args.verbose:
            print("License Request Generated ")
        if license_response:
            print("\n\nGenerated:-> \n")
            print("\n".join([f'--key {key["key"]}' for key in r.json()["keys"]]))
            self.kid_key = " ".join([f'--key {key["key"]}' for key in r.json()["keys"]])

        return r.content

    def check(self):
        try:
            payloads_token = json.loads(
                base64.b64decode(self.json_payloads["token"]).decode()
            )
        except Exception as error:
            raise Exception(f"Error Parsing JSON: {str(error)}")
        payloads_token["licenseRequest"] = "CAQ="
        change = base64.b64encode(str(json.dumps(payloads_token)).encode()).decode()
        self.json_payloads["token"] = change
        challenge = self.json_payloads
        r = requests.post(
            self.args.license_url, json=challenge, headers=self.headers, timeout=10
        )
        print(r.content)
        r.raise_for_status()

        if r.status_code == 200:
            if "license" in str(r.text):

                if args.verbose:
                    print("Token is okay!")
                return 1
        else:
            return 0

    def post_request(self, challenge):
        try:
            payloads_token = json.loads(
                base64.b64decode(self.json_payloads["token"]).decode()
            )
        except Exception as error:
            raise Exception(f"Error Parsing JSON: {str(error)}")
        payloads_token["licenseRequest"] = challenge.decode("utf-8")
        change = base64.b64encode(str(json.dumps(payloads_token)).encode()).decode()
        self.json_payloads["token"] = change
        challenge = self.json_payloads
        if args.verbose:
            print(f"Challenge:{json.dumps(challenge)}")

        r = requests.post(
            self.args.license_url, json=challenge, headers=self.headers, timeout=10
        )

        if r.status_code == 200:
            if args.verbose:
                print(f"Response:{json.dumps(r.text)}")
            return r.json()["license"]
        else:
            print(r.content)
            return 0

    def main(self):

        status = self.check()
        if status != 1:
            raise Exception("Token Expired")
        license_request = self.generate_request_decrypt()
        if license_request != 0:
            if args.verbose:
                print(f"Sending License URL Request")
            license_response = self.post_request(license_request)
            if license_response == 0:
                print("failed")
                return
            self.generate_request_decrypt(license_response)
            print("Mpd:-", self.mpd)
            print("Title:-", self.title)
        else:
            print("\nMpd:-", self.mpd)
            print("Title:-", self.title)
        open("keysdb.txt", "a+", encoding="utf-8").write(
            f"{self.title}*{self.mpd}*{self.kid_key}*{self.idx}\n"
        )


def ex_main(toke):
    parser = argparse.ArgumentParser()
    args = parser.parse_args()

    if len(sys.argv) == 1:
        args.auth = toke
        args.buildinfo = (
            "AZ1122aosp_kenzokenzo:7.1.2NZH542doveki08121232:userdebugtest-keys"
        )
        args.cache = True
        args.verbose = False

        start = VdoCipher(args)
        start.mainx()


if __name__ == "__main__":
    print(f"\n{' ' * 6}VdoCipher {version}\n{' ' * 7} from getwvkeys \n\n")

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-auth", help="auth token of vdocipher https://imgur.com/GqYXuV3"
    )
    parser.add_argument("--verbose", "-v", help="Debug", action="store_true")
    parser.add_argument(
        "--cache",
        "-c",
        help="Cache On. default is OFF",
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "--buildinfo",
        "-b",
        default="AZ1122aosp_kenzokenzo:7.1.2NZH542doveki08121232:userdebugtest-keys",
        help="Buildinfo",
        required=False,
    )
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        print()
        while args.auth is None:
            args.auth = input(" Enter Auth : ")
        args.buildinfo = (
            "AZ1122aosp_kenzokenzo:7.1.2NZH542doveki08121232:userdebugtest-keys"
        )
        args.cache = False
        args.verbose = False

    try:
        
        """
        : ) ^_^
        
        """
        start = VdoCipher(args)
        start.main()
    except Exception as e:
        raise

    input("\nDONE\n")
