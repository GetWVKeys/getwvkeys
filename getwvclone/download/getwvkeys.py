import argparse
import base64
import json
import sys

import requests

version = "4.0"


# Change your headers here
def headers():
    return {"content-length": "316", "Connection": "keep-alive", "accept": "*/*"}


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
class GetwvCloneApi:
    def __init__(self, arg) -> None:
        self.baseurl = "https://getwvkeys.cc"
        self.api_url = self.baseurl + "/pywidevine"
        self.args = arg
        self.args.headers = headers()

    def generate_request(self):
        if self.args.verbose:
            print("[+] Generating License Request ")
        data = {"pssh": self.args.pssh, "buildInfo": self.args.buildinfo, "cache": self.args.cache}
        header = {"X-API-Key": args.auth}
        r = requests.post(self.api_url, json=data, headers=header)
        if not r.ok:
            if "error" in r.text:
                # parse the response as a json error
                error = json.loads(r.text)
                print("[-] Failed to generate license request: [{}] {}".format(error.get("code"), error.get("message")))
                exit(1)
            print("[-] Failed to generate license request: [{}] {}".format(r.status_code, r.text))
            exit(1)

        if "cached" in r.headers:
            print(r.json())
            input("[+] Press Enter To Continue with request")
            self.args.cache = False
            return self.generate_request()
        if self.args.verbose:
            print("[+] License Request Generated ")

        return base64.b64decode(r.text).decode("ISO-8859-1")

    def decrypter(self, license_response):
        if self.args.verbose:
            print("[+] Decrypting with License Request and Response ")
        data = {"pssh": self.args.pssh, "response": license_response, "license_url": self.args.url, "headers": self.args.headers, "buildInfo": self.args.buildinfo, "cache": self.args.cache}
        header = {"X-API-Key": args.auth}
        r = requests.post(self.api_url, json=data, headers=header)
        if not r.ok:
            if "error" in r.text:
                # parse the response as a json error
                error = json.loads(r.text)
                print("[-] Failed to decrypt license: [{}] {}".format(error.get("code"), error.get("message")))
                exit(1)
            print("[-] Failed to decrypt license: [{}] {}".format(r.status_code, r.text))
            exit(1)
        return r.text

    def main(self):
        license_request = self.generate_request()
        if args.verbose:
            print("[+] Sending License URL Request")
        license_response = post_request(args, license_request)
        print("\n" + self.decrypter(base64.b64encode(license_response).decode()))


if __name__ == "__main__":
    print(f"\n{' ' * 6}pywidevine-api {version}\n{' ' * 7} from getwvkeys \n\n")

    parser = argparse.ArgumentParser()
    parser.add_argument("-url", help="LICENSE URL")
    parser.add_argument("-pssh", help="PSSH")
    parser.add_argument("-auth", help="Auth Key from getwvkeys.cc")
    parser.add_argument("--verbose", "-v", help="increase output verbosity", action="store_true")
    parser.add_argument("--cache", "-c", help="Cache On. default is OFF", default=False, action="store_true")
    parser.add_argument("--buildinfo", "-b", default="", help="Buildinfo", required=False)

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        print()
        while (args.url is None and args.pssh is None) or (args.url == "" and args.pssh == ""):
            args.url = input("Enter LICENSE URL:")
            args.pssh = input("Enter PSSH:")
            args.auth = input("Enter GetWVKeys API Key:")
        args.buildinfo = ""
        args.cache = True
        args.verbose = False

    try:
        start = GetwvCloneApi(args)
        start.main()
    except Exception as e:
        raise
