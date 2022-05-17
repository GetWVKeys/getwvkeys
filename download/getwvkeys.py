import argparse
import base64
import sys

import requests

version = "2.0"


# Change your headers here
def headers():
    return {
        "content-length": "316",
        "Connection": "keep-alive",
        "accept": "*/*"
    }


# CHANGE THIS FUNCTION TO PARSE LICENSE URL RESPONSE
def post_request(arg, challenge):
    r = requests.post(arg.url, headers=arg.headers, data=challenge, timeout=10)
    if arg.verbose:
        print(f"License Response:\n{r.text}")
    r.raise_for_status()
    return r.content


# Do Not Change Anything in this class
class GetwvCloneApi:
    def __init__(self, arg) -> None:
        self.baseurl = "http://getwvkeys.cc/"
        self.api_url = self.baseurl + "/pywidevine"
        self.args = arg
        self.args.headers = headers()

    def generate_request(self):
        if self.args.verbose:
            print("Generating License Request ")
        data = {

            "pssh": self.args.pssh,
            "buildInfo": self.args.buildinfo,
            "Challenge": True,
            "cache": self.args.cache
        }
        r = requests.post(self.api_url, json=data)
        r.raise_for_status()

        if 'cached' in r.headers:
            print(r.json())
            input('Press Enter To Continue with request')
            self.args.cache = False
            self.generate_request()
        if self.args.verbose:
            print("License Request Generated ")

        return base64.b64decode(r.text).decode('ISO-8859-1')

    def decrypter(self, license_response):
        if self.args.verbose:
            print("Decrypting with License Request and Response ")
        data = {

            "pssh": self.args.pssh,
            "response": license_response,
            "license": self.args.url,
            "headers": self.args.headers,
            "buildInfo": self.args.buildinfo
        }
        r = requests.post(self.api_url, json=data)
        r.raise_for_status()
        return r.text

    def main(self):
        license_request = self.generate_request()
        if args.verbose:
            print(f"Sending License URL Request")
        license_response = post_request(args, license_request)
        print("\n" + self.decrypter(base64.b64encode(license_response).decode()))


if __name__ == "__main__":
    print(f"\n{' ' * 6}pywidevine-api {version}\n{' ' * 7} from getwvkeys \n\n")

    parser = argparse.ArgumentParser()
    parser.add_argument('-url', help='LICENSE URL')
    parser.add_argument('-pssh', help='PSSH')
    parser.add_argument('--verbose', "-v", help="increase output verbosity", action="store_true")
    parser.add_argument("--cache", "-c", help="Cache On. default is OFF", default=False, action="store_true")
    parser.add_argument('--buildinfo', '-b', default="", help='Buildinfo', required=False)

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        print()
        while (args.url is None and args.pssh is None) or (args.url == "" and args.pssh == ""):
            args.url = input('Enter LICENSE URL:')
            args.pssh = input('Enter PSSH:')
        args.buildinfo = ""
        args.cache = True
        args.verbose = False

    try:
        start = GetwvCloneApi(args)
        start.main()
    except Exception as e:
        raise

    input("\nDONE\n")
