import base64
import json
import uncurl
import requests
import argparse
import sys
import re
from urllib.parse import urlparse

version = "2.0"


# Do Not Change Anything in this class
class Channel4:

    def __init__(self, arg) -> None:
        self.args = arg
        self.parsecul_ = self.parsecurl()
        if self.parsecul_ == 0:
            return
        self.headers, self.license_url, self.data, self.cookie = self.parsecul_
        self.mpd = self.data['video']['url']
        self.baseurl = "http://getwvkeys.cc/"
        self.api_url = self.baseurl + "/pywidevine"
        self.args.pssh, self.kid = self.psshgen()

    def psshcheck(self):
        r = requests.post(self.baseurl + 'findpssh', data=self.kid)
        try:
            pp = (re.findall(r'\>(.*)\<\/li\>', r.text))
            if len(pp) > 0:
                print('\nCached:-> ')
                print('--key', pp[0])

                return 0
        except:
            print(r.text)
        return 1

    def psshgen(self):
        a = self.mpd.split('/stream.mpd')[0]
        b = '/dash/' + a.split('/')[-1].replace('.ism',
                                                '') + '-audio=128000.dash'
        c = a + b
        d = requests.get(c, stream=True)
        if d.status_code == 200 or d.status_code == 206:
            for z in d.iter_content(chunk_size=4096):
                # print(z)
                g = z.rfind(
                    b"\xED\xEF\x8B\xA9\x79\xD6\x4A\xCE\xA3\xC8\x27\xDC\xD5\x1D\x21\xED"
                )

                e = g - 12
                f = int.from_bytes(z[e:e + 4], 'big')
                # print(f)
                h = z[e:e + f]
                if g == -1:
                    h = z[0:0]
                y = z.rfind(b'tenc')
                x = int.from_bytes(z[y - 4:y], 'big')
                w = z[y - 4:y - 4 + x][-16:].hex()

                i = base64.b64encode(h).decode("utf-8")
                print(i, '\n', w)
                return i, w

    def parsecurl(self):
        try:

            ab = []
            print("Enter license Curl")
            while True:

                aa = input()

                if (len(aa) > 0 and aa[-1] == "\\"):
                    ab.append(aa[0:-2])
                    continue

                ab.append(aa)
                if (aa == "  " or "--compressed" in aa):
                    break

            ac = "\n".join(ab)
            p_data = uncurl.parse_context(ac)
            #  print(p_data.data)
            header = dict(p_data.headers)
            try:
                data = (dict(p_data.data) if (p_data.data) != None else None)
            except:
                try:
                    data = eval(p_data.data)
                except:
                    pass

            url = p_data.url
            cookie = (dict(p_data.cookies) if
                      (p_data.cookies) != None else None)
            return (
                header,
                url,
                data,
                cookie,
            )
        except:
            return 0

    def generate_request_decrypt(self, license_response=None):

        data = {
            "pssh": self.args.pssh,
            "buildInfo": self.args.buildinfo,
            "Challenge": True,
            "cache": False
        }

        if license_response:
            data['response'] = license_response
            data['license'] = self.license_url
            data['headers'] = self.headers
            data['cache'] = False
            data.pop('Challenge')

        # print(data)
        r = requests.post(self.api_url, json=data)
        # print(r.text)
        r.raise_for_status()

        if 'cached' in r.headers:
            print('\nCached:-> \n')
            try:
                print('\n'.join(
                    [f'--key {key["key"]}' for key in r.json()['keys']]))
            except:
                print(r.json())
            return 0

        if self.args.verbose:
            print("License Request Generated ")
        if license_response:
            print('Generated:-> \n')
            print('\n'.join(
                [f'--key {key["key"]}' for key in r.json()['keys']]))

        return r.content

    def check(self):

        r = requests.post(self.license_url,
                          json=self.data,
                          headers=self.headers,
                          timeout=10)
        # print(r.content)
        r.raise_for_status()

        if r.status_code == 200:
            if "license" in str(r.text):
                if args.verbose:
                    print("Token is okay!")
                return 1
        else:
            return 0

    def post_request(self, challenge):
        self.data['message'] = challenge.decode('utf-8')
        challenge = self.data
        # print(challenge)

        r = requests.post(self.license_url,
                          json=challenge,
                          headers=self.headers,
                          timeout=10)

        if r.status_code == 200:
            if args.verbose:
                print(f"Response:{json.dumps(r.text)}")
            return r.json()["license"]
        else:
            print(r.content)
            return 0

    def main(self):
        checkpssh = self.psshcheck()
        if checkpssh == 0:
            print("\nMpd:-", self.mpd)
            return

        status = self.check()
        if status != 1:
            raise Exception("Token Expired")
        license_request = self.generate_request_decrypt()
        # print(license_request)
        if license_request != 0:
            if args.verbose:
                print(f"Sending License URL Request")
            license_response = self.post_request(license_request)
            if license_response == 0:
                print("failed")
                return
            self.generate_request_decrypt(license_response)
            print("\nMpd:-", self.mpd)

        else:
            print("\nMpd:-", self.mpd)


if __name__ == "__main__":
    print(f"\n{' ' * 6}Channel4 {version}\n{' ' * 7} from getwvkeys \n\n")

    parser = argparse.ArgumentParser()

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
        default=
        "AZ1122aosp_kenzokenzo:7.1.2NZH541doveki08121232:userdebugtest-keys",
        help="Buildinfo",
        required=False,
    )
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        print()

        args.buildinfo = (
            "AZ1122aosp_kenzokenzo:7.1.2NZH541doveki08121232:userdebugtest-keys"
        )
        args.cache = True
        args.verbose = False

    try:

        start = Channel4(args)
        start.main()
    except Exception as e:
        raise

    input("\nDONE\n")
