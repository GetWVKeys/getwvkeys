"""
 This file is part of the GetWVKeys project (https://github.com/GetWVKeys/getwvkeys)
 The code in this file has been adapted from: https://github.com/google/shaka-packager/blob/master/packager/tools/pssh/pssh-box.py

 Copyright (C) 2022 Notaghost, Puyodead1 and GetWVKeys contributors 
 
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
import struct

from getwvkeys.pywidevine.cdm.formats.widevine_pssh_data_pb2 import WidevinePsshData

WIDEVINE_SYSTEM_ID = base64.b16decode("EDEF8BA979D64ACEA3C827DCD51D21ED")


def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, "big")


def parse_pssh(pssh_b64):
    """Parses a PSSH box in base 64"""
    data = base64.b64decode(pssh_b64)
    reader = BinaryReader(data, little_endian=False)
    while reader.has_data():
        start = reader.position
        size = reader.read_int(4)
        box_type = reader.read_bytes(4)
        if box_type != b"pssh":
            raise Exception("Invalid box type 0x%s, not 'pssh'" % box_type.hex())
        version_and_flags = reader.read_int(4)
        version = version_and_flags >> 24
        if version > 1:
            raise Exception("Invalid pssh version %d" % version)

        system_id = reader.read_bytes(16)
        key_ids = []
        if version == 1:
            count = reader.read_int(4)
            while count > 0:
                key = reader.read_bytes(16)
                key_ids.append(key)
                count -= 1

        pssh_data_size = reader.read_int(4)
        pssh_data = reader.read_bytes(pssh_data_size)

        if start + size != reader.position:
            raise Exception("Box does not match size of data")

        pssh = Pssh(version, system_id, key_ids, pssh_data)
        return pssh


def _create_bin_int(value):
    """Creates a binary string as 4-byte array from the given integer."""
    return struct.pack(">i", value)


def _to_hex(data):
    return base64.b16encode(data).decode().lower()


def _create_uuid_from_hex(ret):
    """Creates a human readable UUID string from the given hex string."""
    return ret[:8] + "-" + ret[8:12] + "-" + ret[12:16] + "-" + ret[16:20] + "-" + ret[20:]


def _create_uuid(data):
    """Creates a human readable UUID string from the given binary string."""
    ret = base64.b16encode(data).decode().lower()
    return ret[:8] + "-" + ret[8:12] + "-" + ret[12:16] + "-" + ret[16:20] + "-" + ret[20:]


def _parse_widevine_data(data):
    """Parses Widevine PSSH box from the given binary string."""
    wv = WidevinePsshData()
    wv.ParseFromString(data)

    key_ids = []
    provider = None
    content_id = None
    policy = None
    crypto_index_period = None
    protection_scheme = None

    if wv.key_id:
        key_ids = wv.key_id

    if wv.HasField("provider"):
        provider = wv.provider
    if wv.HasField("content_id"):
        content_id = base64.b16encode(wv.content_id).decode()
    if wv.HasField("policy"):
        policy = wv.policy
    if wv.HasField("crypto_period_index"):
        crypto_index_period = wv.crypto_period_index
    if wv.HasField("protection_scheme"):
        protection_scheme = struct.pack(">L", wv.protection_scheme)

    return PsshData(key_ids, provider, content_id, policy, crypto_index_period, protection_scheme)


def _generate_widevine_data(key_ids, protection_scheme):
    """Generate widevine pssh data."""
    wv = WidevinePsshData()
    wv.key_id.extend(key_ids)
    # 'cenc' is the default, so omitted to save bytes.
    if protection_scheme:
        wv.protection_scheme = struct.unpack(">L", protection_scheme.encode())[0]
    return wv.SerializeToString()


class PsshData(object):
    def __init__(self, key_ids, provider, content_id, policy, crypto_period_index, protection_scheme):
        self.key_ids = [_to_hex(x) for x in key_ids]
        self.provider = provider
        self.content_id = content_id
        self.policy = policy
        self.crypto_period_index = crypto_period_index
        self.protection_scheme = protection_scheme

    def __repr__(self):
        lines = []
        try:
            extra = self.humanize()
            lines.extend(["      " + x for x in extra])
        # pylint: disable=broad-except
        except Exception as e:
            lines.append("      ERROR: " + str(e))

        return "\n".join(lines)

    def humanize(self):
        ret = []
        if self.key_ids:
            ret.append("Key IDs (%d):" % len(self.key_ids))
            ret.extend(["  " + _create_uuid_from_hex(x) for x in self.key_ids])

        if self.provider:
            ret.append("Provider: " + self.provider)
        if self.content_id:
            ret.append("Content ID: " + self.content_id)
        if self.policy:
            ret.append("Policy: " + self.policy)
        if self.crypto_period_index:
            ret.append("Crypto Period Index: %d" % self.crypto_period_index)
        if self.protection_scheme:
            ret.append("Protection Scheme: %s" % self.protection_scheme)

        return ret


class Pssh(object):
    """Defines a PSSH box and related functions."""

    def __init__(self, version, system_id, key_ids, pssh_data):
        """Parses a PSSH box from the given data.
        Args:
          version: The version number of the box
          system_id: A binary string of the System ID
          key_ids: An array of binary strings for the key IDs
          pssh_data: A binary string of the PSSH data
        """
        self.version = version
        self.system_id = system_id
        self.key_ids = key_ids or []
        self.pssh_data = pssh_data or b""
        self.data = _parse_widevine_data(self.pssh_data)

    def binary_string(self):
        """Converts the PSSH box to a binary string."""
        ret = b"pssh" + _create_bin_int(self.version << 24)
        ret += self.system_id
        if self.version == 1:
            ret += _create_bin_int(len(self.key_ids))
            for key in self.key_ids:
                ret += key
        ret += _create_bin_int(len(self.pssh_data))
        ret += self.pssh_data
        return _create_bin_int(len(ret) + 4) + ret

    def __repr__(self):
        """Converts the PSSH box to a human readable string."""
        system_name = ""
        convert_data = self.data.humanize
        if self.system_id == WIDEVINE_SYSTEM_ID:
            system_name = "Widevine"

        lines = ["PSSH Box v%d" % self.version, "  System ID: %s %s" % (system_name, _create_uuid(self.system_id))]
        if self.version == 1:
            lines.append("  Key IDs (%d):" % len(self.key_ids))
            lines.extend(["    " + _create_uuid(key) for key in self.key_ids])

        lines.append("  PSSH Data (size: %d):" % len(self.pssh_data))
        if self.pssh_data:
            if convert_data:
                lines.append("    " + system_name + " Data:")
                try:
                    extra = convert_data()
                    lines.extend(["      " + x for x in extra])
                # pylint: disable=broad-except
                except Exception as e:
                    lines.append("      ERROR: " + str(e))
            else:
                lines.extend(["    Raw Data (base64):", "      " + base64.b64encode(self.pssh_data).decode("utf8")])

        return "\n".join(lines)


class BinaryReader(object):
    """A helper class used to read binary data from an binary string."""

    def __init__(self, data, little_endian):
        self.data = data
        self.little_endian = little_endian
        self.position = 0

    def has_data(self):
        """Returns whether the reader has any data left to read."""
        return self.position < len(self.data)

    def read_bytes(self, count):
        """Reads the given number of bytes into an array."""
        if len(self.data) < self.position + count:
            raise Exception("Invalid PSSH box, not enough data")
        ret = self.data[self.position : self.position + count]
        self.position += count
        return ret

    def read_int(self, size):
        """Reads an integer of the given size (in bytes)."""
        data = self.read_bytes(size)
        ret = 0
        for i in range(0, size):
            if self.little_endian:
                ret |= data[i] << (8 * i)
            else:
                ret |= data[i] << (8 * (size - i - 1))
        return ret
