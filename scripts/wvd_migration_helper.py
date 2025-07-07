import base64
import hashlib

from pywidevine import Device, DeviceTypes
from sqlalchemy import create_engine, text

engine = create_engine(
    "mariadb+mariadbconnector://getwvkeys:getwvkeys@localhost/getwvkeys"
)


cdms = [
    "Android/sdk_phone_x86_64/generic_x86_64:10/QSR1.210820.001/7663313:userdebug/test-keys",
]

hashes = []


with engine.connect() as conn:
    for x in cdms:
        result = conn.execute(
            text("SELECT * FROM cdms WHERE code = :code"), {"code": x}
        )
        row = result.first()
        if row:
            id, typ, level, client_id, private_key, code, uploaded_by = row
            # convert to wvd
            wvd = Device(
                type_=DeviceTypes.ANDROID,
                security_level=3,
                flags=None,
                private_key=base64.b64decode(private_key),
                client_id=base64.b64decode(client_id),
            )

            wvd_raw = wvd.dumps()
            wvd_hash = hashlib.sha256(wvd_raw).hexdigest()
            wvd_b64 = base64.b64encode(wvd_raw).decode()

            hashes.append(wvd_hash)

# print a json style array of the hashes
print("[")
for i, h in enumerate(hashes):
    if i > 0:
        print(",")
    print(f'"{h}"', end="")
print("\n]")
