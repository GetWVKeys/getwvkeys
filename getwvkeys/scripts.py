import base64
import json
from pathlib import Path
from typing import List

import click
from pywidevine import Device, DeviceTypes
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from getwvkeys import config
from getwvkeys.models.Device import generate_device_code
from getwvkeys.utils import get_blob_id

engine = create_engine(config.SQLALCHEMY_DATABASE_URI)
session = Session(engine)


@click.group()
def cli():
    pass


# seed system devices, requires migration f194cc3e699f
@cli.command()
@click.argument("folder", type=click.Path(exists=True, file_okay=False, dir_okay=True, readable=True))
def seed_devices(folder: click.Path):
    cfg_out = []

    system_user = session.execute(text("SELECT * FROM users WHERE id = '0000000000000000000';")).first()
    if system_user is None:
        raise Exception("Cannot find system user, please run the alembic migration f194cc3e699f")
    else:
        print("Found system user")

    # check for a manifest in the folder
    manifest_path = Path(folder) / "manifest.json"
    if not manifest_path.exists():
        print("ERR: Missing manifest.json")
        exit(1)

    # load the manifest
    with open(manifest_path, "r") as f:
        manifest: List[List[str]] = json.load(f)
        for device in manifest:
            client_id = device[0]
            private_key = device[1]

            client_id_blob = open(Path(folder) / client_id, "rb").read()
            device_private_key = open(Path(folder) / private_key, "r").read()

            client_id_b64 = base64.b64encode(client_id_blob).decode()
            private_key_b64 = base64.b64encode(device_private_key.encode()).decode()

            code = generate_device_code(client_id_b64, private_key_b64)

            # check if device is already in the database
            device_exists = session.execute(text("SELECT * FROM devices WHERE code = :code;"), {"code": code}).first()
            if device_exists is not None:
                print(f"Device {code} already exists")
                cfg_out.append(code)
            else:
                info = get_blob_id(client_id_b64)
                wvd = Device(
                    type_=DeviceTypes.ANDROID,
                    security_level=3,  # TODO: let user specify?
                    flags=None,
                    private_key=device_private_key,
                    client_id=client_id_blob,
                )

                # insert
                result = session.execute(
                    text(
                        "INSERT INTO devices (code, wvd, uploaded_by, info) VALUES (:code, :wvd, :uploaded_by, :info);"
                    ),
                    {
                        "code": code,
                        "wvd": base64.b64encode(wvd.dumps()).decode(),
                        "uploaded_by": system_user.id,
                        "info": info,
                    },
                )

                if result.rowcount == 1:
                    print(f"Device {code} created")
                    cfg_out.append(code)
                else:
                    print(f"ERR: Failed to create device {code}")

    session.commit()

    # close
    session.close()
    engine.dispose()

    # print json array
    print(json.dumps(cfg_out, indent=4))


def main():
    cli()
