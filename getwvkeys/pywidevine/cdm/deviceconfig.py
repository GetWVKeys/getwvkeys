class DeviceConfig:
    def __init__(self, library, code):
        if not code or code == "":
            raise Exception("No device selected.")
        loaded = library.device_selector(code)

        if loaded is not None:
            self.device_private_key_filename = loaded["device_private_key"]
            self.device_client_id_blob_filename = loaded["client_id_blob_filename"]
            self.private_key_available = True
            self.vmp = False
            self.send_key_control_nonce = True
        else:
            raise Exception("Invalid Device Key ID. Either leave it empty or use a valid identifier.")

    def __repr__(self):
        return "DeviceConfig(private_key_available={}, vmp={})".format(
            self.private_key_available,
            self.vmp,
        )


class DeviceConfig2:
    def __init__(self, private_key, blob):
        self.device_private_key_filename = private_key
        self.device_client_id_blob_filename = blob
        self.private_key_available = True
        self.vmp = False
        self.send_key_control_nonce = True

    def __repr__(self):
        return "DeviceConfig(private_key_available={}, vmp={})".format(
            self.private_key_available,
            self.vmp,
        )
