class DeviceConfig:
    def __init__(self, library, device):
        if not device or device == "":
            raise Exception("No CDM selected.")
        loaded = library.cdm_selector(device)

        if loaded is not None:
            self.device_name = "asd"
            self.description = "asd"
            self.security_level = loaded["security_level"]
            self.session_id_type = loaded["session_id_type"]
            self.device_private_key_filename = loaded["device_private_key"]
            self.device_client_id_blob_filename = loaded["client_id_blob_filename"]
            self.private_key_available = True
            self.vmp = False
            self.send_key_control_nonce = True
        else:
            raise Exception(f"NO CDM ASSOSIATED WITH THIS ID FOUND IN OUR " f"SYSTEM EITHER LEAVE IT EMPTY OR UPLOAD THIS CDM FIRST")

    def __repr__(self):
        return "DeviceConfig(name={}, description={}, security_level={}, session_id_type={}," " private_key_available={}, vmp={})".format(
            self.device_name, self.description, self.security_level, self.session_id_type, self.private_key_available, self.vmp
        )


class DeviceConfig2:
    def __init__(self, private_key, blob):
        self.device_name = "asd"
        self.description = "asd"
        self.security_level = "3"
        self.session_id_type = "android"
        self.device_private_key_filename = private_key
        self.device_client_id_blob_filename = blob
        self.private_key_available = True
        self.vmp = False
        self.send_key_control_nonce = True

    def __repr__(self):
        return "DeviceConfig(name={}, description={}, security_level={}, session_id_type={}," " private_key_available={}, vmp={})".format(
            self.device_name, self.description, self.security_level, self.session_id_type, self.private_key_available, self.vmp
        )
