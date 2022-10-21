import binascii


class Key:
    def __init__(self, kid, type, key, permissions=None):
        self.kid = kid
        self.type = type
        self.key = key
        self.permissions = permissions or []

    def __repr__(self):
        if self.type == "OPERATOR_SESSION":
            return "key(kid={}, type={}, key={}, permissions={})".format(self.kid, self.type, binascii.hexlify(self.key), self.permissions)
        else:
            return "key(kid={}, type={}, key={})".format(self.kid, self.type, binascii.hexlify(self.key))
