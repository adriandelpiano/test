# BIP39: convertir mnemónico en seed binaria con PBKDF2-HMAC-SHA512

from .biputils import pbkdf2_sha512

class Bip39SeedGenerator:
    def __init__(self, mnemonic: str):
        self.mnemonic = mnemonic

    def Generate(self, passphrase: str = "") -> bytes:
        # salt = "mnemonic" + passphrase
        salt = ("mnemonic" + passphrase).encode("utf-8")
        return pbkdf2_sha512(self.mnemonic.encode("utf-8"), salt, iterations=2048, dklen=64)
