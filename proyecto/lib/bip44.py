# BIP44: derivación HD y dirección Ethereum usando secp256k1 + Keccak-256 (manual).
# - Métodos inmutables (evitan mutación del nodo al encadenar).
# - Extracción robusta de clave privada (32 bytes big-endian).
# - Dirección Ethereum: keccak256(X||Y) y últimos 20 bytes.

from .bip32 import BIP32Node
from .secp256k1 import privkey_to_pubkey_uncompressed
from .keccak import keccak256

def _extract_priv_bytes(node: BIP32Node) -> bytes:
    if hasattr(node, "k") and isinstance(node.k, int):
        return node.k.to_bytes(32, "big")
    if hasattr(node, "privkey") and isinstance(node.privkey, int):
        return node.privkey.to_bytes(32, "big")
    if hasattr(node, "privkey") and isinstance(node.privkey, (bytes, bytearray)):
        b = bytes(node.privkey)
        return b if len(b) == 32 else int.from_bytes(b, "big").to_bytes(32, "big")
    if hasattr(node, "privkey_bytes") and isinstance(node.privkey_bytes, (bytes, bytearray)):
        b = bytes(node.privkey_bytes)
        return b if len(b) == 32 else int.from_bytes(b, "big").to_bytes(32, "big")
    raise ValueError("No se pudo extraer la clave privada del nodo BIP32 en 32 bytes")

class _KeyRaw:
    def __init__(self, b: bytes):
        self._b = b
    def ToHex(self) -> str:
        return self._b.hex()

class _PrivateKey:
    def __init__(self, privkey_bytes: bytes):
        self._priv = privkey_bytes
    def Raw(self) -> _KeyRaw:
        return _KeyRaw(self._priv)

class _PublicKey:
    def __init__(self, privkey_bytes: bytes):
        self._priv = privkey_bytes
    def ToAddress(self) -> str:
        pub = privkey_to_pubkey_uncompressed(self._priv)  # 65 bytes: 0x04 + X + Y
        addr = keccak256(pub[1:])[-20:]  # Ethereum: hash de X||Y (sin 0x04), últimos 20 bytes
        return "0x" + addr.hex()

class _Node:
    def __init__(self, node: BIP32Node, coin_def: dict):
        self._node = node
        self._coin = coin_def

    def PrivateKey(self) -> _PrivateKey:
        return _PrivateKey(_extract_priv_bytes(self._node))

    def PublicKey(self) -> _PublicKey:
        return _PublicKey(_extract_priv_bytes(self._node))

    def Purpose(self):
        child = self._node.ckd_priv(self._coin["purpose"], hardened=True)
        return _Node(child, self._coin)

    def Coin(self):
        child = self._node.ckd_priv(self._coin["coin_type"], hardened=True)
        return _Node(child, self._coin)

    def Account(self, index: int):
        child = self._node.ckd_priv(index, hardened=True)
        return _Node(child, self._coin)

    def Change(self, change: int):
        child = self._node.ckd_priv(change, hardened=False)
        return _Node(child, self._coin)

    def AddressIndex(self, index: int):
        child = self._node.ckd_priv(index, hardened=False)
        return _Node(child, self._coin)

    def DerivePath(self, account: int, change: int, index: int):
        n = self._node.ckd_priv(self._coin["purpose"], hardened=True)
        n = n.ckd_priv(self._coin["coin_type"], hardened=True)
        n = n.ckd_priv(account, hardened=True)
        n = n.ckd_priv(change, hardened=False)
        n = n.ckd_priv(index, hardened=False)
        return _Node(n, self._coin)

class Bip44:
    @staticmethod
    def FromSeed(seed_bytes: bytes, coin_def: dict) -> _Node:
        master = BIP32Node.master_from_seed(seed_bytes)
        return _Node(master, coin_def)
