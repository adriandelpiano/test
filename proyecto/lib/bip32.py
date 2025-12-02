# Implementación manual de BIP32 (solo rama privada: CKDpriv)
# Compatible con MetaMask cuando se usa con BIP44 y secp256k1 + Keccak correctos.

import hmac, hashlib
from typing import Tuple
from .secp256k1 import N, G, scalar_mult

# Helpers de serialización
def ser256(x: int) -> bytes:
    return x.to_bytes(32, "big")

def ser32(i: int) -> bytes:
    return i.to_bytes(4, "big")

def serP_compressed(point: Tuple[int,int]) -> bytes:
    x, y = point
    prefix = 0x02 if (y % 2 == 0) else 0x03
    return bytes([prefix]) + x.to_bytes(32, "big")

def hash160(b: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()

class BIP32Node:
    def __init__(self, privkey: int, chaincode: bytes):
        self.k = privkey            # entero privado
        self.chaincode = chaincode  # 32 bytes
        self.privkey = ser256(privkey)  # cache en bytes

    @staticmethod
    def master_from_seed(seed: bytes) -> 'BIP32Node':
        I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        IL, IR = I[:32], I[32:]
        k = int.from_bytes(IL, "big")
        if k == 0 or k >= N:
            raise ValueError("Master key fuera de rango")
        return BIP32Node(k, IR)

    def ckd_priv(self, index: int, hardened: bool) -> 'BIP32Node':
        if hardened:
            data = b"\x00" + ser256(self.k) + ser32(index | 0x80000000)
        else:
            # usar pubkey comprimido del padre
            Px, Py = scalar_mult(self.k, G)
            data = serP_compressed((Px, Py)) + ser32(index)
        I = hmac.new(self.chaincode, data, hashlib.sha512).digest()
        IL, IR = I[:32], I[32:]
        child_k = (int.from_bytes(IL, "big") + self.k) % N
        if child_k == 0:
            raise ValueError("Child key inválida (zero)")
        return BIP32Node(child_k, IR)
