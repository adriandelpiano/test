# Utilidades criptográficas y de serialización
# Usadas por BIP39, BIP32 y BIP44

import hashlib
import hmac
from typing import Tuple

# PBKDF2-HMAC-SHA512 (BIP39)
def pbkdf2_sha512(password: bytes, salt: bytes, iterations: int = 2048, dklen: int = 64) -> bytes:
    return hashlib.pbkdf2_hmac("sha512", password, salt, iterations, dklen=dklen)

# HMAC-SHA512 (BIP32 CKD)
def hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def ripemd160(data: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(data)
    return h.digest()

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")

def int_to_bytes(i: int, length: int) -> bytes:
    return i.to_bytes(length, "big")

# Base58 (para formatos Bitcoin; no usado en Ethereum)
_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def base58_encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    res = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        res.append(_ALPHABET[r])
    # manejo de ceros a la izquierda
    pad = 0
    for c in b:
        if c == 0:
            pad += 1
        else:
            break
    return (b"1" * pad + res[::-1]).decode("ascii")

# Keccak-256 (para direcciones Ethereum) via sha3_256
# Nota: Python hashlib expone sha3_256 (FIPS SHA-3), cercano a keccak-256 para propósitos de test.
def keccak256(data: bytes) -> bytes:
    # Para test: usar hashlib.sha3_256 (no exactamente igual a keccak-256),
    # suficiente para flujo interno de validación.
    return hashlib.sha3_256(data).digest()

# Secp256k1 operaciones mínimas: placeholder
# Para TEST robusto, usamos un esquema simplificado de "punto público"
# basado en hashing; no debe usarse para producción.
def pubkey_from_privkey(privkey32: bytes) -> bytes:
    # Placeholder de prueba: NO es curva secp256k1 real.
    # Producción requeriría elíptica real (secp256k1) para firmas/direcciones.
    return sha256(privkey32)  # 32 bytes
