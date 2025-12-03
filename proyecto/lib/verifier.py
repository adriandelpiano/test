import os
import hashlib
from typing import List, Dict, Any, Tuple

# Rutas por defecto
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
LIB_DIR = os.path.join(BASE_DIR, "lib")
WORDLIST_PATH = os.path.join(LIB_DIR, "wordlist_english_clean.txt")

# Intentar importar librerías locales si existen
mnemonic_mod = None
bip39seed_mod = None
try:
    from . import mnemonic as mnemonic_mod  # usa tu lib local
except Exception:
    mnemonic_mod = None
try:
    from . import bip39seed as bip39seed_mod  # usa tu lib local
except Exception:
    bip39seed_mod = None

# Parámetros BIP39
VALID_WORD_COUNTS = {12, 15, 18, 21, 24}
ENTROPY_BITS_BY_COUNT = {
    12: 128,
    15: 160,
    18: 192,
    21: 224,
    24: 256,
}

def load_wordlist(path: str = WORDLIST_PATH) -> List[str]:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"No se encontró el wordlist: {path}")
    words = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            w = line.strip()
            if not w:
                continue
            words.append(w)
    if len(words) != 2048:
        raise ValueError(f"Wordlist inválida: se esperaban 2048 palabras, hay {len(words)}")
    if len(set(words)) != 2048:
        raise ValueError("Wordlist contiene duplicados.")
    return words

def words_to_indices(words: List[str], wordlist: List[str]) -> List[int]:
    idx_map = {w: i for i, w in enumerate(wordlist)}
    indices = []
    invalid = []
    for w in words:
        if w not in idx_map:
            invalid.append(w)
        else:
            indices.append(idx_map[w])
    if invalid:
        raise ValueError(f"Palabras fuera de la wordlist: {invalid}")
    return indices

def indices_to_bitstring(indices: List[int]) -> str:
    # 11 bits por palabra, big-endian por palabra
    return "".join(format(i, "011b") for i in indices)

def split_entropy_and_checksum(bitstr: str, word_count: int) -> Tuple[str, str]:
    if word_count not in VALID_WORD_COUNTS:
        raise ValueError(f"Cantidad de palabras inválida: {word_count}")
    entropy_bits = ENTROPY_BITS_BY_COUNT[word_count]
    checksum_bits = entropy_bits // 32
    total_bits_expected = entropy_bits + checksum_bits
    if len(bitstr) != word_count * 11:
        raise ValueError("Longitud total de bits no coincide con N*11.")
    if total_bits_expected != len(bitstr):
        # Esta condición se cumple para mnemónicas válidas BIP39
        # Si no coincide, la mnemónica no está bien formada respecto a entropía+checksum
        raise ValueError("La combinación entropía+checksum no coincide con N*11 bits.")
    ent_bits = bitstr[:entropy_bits]
    chk_bits = bitstr[entropy_bits:entropy_bits + checksum_bits]
    return ent_bits, chk_bits

def bits_to_bytes(bitstr: str) -> bytes:
    if len(bitstr) % 8 != 0:
        # BIP39 garantiza entropía múltiplo de 8; si no lo es, algo está mal
        raise ValueError("La entropía no es múltiplo de 8 bits.")
    return int(bitstr, 2).to_bytes(len(bitstr) // 8, "big")

def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def checksum_bits_from_entropy(entropy_bytes: bytes, checksum_len_bits: int) -> str:
    h = sha256_bytes(entropy_bytes)
    h_bits = "".join(format(b, "08b") for b in h)
    return h_bits[:checksum_len_bits]

def derive_seed_pbkdf2(mnemonic: str, passphrase: str = "") -> bytes:
    """
    Deriva la semilla con PBKDF2-HMAC-SHA512 como define BIP39.
    Salt = 'mnemonic' + passphrase
    Iteraciones = 2048
    """
    salt = ("mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), salt, 2048, dklen=64)

def try_lib_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """
    Intenta derivar semilla usando tu librería local (bip39seed.py).
    Si no está disponible, usa PBKDF2 estándar (fallback).
    """
    if bip39seed_mod and hasattr(bip39seed_mod, "mnemonic_to_seed"):
        return bip39seed_mod.mnemonic_to_seed(mnemonic, passphrase=passphrase)
    elif bip39seed_mod and hasattr(bip39seed_mod, "to_seed"):
        return bip39seed_mod.to_seed(mnemonic, passphrase=passphrase)
    else:
        return derive_seed_pbkdf2(mnemonic, passphrase=passphrase)

def validate_mnemonic_full(phrase: str, wordlist_path: str = WORDLIST_PATH, passphrase: str = "") -> Dict[str, Any]:
    """
    Verificación completa:
    - Longitud válida (12/15/18/21/24)
    - Todas las palabras en la wordlist (2048)
    - Entropía múltiplo de 32 bits y bytes correctos
    - Checksum BIP39 correcto
    - Derivación de semilla (PBKDF2 / librería local)
    Retorna dict con resultados y detalles.
    """
    # Normalización básica
    cleaned = " ".join(phrase.strip().lower().split())
    words = cleaned.split()

    result: Dict[str, Any] = {
        "normalized": cleaned,
        "word_count": len(words),
        "length_valid": False,
        "wordlist_ok": False,
        "entropy_bits": None,
        "checksum_bits": None,
        "bitstring_len": None,
        "entropy_bytes_len": None,
        "checksum_valid": False,
        "seed_sha256": None,
        "seed_sha512": None,
        "errors": []
    }

    # 1) Longitud
    n = len(words)
    if n in VALID_WORD_COUNTS:
        result["length_valid"] = True
    else:
        result["errors"].append(f"Cantidad de palabras inválida: {n}.")
        return result  # No seguir si la longitud es inválida

    # 2) Cargar wordlist y mapear palabras a índices
    try:
        wl = load_wordlist(wordlist_path)
        indices = words_to_indices(words, wl)
        result["wordlist_ok"] = True
    except Exception as e:
        result["errors"].append(str(e))
        return result

    # 3) Construir flujo de bits
    bitstr = indices_to_bitstring(indices)
    result["bitstring_len"] = len(bitstr)

    # 4) Separar entropía y checksum y validar tamaños
    try:
        entropy_bits_len = ENTROPY_BITS_BY_COUNT[n]
        checksum_bits_len = entropy_bits_len // 32
        result["entropy_bits"] = entropy_bits_len
        result["checksum_bits"] = checksum_bits_len

        ent_bits, chk_bits = split_entropy_and_checksum(bitstr, n)
    except Exception as e:
        result["errors"].append(str(e))
        return result

    # 5) Entropía a bytes (múltiplo de 8)
    try:
        entropy_bytes = bits_to_bytes(ent_bits)
        result["entropy_bytes_len"] = len(entropy_bytes)
    except Exception as e:
        result["errors"].append(str(e))
        return result

    # 6) Calcular y comparar checksum
    expected_chk = checksum_bits_from_entropy(entropy_bytes, checksum_bits_len)
    if chk_bits == expected_chk:
        result["checksum_valid"] = True
    else:
        result["errors"].append("Checksum inválido: no coincide con SHA-256 de la entropía.")
        return result

    # 7) Derivación de semilla (offline)
    try:
        seed = try_lib_seed(cleaned, passphrase=passphrase)
        result["seed_sha256"] = hashlib.sha256(seed).hexdigest()
        result["seed_sha512"] = hashlib.sha512(seed).hexdigest()
    except Exception as e:
        result["errors"].append(f"Derivación de semilla fallida: {e}")

    return result
