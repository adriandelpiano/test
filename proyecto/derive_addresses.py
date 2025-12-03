import os, sys, json, hashlib, hmac

BASE_DIR = os.path.dirname(__file__)
LIB_DIR = os.path.join(BASE_DIR, "lib")
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)
if LIB_DIR not in sys.path:
    sys.path.append(LIB_DIR)

from lib.metamask_verifier import derive_seed
from lib import keccak
from lib.secp256k1 import (
    privkey_to_pubkey_compressed,
    privkey_to_pubkey_uncompressed,
    N as SECP256K1_N,
)

def hmac_sha512(key, data):
    return hmac.new(key, data, hashlib.sha512).digest()

def derive_master_key(seed: bytes):
    I = hmac_sha512(b"Bitcoin seed", seed)
    master_priv = I[:32]
    chain_code = I[32:]
    return master_priv, chain_code

def derive_child_key_nh(parent_priv: bytes, parent_chain: bytes, index: int):
    parent_pub_compressed = privkey_to_pubkey_compressed(parent_priv)
    data = parent_pub_compressed + index.to_bytes(4, "big")
    I = hmac_sha512(parent_chain, data)
    IL, IR = I[:32], I[32:]
    child_int = (int.from_bytes(IL, "big") + int.from_bytes(parent_priv, "big")) % SECP256K1_N
    child_priv = child_int.to_bytes(32, "big")
    return child_priv, IR

def priv_to_pubkey(privkey_bytes: bytes, compressed: bool = True) -> bytes:
    return (
        privkey_to_pubkey_compressed(privkey_bytes)
        if compressed
        else privkey_to_pubkey_uncompressed(privkey_bytes)
    )

def pubkey_to_eth_address(pubkey_uncompressed: bytes) -> str:
    if not (len(pubkey_uncompressed) == 65 and pubkey_uncompressed[0] == 0x04):
        raise ValueError("Se requiere clave pública no comprimida (65 bytes, prefijo 0x04) para ETH.")
    uncompressed_xy = pubkey_uncompressed[1:]
    addr = keccak.keccak256(uncompressed_xy)[-20:]
    return "0x" + addr.hex()

def pubkey_to_btc_address(pubkey_compressed: bytes) -> str:
    sha = hashlib.sha256(pubkey_compressed).digest()
    ripe = hashlib.new("ripemd160", sha).digest()
    ver_payload = b"\x00" + ripe
    checksum = hashlib.sha256(hashlib.sha256(ver_payload).digest()).digest()[:4]
    addr_bytes = ver_payload + checksum
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(addr_bytes, "big")
    out = ""
    while num > 0:
        num, rem = divmod(num, 58)
        out = alphabet[rem] + out
    pad = 0
    for b in addr_bytes:
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + out

def process_phrases(phrases):
    results = []
    for phrase in phrases:
        seed = derive_seed(phrase)
        master_priv, chain = derive_master_key(seed)
        child_priv, child_chain = derive_child_key_nh(master_priv, chain, 0)
        pubkey_compressed = priv_to_pubkey(child_priv, compressed=True)
        pubkey_uncompressed = priv_to_pubkey(child_priv, compressed=False)
        eth_addr = pubkey_to_eth_address(pubkey_uncompressed)
        btc_addr = pubkey_to_btc_address(pubkey_compressed)
        results.append({
            "mnemonic": phrase,
            "eth_address": eth_addr,
            "btc_address": btc_addr
        })
    return results

def main():
    print("Seleccione una opción:")
    print("1) Agregar nuevas semillas y derivar direcciones")
    print("2) Usar archivo existente valid_seeds.json")
    choice = input("> ").strip()

    if choice == "1":
        phrases = []
        print("Ingrese frases semilla (12 palabras cada una). Escriba 'fin' para terminar:")
        while True:
            line = input("> ").strip()
            if line.lower() == "fin":
                break
            if line:
                phrases.append(line)
        results = process_phrases(phrases)
    else:
        input_path = os.path.join(BASE_DIR, "valid_seeds.json")
        with open(input_path, "r", encoding="utf-8") as f:
            phrases = json.load(f)
        results = process_phrases(phrases)

    output_path = os.path.join(BASE_DIR, "derived_addresses.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"✅ Se derivaron direcciones ETH y BTC de {len(results)} frases en {output_path}")

if __name__ == "__main__":
    main()
