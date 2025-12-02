#!/usr/bin/env python3
# Flujo robusto de prueba: BIP39 + BIP32 + BIP44 (solo testnet)
# No usar para fondos reales.

import os

def ensure_dirs():
    base = "proyecto"
    lib = os.path.join(base, "lib")
    if not os.path.exists(base):
        os.makedirs(base)
        print(f"[INFO] Carpeta creada: {base}")
    if not os.path.exists(lib):
        os.makedirs(lib)
        print(f"[INFO] Carpeta creada: {lib}")

ensure_dirs()

from lib.mnemonic import Mnemonic
from lib.bip39seed import Bip39SeedGenerator
from lib.bip44coin import Bip44Coins
from lib.bip44 import Bip44

def main():
    print("[INFO] Inicio flujo de prueba HD (BIP39/BIP32/BIP44)")

    wordlist_path = "proyecto/lib/wordlist_english_clean.txt"
    if not os.path.exists(wordlist_path):
        print(f"[ERROR] No se encontró el archivo de wordlist: {wordlist_path}")
        return

    mnemo = Mnemonic("english", wordlist_path=wordlist_path)
    words = mnemo.generate(strength=128)
    if not mnemo.validate(words):
        print("[ERROR] Mnemonic inválido")
        return
    print(f"[OK] Mnemonic (12 palabras): {words}")

    seed_bytes = Bip39SeedGenerator(words).Generate(passphrase="")
    print(f"[OK] Seed bytes len: {len(seed_bytes)}")

    master = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
    acct0_0_0 = master.Purpose().Coin().Account(0).Change(0).AddressIndex(0)

    print(f"[OK] PrivKey hex: {acct0_0_0.PrivateKey().Raw().ToHex()}")
    print(f"[OK] Address: {acct0_0_0.PublicKey().ToAddress()}")

    for i in range(1, 5):
        node = master.Purpose().Coin().Account(0).Change(0).AddressIndex(i)
        print(f"[OK] #{i} Address: {node.PublicKey().ToAddress()}")

    print("[INFO] Flujo finalizado (TESTNET/DEV). No usar con fondos reales.")

if __name__ == "__main__":
    main()
