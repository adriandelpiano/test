#!/usr/bin/env python3
# Genera las dos primeras direcciones Ethereum a partir de una semilla BIP39.
# No usar con fondos reales.

from lib.bip39seed import Bip39SeedGenerator
from lib.bip44coin import Bip44Coins
from lib.bip44 import Bip44

def main():
    print("[INFO] Generador de direcciones Ethereum desde semilla BIP39")
    mnemonic = input("Ingrese su frase semilla (12/24 palabras): ").strip()
    passphrase = ""  # MetaMask usa passphrase vacía por defecto

    # 1) Generar seed
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase=passphrase)
    print(f"[OK] Seed generada ({len(seed_bytes)} bytes)")

    # 2) Derivar con BIP44: Ethereum m/44'/60'/0'/0/n
    coin_def = Bip44Coins.ETHEREUM   # <-- corregido
    master = Bip44.FromSeed(seed_bytes, coin_def)

    for i in range(2):  # primeras dos direcciones
        node = master.Purpose().Coin().Account(0).Change(0).AddressIndex(i)
        priv_hex = node.PrivateKey().Raw().ToHex()
        addr = node.PublicKey().ToAddress()
        print(f"\n[#{i}]")
        print(f"Clave privada: {priv_hex}")
        print(f"Dirección ETH: {addr}")

if __name__ == "__main__":
    main()
