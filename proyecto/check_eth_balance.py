#!/usr/bin/env python3
# Verificar saldo ETH en múltiples RPC públicos
# No usar con fondos reales. Solo testnet/dev.

import requests
import sys

RPC_ENDPOINTS = [
    # RPCs públicos conocidos (mainnet)
    "https://cloudflare-eth.com",
    "https://rpc.ankr.com/eth",
    "https://eth-mainnet.public.blastapi.io",
    "https://rpc.payload.de",
    "https://ethereum.publicnode.com",
    "https://rpc.ankr.com/eth",
    "https://mainnet.infura.io/v3/00000000000000000000000000000000",  # reemplazar con tu API key
    "https://rpc.flashbots.net",
    "https://rpc.builder0x69.io",
    "https://rpc.mevblocker.io",
]

def get_balance(rpc_url, address):
    try:
        payload = {
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": [address, "latest"],
            "id": 1,
        }
        r = requests.post(rpc_url, json=payload, timeout=5)
        r.raise_for_status()
        data = r.json()
        if "result" in data:
            wei = int(data["result"], 16)
            eth = wei / 10**18
            return eth
    except Exception as e:
        return None
    return None

def main():
    if len(sys.argv) < 2:
        print("Uso: python3 check_eth_balance.py <direccion_eth>")
        sys.exit(1)

    address = sys.argv[1]
    print(f"[INFO] Consultando saldo de {address} en múltiples RPCs...\n")

    for rpc in RPC_ENDPOINTS:
        balance = get_balance(rpc, address)
        if balance is not None:
            print(f"[OK] {rpc} → {balance:.8f} ETH")
        else:
            print(f"[ERROR] {rpc} → sin respuesta")

if __name__ == "__main__":
    main()
