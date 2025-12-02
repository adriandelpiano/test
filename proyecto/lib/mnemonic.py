# BIP39: generación y validación de mnemónicos (12/24 palabras)
# Usa wordlist en formato plano (una palabra por línea)

import os
from typing import List
from .biputils import sha256

class Mnemonic:
    def __init__(self, language: str = "english", wordlist_path: str = None):
        if language != "english":
            raise ValueError("Solo 'english' soportado.")
        if not wordlist_path:
            raise ValueError("Se requiere path a wordlist inglesa BIP39.")
        self.wordlist = self._load_wordlist(wordlist_path)
        if len(self.wordlist) != 2048:
            raise ValueError(f"Wordlist debe tener 2048 palabras BIP39. Encontradas: {len(self.wordlist)}")

    def _load_wordlist(self, path: str) -> List[str]:
        with open(path, "r", encoding="utf-8") as f:
            return [w.strip() for w in f.readlines() if w.strip()]

    def generate(self, strength: int = 128) -> str:
        if strength not in (128, 160, 192, 224, 256):
            raise ValueError("Strength inválido. Use 128,160,192,224,256.")
        ent = os.urandom(strength // 8)
        entropy_bits = bin(int.from_bytes(ent, "big"))[2:].zfill(strength)
        hash_bits = bin(int.from_bytes(sha256(ent), "big"))[2:].zfill(256)
        cs_len = strength // 32
        checksum_bits = hash_bits[:cs_len]
        bits = entropy_bits + checksum_bits
        indices = [int(bits[i*11:(i+1)*11], 2) for i in range(len(bits)//11)]
        words = [self.wordlist[idx] for idx in indices]
        return " ".join(words)

    def validate(self, words: str) -> bool:
        parts = words.strip().split()
        if len(parts) not in (12, 15, 18, 21, 24):
            return False
        try:
            indices = [self.wordlist.index(w) for w in parts]
        except ValueError:
            return False
        bitstr = "".join(bin(i)[2:].zfill(11) for i in indices)
        total_len = len(bitstr)
        cs_len = total_len // 33
        ent_len = total_len - cs_len
        entropy_bits = bitstr[:ent_len]
        checksum_bits = bitstr[ent_len:]
        ent_bytes = int(entropy_bits, 2).to_bytes(ent_len // 8, "big")
        hash_bits = bin(int.from_bytes(sha256(ent_bytes), "big"))[2:].zfill(256)
        return checksum_bits == hash_bits[:cs_len]
