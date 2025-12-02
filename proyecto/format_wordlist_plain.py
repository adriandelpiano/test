#!/usr/bin/env python3
# Convierte wordlist con palabras separadas por espacios
# a un archivo plano con una palabra por línea.

def main():
    in_path = "proyecto/lib/wordlist_english.txt"
    out_path = "proyecto/lib/wordlist_english_clean.txt"

    with open(in_path, "r", encoding="utf-8") as f:
        words = [w.strip() for w in f.read().split() if w.strip()]

    print(f"[INFO] Palabras cargadas: {len(words)}")

    with open(out_path, "w", encoding="utf-8") as f:
        for w in words:
            f.write(w + "\n")

    print(f"[OK] Wordlist exportada en formato limpio: {out_path}")

if __name__ == "__main__":
    main()
