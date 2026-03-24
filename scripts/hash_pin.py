#!/usr/bin/env python3
"""
hash_pin.py — Calcule SHA-256 d'un PIN et genere le tableau C
              a coller dans blackbox.c (Correction C9)

Usage :
    python hash_pin.py 1234
    python hash_pin.py 0000

Sortie :
    Le tableau uint8_t PIN_HASH[32] pret a coller dans le code.
"""

import hashlib
import sys


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <PIN>")
        print(f"  Ex:  python {sys.argv[0]} 1234")
        sys.exit(1)

    pin = sys.argv[1]

    # Calcul SHA-256
    digest = hashlib.sha256(pin.encode("ascii")).digest()

    print(f"PIN      : \"{pin}\"")
    print(f"SHA-256  : {digest.hex()}")
    print()
    print("=" * 60)
    print("Tableau C a coller dans blackbox.c (section CONFIGURATION) :")
    print("=" * 60)
    print()
    print(f"/* SHA-256(\"{pin}\") — genere par hash_pin.py */")
    print("/* Remplace #define PIN_SECRET en correction C9 */")
    print("static const uint8_t PIN_HASH[32] = {")

    hex_bytes = [f"0x{b:02X}" for b in digest]
    for i in range(0, 32, 8):
        ligne = ", ".join(hex_bytes[i:i+8])
        virgule = "," if i + 8 < 32 else ""
        print(f"    {ligne}{virgule}")

    print("};")
    print()
    print("=" * 60)
    print("Dans cmd_login(), remplacer comparer_pin() par :")
    print("=" * 60)
    print()
    print("    uint8_t digest[32];")
    print("    HAL_HASH_SHA256_Start(&hhash,")
    print(f"        (uint8_t *)pin_saisi, strlen(pin_saisi),")
    print("        digest, HAL_MAX_DELAY);")
    print("    if (memcmp(digest, PIN_HASH, 32) == 0) {")
    print("        /* PIN correct */")
    print("    }")
    print()
    print("Verification Python :")
    print(f"  import hashlib")
    print(f"  print(hashlib.sha256(b\"{pin}\").hexdigest())")
    print(f"  => {digest.hex()}")


if __name__ == "__main__":
    main()
