#!/usr/bin/env python3
"""
spi_receive.py — Recepteur de la trame FWDUMP SPI BlackBox B1
GUARDIA — Script de validation C7 et C8

Ce script simule un recepteur SPI. Il lit la trame FWDUMP sur le port
serie et la decode.

En Phase 2, la carte envoie les logs via SPI1 (PA7=MOSI, PA5=SCK).
Un adaptateur USB-SPI (ex: FT232H) ou un second STM32 peut capturer
la trame. Ce script attendrait des donnees sur un port serie connecte
au recepteur.

Pour les tests sans analyseur logique :
    Les donnees sont aussi affichees en hexa sur l'UART (version V7).
    Ce script peut parser cette sortie hexa pour valider C7/C8.

Usage :
    # Analyser la sortie hexa affichee par fwdump (mode UART temporaire)
    python spi_receive.py --hex "BB AA 03 05 68 65 6C 6C 6F 06 77 6F 72 6C 64 21 EE FF"

    # Avec cle XOR (si C8 implemente)
    python spi_receive.py --hex "BB AA 03 ..." --key 0x42

    # Depuis un port serie (adaptateur USB-SPI)
    python spi_receive.py COM5 --key 0x42
"""

import sys
import argparse


# ── Constantes de trame ──────────────────────────────────────────────
TRAME_DEBUT_0 = 0xBB
TRAME_DEBUT_1 = 0xAA
TRAME_FIN_0   = 0xEE
TRAME_FIN_1   = 0xFF


def dechiffrer(donnees, cle):
    """XOR chaque octet avec la cle (symetrique : dechiffre == chiffre)."""
    return bytes(b ^ cle for b in donnees)


def parser_trame(octets, cle=None):
    """
    Parse la trame FWDUMP :
      [0xBB][0xAA][nb_logs]
      Pour chaque log : [longueur][data...]
      [0xEE][0xFF]

    Retourne la liste des messages dechiffres.
    """
    i = 0
    n = len(octets)

    # Chercher le marqueur de debut
    while i < n - 1:
        if octets[i] == TRAME_DEBUT_0 and octets[i+1] == TRAME_DEBUT_1:
            break
        i += 1
    else:
        print("[!] Marqueur de debut 0xBB 0xAA introuvable.")
        return []

    i += 2  # sauter le marqueur
    if i >= n:
        print("[!] Trame tronquee apres le marqueur de debut.")
        return []

    nb_logs = octets[i]
    i += 1
    print(f"[*] {nb_logs} log(s) declares dans la trame.")

    messages = []
    for idx in range(nb_logs):
        if i >= n:
            print(f"[!] Trame tronquee au log {idx+1}.")
            break
        longueur = octets[i]
        i += 1
        if i + longueur > n:
            print(f"[!] Longueur {longueur} depasse la trame au log {idx+1}.")
            break

        data_brute = bytes(octets[i:i+longueur])
        i += longueur

        if cle is not None:
            data = dechiffrer(data_brute, cle)
        else:
            data = data_brute

        try:
            message = data.decode('utf-8', errors='replace').rstrip('\x00')
        except Exception:
            message = data.hex()

        messages.append((idx+1, data_brute, message))

    # Verifier le marqueur de fin
    if i + 1 < n and octets[i] == TRAME_FIN_0 and octets[i+1] == TRAME_FIN_1:
        print("[*] Marqueur de fin 0xEE 0xFF trouve. Trame complete.")
    else:
        print("[?] Marqueur de fin non trouve ou trame incomplete.")

    return messages


def afficher_rapport(messages, cle):
    """Affiche le rapport de decodage."""
    print()
    print("=" * 55)
    print("  RAPPORT FWDUMP DECODE")
    print("=" * 55)
    if cle is not None:
        print(f"  Cle XOR utilisee : 0x{cle:02X}")
    else:
        print(f"  Aucune cle XOR (donnees en clair ou non dechiffrees)")
    print()

    for idx, brut, message in messages:
        print(f"  Log [{idx}]")
        print(f"    Brut (hexa) : {brut.hex(' ').upper()}")
        print(f"    Dechiffre   : {message}")
        print()

    if not messages:
        print("  Aucun log decode.")
    print("=" * 55)


def depuis_hex_string(hex_str):
    """Convertit une chaine hexadecimale en liste d'octets."""
    hex_str = hex_str.replace("0x", "").replace(",", " ")
    try:
        return list(bytes.fromhex(hex_str.replace(" ", "")))
    except ValueError as e:
        print(f"[!] Erreur de decodage hex : {e}")
        sys.exit(1)


def depuis_port_serie(port, cle, baud=115200):
    """Capture une trame depuis un port serie."""
    try:
        import serial
        import time
    except ImportError:
        print("[!] Module 'serial' requis : pip install pyserial")
        sys.exit(1)

    print(f"[*] Ecoute sur {port} ({baud} bauds)...")
    print("    Appuyez sur Ctrl+C pour arreter.")
    print()

    ser = serial.Serial(port, baud, timeout=1.0)
    try:
        time.sleep(0.3)
        donnees = bytearray()

        while True:
            c = ser.read(1)
            if c:
                donnees += c
                # Detecter fin de trame
                if len(donnees) >= 2 and donnees[-2] == TRAME_FIN_0 and donnees[-1] == TRAME_FIN_1:
                    print(f"[*] Trame complete recue ({len(donnees)} octets).")
                    break
    except KeyboardInterrupt:
        print(f"\n[*] Arret. {len(donnees)} octets recus.")
    finally:
        ser.close()

    return list(donnees)


def main():
    parser = argparse.ArgumentParser(
        description="Decodeur trame FWDUMP SPI — BlackBox B1 GUARDIA"
    )
    parser.add_argument("port", nargs="?",
                        help="Port serie du recepteur SPI (optionnel)")
    parser.add_argument("--hex", metavar="HEXDATA",
                        help="Donnees hexa a parser (ex: 'BB AA 03 ...')")
    parser.add_argument("--key", metavar="KEY", default=None,
                        help="Cle XOR pour dechiffrement (ex: 0x42 ou 66)")
    args = parser.parse_args()

    # Parser la cle
    cle = None
    if args.key:
        try:
            cle = int(args.key, 0)  # accepte 0xAB et 171
        except ValueError:
            print(f"[!] Cle invalide : {args.key}. Utiliser un format hexa (0xAB) ou decimal (171).")
            sys.exit(1)

    print("=" * 55)
    print("  SPI RECEIVE — Decodeur FWDUMP BlackBox B1")
    print("=" * 55)

    if args.hex:
        print(f"[*] Mode : analyse de donnees hexa")
        octets = depuis_hex_string(args.hex)
        print(f"[*] {len(octets)} octets a analyser.")
    elif args.port:
        print(f"[*] Mode : ecoute sur port serie {args.port}")
        octets = depuis_port_serie(args.port, cle)
    else:
        # Exemple pedagogique avec des donnees hardcodees
        print("[*] Mode demonstration (donnees exemple).")
        print("    Usage : python spi_receive.py --hex 'BB AA 02 05 68 65 6C 6C 6F 06 6D 6F 6E 64 65 21 EE FF'")
        print("    Ou    : python spi_receive.py COM5 --key 0x42")
        print()
        # "hello" et "monde!" en plaintext
        exemple = [0xBB, 0xAA, 0x02,
                   0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
                   0x06, 0x6D, 0x6F, 0x6E, 0x64, 0x65, 0x21,
                   0xEE, 0xFF]
        octets = exemple
        print(f"[*] Trame exemple : {bytes(octets).hex(' ').upper()}")

    messages = parser_trame(octets, cle)
    afficher_rapport(messages, cle)


if __name__ == "__main__":
    main()
