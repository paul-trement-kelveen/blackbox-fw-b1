#!/usr/bin/env python3
"""
decode_fwdump.py — Decodeur de trame FWDUMP BlackBox

Deux modes d'utilisation :
  1) Capture en direct depuis la carte :
     python decode_fwdump.py COM9

  2) Decode une chaine hex copiee depuis PuTTY :
     python decode_fwdump.py --hex "BB AA 05 2E 54 2B ..."

Le protocole FWDUMP :
  [BB AA] [N] [len1] [data1...] [len2] [data2...] ... [EE FF]
  - BB AA   : marqueur de debut
  - N       : nombre de messages (1 octet)
  - lenI    : longueur du message I (1 octet)
  - dataI   : donnees ASCII du message I (lenI octets)
  - EE FF   : marqueur de fin
"""

import sys
import time

# ── Constantes du protocole ─────────────────────────────────
TRAME_DEBUT = bytes([0xBB, 0xAA])
TRAME_FIN   = bytes([0xEE, 0xFF])


def decoder_trame(data):
    """Decode une trame FWDUMP brute (bytes) et retourne la liste des messages."""

    # Verifier le marqueur de debut
    if len(data) < 4:
        print("[ERREUR] Trame trop courte.")
        return []

    if data[0:2] != TRAME_DEBUT:
        print(f"[ERREUR] Marqueur de debut absent. Attendu BB AA, recu {data[0]:02X} {data[1]:02X}")
        return []

    nb_messages = data[2]
    print(f"[INFO] Nombre de messages declares : {nb_messages}")

    messages = []
    pos = 3  # position courante apres le marqueur et le compteur

    for i in range(nb_messages):
        if pos >= len(data):
            print(f"[ERREUR] Fin de trame prematuree au message {i+1}")
            break

        msg_len = data[pos]
        pos += 1

        if pos + msg_len > len(data):
            print(f"[ERREUR] Longueur message {i+1} ({msg_len}) depasse la trame")
            break

        msg_bytes = data[pos:pos + msg_len]
        msg_text = msg_bytes.decode('ascii', errors='replace')
        messages.append(msg_text)
        pos += msg_len

    # Verifier le marqueur de fin
    if pos + 1 < len(data) and data[pos:pos+2] == TRAME_FIN:
        print("[OK] Marqueur de fin EE FF trouve.")
    else:
        octets_restants = data[pos:]
        print(f"[ATTENTION] Marqueur de fin non trouve. Octets restants : "
              f"{' '.join(f'{b:02X}' for b in octets_restants)}")

    return messages


def capturer_fwdump(port, baudrate=115200):
    """Capture la sortie de fwdump en envoyant la commande a la carte."""
    try:
        import serial
    except ImportError:
        print("[ERREUR] pyserial non installe. Lancez : pip install pyserial")
        sys.exit(1)

    ser = serial.Serial(port, baudrate, timeout=3)
    time.sleep(0.5)
    ser.reset_input_buffer()

    # Envoyer la commande login puis fwdump
    def envoyer(cmd):
        for c in cmd:
            ser.write(c.encode())
            time.sleep(0.02)
        ser.write(b'\r')
        time.sleep(0.5)

    # Login d'abord (requis pour fwdump)
    pin = input("[?] Entrez le PIN pour login : ").strip()
    envoyer(f"login {pin}")
    resp = ser.read(ser.in_waiting).decode('utf-8', errors='replace')
    if "reussie" not in resp.lower() and "connecte" not in resp.lower():
        print("[ATTENTION] Login peut-etre echoue. Reponse :")
        print(resp)

    # Envoyer fwdump
    envoyer("fwdump")
    time.sleep(2)
    raw = ser.read(ser.in_waiting).decode('utf-8', errors='replace')
    ser.close()

    print("\n=== Sortie brute FWDUMP ===")
    print(raw)

    # Extraire la partie hexadecimale (entre "FWDUMP debut" et "FWDUMP fin")
    lignes = raw.split('\n')
    hex_parts = []
    capture = False

    for ligne in lignes:
        ligne = ligne.strip()
        if 'FWDUMP debut' in ligne:
            capture = True
            # Prendre tout ce qui est apres le ":"
            apres = ligne.split(':', 1)
            if len(apres) > 1 and apres[1].strip():
                hex_parts.append(apres[1].strip())
            continue
        if 'FWDUMP fin' in ligne:
            capture = False
            continue
        if capture and ligne:
            hex_parts.append(ligne)

    hex_str = ' '.join(hex_parts)
    return hex_str


def hex_vers_bytes(hex_str):
    """Convertit une chaine hexadecimale (avec espaces) en bytes."""
    hex_clean = hex_str.replace('\n', ' ').replace('\r', ' ').strip()
    tokens = hex_clean.split()
    return bytes(int(t, 16) for t in tokens if len(t) == 2)


def afficher_hexdump(data, colonnes=16):
    """Affiche un hexdump style xxd."""
    print(f"\n=== Hexdump ({len(data)} octets) ===")
    for offset in range(0, len(data), colonnes):
        ligne = data[offset:offset + colonnes]
        hex_part = ' '.join(f'{b:02X}' for b in ligne)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ligne)
        print(f"  {offset:04X}  {hex_part:<{colonnes*3}}  |{ascii_part}|")


def main():
    if len(sys.argv) < 2:
        print("Usage :")
        print(f"  {sys.argv[0]} COM9               (capture depuis la carte)")
        print(f"  {sys.argv[0]} --hex \"BB AA ...\"   (decode une chaine hex)")
        sys.exit(1)

    if sys.argv[1] == '--hex':
        hex_str = ' '.join(sys.argv[2:])
        data = hex_vers_bytes(hex_str)
    else:
        port = sys.argv[1]
        print(f"[INFO] Connexion a {port} ...")
        hex_str = capturer_fwdump(port)
        if not hex_str.strip():
            print("[ERREUR] Aucune donnee hexadecimale capturee.")
            sys.exit(1)
        data = hex_vers_bytes(hex_str)

    # Afficher le hexdump
    afficher_hexdump(data)

    # Decoder la trame
    print("\n=== Decodage de la trame ===")
    messages = decoder_trame(data)

    if messages:
        print(f"\n=== {len(messages)} message(s) decode(s) ===")
        for i, msg in enumerate(messages, 1):
            print(f"  [{i}] {msg}")
    else:
        print("\n[ERREUR] Aucun message decode.")

    # Verifier l'absence de checksum
    print("\n=== Analyse de securite ===")
    print("  Chiffrement des donnees : NON (clair)")
    print("  Checksum / CRC          : NON (aucune integrite)")
    print("  → Un attaquant peut lire et modifier les donnees en transit.")


if __name__ == '__main__':
    main()
