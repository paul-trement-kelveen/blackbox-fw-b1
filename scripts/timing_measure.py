#!/usr/bin/env python3
"""
timing_measure.py — Mesure simple du temps de reponse de login
                    (utilise en Phase 1, Q12 du carnet)

Fournit le tableau de mesures pour comprendre le timing attack
AVANT de lancer timing_attack.py.

Usage :
    python timing_measure.py COM3
    python timing_measure.py COM3 --pin-connu 0000
"""

import serial
import time
import sys
import statistics
import argparse


def ouvrir_port(port, baud=115200):
    try:
        ser = serial.Serial(port, baud, timeout=0.1)
        time.sleep(0.3)
        ser.reset_input_buffer()
        return ser
    except serial.SerialException as e:
        print(f"[!] Impossible d'ouvrir {port} : {e}")
        sys.exit(1)


def lire_tout(ser, timeout=2.0):
    """Lit tout ce qui arrive pendant 'timeout' secondes."""
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        chunk = ser.read(64)
        if chunk:
            buf += chunk
        else:
            if buf:
                break
    return buf


def mesurer_un(ser, pin):
    """Envoie login <pin> et mesure le temps jusqu'au mot-cle de reponse."""
    # Vider ce qui traine
    ser.read(ser.in_waiting or 1)

    commande = f"login {pin}\r\n".encode()
    ser.write(commande)
    t0 = time.perf_counter()

    reponse = b""
    while (time.perf_counter() - t0) < 5.0:
        chunk = ser.read(32)
        if chunk:
            reponse += chunk
            if b"incorrect" in reponse or b"reussie" in reponse \
               or b"invalide" in reponse or b"Trop" in reponse:
                t1 = time.perf_counter()
                # Consommer le reste (prompt bb>) et le prompt de la ligne vide
                time.sleep(0.3)
                ser.read(ser.in_waiting or 1)
                time.sleep(0.4)
                ser.read(ser.in_waiting or 1)
                # Logout si connecte
                if b"reussie" in reponse:
                    ser.write(b"logout\r\n")
                    time.sleep(0.5)
                    ser.read(ser.in_waiting or 1)
                    time.sleep(0.4)
                    ser.read(ser.in_waiting or 1)
                return (t1 - t0) * 1000, True

    # Timeout — consommer ce qui reste
    time.sleep(0.3)
    ser.read(ser.in_waiting or 1)
    time.sleep(0.4)
    ser.read(ser.in_waiting or 1)
    return (time.perf_counter() - t0) * 1000, False


def mesurer(ser, pin, n=5):
    temps = []
    for _ in range(n):
        dt, ok = mesurer_un(ser, pin)
        temps.append(dt)
    return statistics.median(temps), min(temps), max(temps)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("port")
    parser.add_argument("--pin-connu", default=None,
                        help="PIN correct connu (pour comparaison)")
    parser.add_argument("--samples", type=int, default=5)
    args = parser.parse_args()

    print("=" * 55)
    print("  MESURE TIMING — BlackBox B1 GUARDIA")
    print("=" * 55)
    print(f"  Port    : {args.port}")
    print(f"  Samples : {args.samples} par PIN")
    print()
    print("  Ce script mesure le temps de reponse de 'login'")
    print("  pour differents PINs commencant par 0, 1, 2...")
    print("  Si le temps augmente avec les chiffres corrects,")
    print("  la cible est vulnerable au timing attack.")
    print("=" * 55)
    print()

    ser = ouvrir_port(args.port)

    # Synchronisation initiale : reveiller le shell
    ser.write(b"\r\n")
    time.sleep(1.0)
    ser.read(ser.in_waiting or 1)
    time.sleep(0.5)
    ser.read(ser.in_waiting or 1)

    # PINs de test Q12 — progression de chiffres corrects
    # (le PIN par defaut est 0000)
    pins_test = [
        ("9000", "0 chiffre correct"),
        ("0900", "1 chiffre correct"),
        ("0090", "2 chiffres corrects"),
        ("0009", "3 chiffres corrects"),
        ("0000", "4 chiffres corrects (PIN par defaut)"),
    ]

    if args.pin_connu:
        pins_test.append((args.pin_connu, "PIN correct (4 chiffres)"))

    print(f"  {'PIN':<8} {'Median (ms)':<14} {'Min':<8} {'Max':<8}  Commentaire")
    print("  " + "-" * 65)

    for pin, commentaire in pins_test:
        med, mn, mx = mesurer(ser, pin, args.samples)
        print(f"  {pin:<8} {med:<14.1f} {mn:<8.1f} {mx:<8.1f}  {commentaire}")

    print()
    print("  Interpretation :")
    print("  - Si les medianes augmentent progressivement -> VULNERABLE (VH1)")
    print("  - Si les medianes sont toutes similaires     -> CORRIGE (temps constant)")
    print()
    print("  Pour exploiter : python timing_attack.py", args.port)

    ser.close()


if __name__ == "__main__":
    main()
