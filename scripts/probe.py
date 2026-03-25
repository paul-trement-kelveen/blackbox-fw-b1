#!/usr/bin/env python3
"""
probe.py — Sonde automatique : teste quelles vulnerabilites sont presentes
           sur une carte BlackBox B1 GUARDIA

Teste V1-V7 + VH1 (timing) sans connaitre le PIN.
Utile en debut de War Day pour cartographier la cible.

Usage :
    python probe.py COM3
"""

import serial
import time
import sys
import statistics


def ouvrir_port(port, baud=115200, timeout=2.0):
    try:
        ser = serial.Serial(port, baud, timeout=timeout)
        time.sleep(0.3)
        ser.reset_input_buffer()
        return ser
    except serial.SerialException as e:
        print(f"[!] Impossible d'ouvrir {port} : {e}")
        sys.exit(1)


def envoyer_cmd(ser, cmd, attente=1.5):
    """Envoie une commande et retourne la reponse."""
    ser.reset_input_buffer()
    ser.write((cmd + "\r\n").encode())
    time.sleep(attente)
    reponse = b""
    while ser.in_waiting:
        reponse += ser.read(ser.in_waiting)
        time.sleep(0.05)
    return reponse.decode(errors="replace")


def mesurer_login(ser, pin, n=3):
    """Mesure le temps median de reponse pour un PIN donne."""
    temps = []
    for _ in range(n):
        ser.reset_input_buffer()
        ser.write(f"login {pin}\r\n".encode())
        t0 = time.perf_counter()
        reponse = b""
        while True:
            c = ser.read(1)
            if not c:
                break
            reponse += c
            if b"incorrect" in reponse or b"reussie" in reponse or b"Trop" in reponse:
                break
        t1 = time.perf_counter()
        temps.append((t1 - t0) * 1000)
        time.sleep(0.05)
    return statistics.median(temps)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <PORT>")
        sys.exit(1)

    port = sys.argv[1]
    resultats = {}

    print("=" * 55)
    print("  PROBE — Analyse vulnerabilites BlackBox B1")
    print("=" * 55)
    print(f"  Cible : {port}")
    print()

    ser = ouvrir_port(port)
    time.sleep(0.5)

    # ── V4 : log read sans auth ──────────────────────────────────
    print("[*] Test V4 — log read sans authentification...")
    rep = envoyer_cmd(ser, "log read")
    if "Erreur" in rep or "connecte" in rep:
        resultats["V4"] = ("CORRIGEE", "log read renvoie une erreur sans login")
    else:
        resultats["V4"] = ("PRESENTE", "log read fonctionne sans login")

    # ── V3 : brute force (test rapide avec PINs classiques) ──────
    print("[*] Test V3 — tentatives illimitees (PINs classiques)...")
    pins_test = ["0000", "1234", "1111", "0001"]
    v3_bloque = False
    pin_trouve = None
    for p in pins_test:
        rep = envoyer_cmd(ser, f"login {p}", attente=1.0)
        if "reussie" in rep or "Connexion" in rep:
            pin_trouve = p
            break
        if "Trop" in rep or "bloque" in rep.lower():
            v3_bloque = True
            break
    if pin_trouve:
        resultats["V3"] = ("PRESENTE", f"PIN par defaut trouve : {pin_trouve}")
        resultats["V1"] = ("PRESENTE", f"PIN en clair dans le code : {pin_trouve}")
    elif v3_bloque:
        resultats["V3"] = ("CORRIGEE", "Lockout detecte apres quelques essais")
    else:
        resultats["V3"] = ("INCONNUE", "PINs classiques rejetes, lockout non detecte")

    # ── VH1 : timing attack (rapide — 2 positions) ───────────────
    print("[*] Test VH1 — timing attack (mesure rapide)...")
    t_zero = mesurer_login(ser, "9000", n=4)
    t_un   = mesurer_login(ser, "0900", n=4)
    delta = t_un - t_zero
    if delta > 6:
        resultats["VH1"] = ("PRESENTE", f"Delta timing {delta:.1f} ms (>6ms = vulnerable)")
    else:
        resultats["VH1"] = ("CORRIGEE", f"Delta timing {delta:.1f} ms (<=6ms = temps constant)")

    # ── V2 : historique expose PIN ───────────────────────────────
    print("[*] Test V2 — historique expose le PIN...")
    rep = envoyer_cmd(ser, "history")
    if "login [***]" in rep:
        resultats["V2"] = ("CORRIGEE", "Historique masque les PINs")
    elif "login " in rep:
        resultats["V2"] = ("PRESENTE", "PIN visible dans l'historique")
    else:
        resultats["V2"] = ("INCONNUE", "Historique vide ou inaccessible")

    # ── V5 : log clear superficiel ───────────────────────────────
    print("[*] Test V5 — log clear superficiel...")
    if pin_trouve:
        envoyer_cmd(ser, f"login {pin_trouve}")
        envoyer_cmd(ser, "log write probe_test_v5")
        envoyer_cmd(ser, "log clear")
        rep = envoyer_cmd(ser, "log read")
        if "probe_test_v5" in rep:
            resultats["V5"] = ("PRESENTE", "Donnees lisibles apres log clear")
        elif "Aucun log" in rep:
            resultats["V5"] = ("INCONNUE", "Log clear semble fonctionner (sans debugger)")
        envoyer_cmd(ser, "logout")
    else:
        resultats["V5"] = ("INCONNUE", "PIN non connu — test impossible")

    # ── VH4 : su accessible sans login ───────────────────────────
    print("[*] Test VH4 — commande 'su' sans login...")
    rep = envoyer_cmd(ser, "su 0000", attente=1.5)
    r = rep.lower()
    if "connexion requise" in r or "non connecte" in r:
        resultats["VH4"] = ("CORRIGEE", "su sans login refuse (C11 bien implemente)")
    elif "non implemente" in r:
        resultats["VH4"] = ("PRESENTE", "su accepte sans login (C11 non code — VH4 ouverte)")
    elif "actif" in r or "eleve" in r:
        resultats["VH4"] = ("PRESENTE", "su accepte sans login ET PIN sudo trouve (0000)")
    elif "incorrect" in r:
        resultats["VH4"] = ("PRESENTE", "su accepte sans login (C11 code mais VH4 non fermee)")
    else:
        resultats["VH4"] = ("INCONNUE", f"Reponse inattendue : {rep.strip()[:50]}")

    # ── VH7 : commande diag (debug code) ──────────────────────────
    print("[*] Test VH7 — commande debug 'diag'...")
    rep = envoyer_cmd(ser, "diag")
    if "CAL:" in rep:
        import re as _re
        cal_match = _re.search(r'CAL:([0-9A-Fa-f]{2})', rep)
        if cal_match:
            xor_key = int(cal_match.group(1), 16)
            resultats["VH7"] = ("PRESENTE", f"diag actif, XOR_KEY=0x{xor_key:02X} ({xor_key})")
        else:
            resultats["VH7"] = ("PRESENTE", "diag actif (CAL non parse)")
    elif "inconnue" in rep.lower():
        resultats["VH7"] = ("CORRIGEE", "diag non reconnu (supprime)")
    else:
        resultats["VH7"] = ("INCONNUE", f"Reponse : {rep.strip()[:50]}")

    # ── VH8 : oracle erreur (longueur PIN) ────────────────────────
    print("[*] Test VH8 — oracle longueur PIN...")
    rep_1 = envoyer_cmd(ser, "login X", attente=1.0)
    rep_4 = envoyer_cmd(ser, "login XXXX", attente=1.0)
    if "Saisie invalide" in rep_1 and "PIN incorrect" in rep_4:
        resultats["VH8"] = ("PRESENTE", "Messages differents => longueur PIN = 4")
    elif "Saisie invalide" in rep_1 or "PIN incorrect" in rep_4:
        resultats["VH8"] = ("PRESENTE", "Messages partiellement differencies")
    else:
        resultats["VH8"] = ("CORRIGEE", "Message d'erreur uniforme")

    # ─────────────────────────────────────────────────────────────
    print()
    print("=" * 55)
    print("  RAPPORT DE VULNERABILITES")
    print("=" * 55)
    print(f"  Cible : {port}")
    print()

    ordre = ["V1", "V2", "V3", "V4", "V5", "VH1", "VH4", "VH7", "VH8"]
    for v in ordre:
        if v in resultats:
            statut, detail = resultats[v]
            icone = "[+]" if statut == "PRESENTE" else ("[v]" if statut == "CORRIGEE" else "[?]")
            print(f"  {icone} {v:<5} {statut:<10}  {detail}")

    print()
    nb_present = sum(1 for s, _ in resultats.values() if s == "PRESENTE")
    nb_corrige = sum(1 for s, _ in resultats.values() if s == "CORRIGEE")
    print(f"  Vulnerabilites presentes : {nb_present}")
    print(f"  Vulnerabilites corrigees : {nb_corrige}")
    print()
    print("  [+] = exploitable  [v] = corrigee  [?] = incertain")
    print("=" * 55)

    ser.close()


if __name__ == "__main__":
    main()
