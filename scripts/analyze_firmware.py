#!/usr/bin/env python3
"""
analyze_firmware.py — Analyse automatisee d'un fichier ELF BlackBox

Usage :
  python analyze_firmware.py blackbox-f7.elf

Ce script automatise les etapes de retro-conception :
  1. Extraction des chaines (strings)
  2. Recherche de secrets (PIN, cles, mots de passe)
  3. Analyse des sections memoire
  4. Liste des fonctions
  5. Rapport de securite

Prerequis : arm-none-eabi-objdump et arm-none-eabi-strings dans le PATH
  ou dans le repertoire STM32CubeIDE.
"""

import sys
import os
import subprocess
import re


# Chemins possibles pour les outils ARM (Windows avec STM32CubeIDE)
TOOL_PATHS = [
    "",  # PATH systeme
    "C:/ST/STM32CubeIDE_2.1.0/STM32CubeIDE/plugins/"
    "com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32."
    "14.3.rel1.win32_1.0.100.202602081740/tools/bin/",
]


def trouver_outil(nom):
    """Cherche un outil ARM dans les chemins connus."""
    for prefix in TOOL_PATHS:
        chemin = os.path.join(prefix, nom)
        try:
            subprocess.run([chemin, "--version"], capture_output=True, timeout=5)
            return chemin
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        # Essayer avec .exe sur Windows
        try:
            subprocess.run([chemin + ".exe", "--version"], capture_output=True, timeout=5)
            return chemin + ".exe"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def executer(cmd):
    """Execute une commande et retourne stdout."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return f"[ERREUR] {e}"


def main():
    if len(sys.argv) < 2:
        print("Usage : python analyze_firmware.py <fichier.elf>")
        sys.exit(1)

    elf_path = sys.argv[1]
    if not os.path.exists(elf_path):
        print(f"[ERREUR] Fichier '{elf_path}' introuvable.")
        sys.exit(1)

    # Trouver les outils
    strings_tool = trouver_outil("arm-none-eabi-strings")
    objdump_tool = trouver_outil("arm-none-eabi-objdump")
    size_tool = trouver_outil("arm-none-eabi-size")

    if not strings_tool:
        print("[ATTENTION] arm-none-eabi-strings non trouve, utilisation de strings standard")
        strings_tool = "strings"
    if not objdump_tool:
        print("[ERREUR] arm-none-eabi-objdump non trouve. Installez la toolchain ARM.")
        sys.exit(1)

    # ── 1. Taille du firmware ──────────────────────────────────
    print("=" * 60)
    print("  ANALYSE FIRMWARE — RETRO-CONCEPTION")
    print("=" * 60)
    print(f"\n  Fichier : {elf_path}")
    print(f"  Taille  : {os.path.getsize(elf_path)} octets")

    if size_tool:
        sortie = executer([size_tool, elf_path])
        print(f"\n=== Taille memoire (arm-none-eabi-size) ===")
        print(sortie)

    # ── 2. Sections ────────────────────────────────────────────
    print("=== Sections du binaire (objdump -h) ===")
    sortie = executer([objdump_tool, "-h", elf_path])
    for ligne in sortie.split('\n'):
        if any(s in ligne for s in ['.text', '.rodata', '.data', '.bss', '.isr_vector', 'Idx']):
            print(f"  {ligne.strip()}")

    # ── 3. Chaines de caracteres ───────────────────────────────
    print("\n=== Chaines de caracteres (strings) ===")
    sortie = executer([strings_tool, elf_path])
    chaines = [s for s in sortie.strip().split('\n') if len(s) >= 4]
    print(f"  Total : {len(chaines)} chaines trouvees")

    # Filtrer les chaines interessantes
    print("\n  --- Chaines suspectes (potentiels secrets) ---")
    secrets_regex = re.compile(r'(pin|pass|key|secret|admin|root|0000|1234|login|sudo)', re.IGNORECASE)
    secrets = [s for s in chaines if secrets_regex.search(s)]
    for s in secrets:
        print(f"    ! \"{s}\"")

    print("\n  --- Messages du firmware ---")
    msg_regex = re.compile(r'(connexion|erreur|commande|log|fwdump|deconnect|session|reussi)', re.IGNORECASE)
    messages = [s for s in chaines if msg_regex.search(s)]
    for s in messages:
        print(f"    > \"{s}\"")

    print("\n  --- Donnees de vol (FDR) ---")
    fdr_regex = re.compile(r'(ALT=|SPD=|HDG=|ENG|ALERT|GPS|T\+\d)')
    fdr = [s for s in chaines if fdr_regex.search(s)]
    for s in fdr:
        print(f"    [FDR] \"{s}\"")

    print("\n  --- Informations firmware ---")
    info_regex = re.compile(r'(v\d\.\d|STM32|Cortex|GUARDIA|BlackBox|MHz)', re.IGNORECASE)
    infos = [s for s in chaines if info_regex.search(s)]
    for s in infos:
        print(f"    [INFO] \"{s}\"")

    # ── 4. Symboles (fonctions) ────────────────────────────────
    print("\n=== Fonctions du firmware (objdump -t) ===")
    sortie = executer([objdump_tool, "-t", elf_path])
    fonctions = []
    for ligne in sortie.split('\n'):
        if ' F .text' in ligne:
            parts = ligne.split()
            addr = parts[0]
            taille = parts[4] if len(parts) > 4 else '?'
            nom = parts[-1] if parts else '?'
            fonctions.append((addr, taille, nom))

    # Trier : fonctions BlackBox d'abord
    bb_funcs = [f for f in fonctions if any(x in f[2] for x in ['bb_', 'auth_', 'logs_', 'shell_', 'leds_', 'fwdump', 'comparer', 'blackbox'])]
    hal_funcs = [f for f in fonctions if 'HAL_' in f[2]]
    other_funcs = [f for f in fonctions if f not in bb_funcs and f not in hal_funcs]

    print(f"\n  --- Fonctions BlackBox ({len(bb_funcs)}) ---")
    for addr, taille, nom in bb_funcs:
        taille_dec = int(taille, 16) if taille != '?' else 0
        print(f"    0x{addr} [{taille_dec:4d} B] {nom}")

    print(f"\n  --- Fonctions HAL ({len(hal_funcs)}) ---")
    for addr, taille, nom in hal_funcs:
        taille_dec = int(taille, 16) if taille != '?' else 0
        print(f"    0x{addr} [{taille_dec:4d} B] {nom}")

    print(f"\n  --- Autres fonctions ({len(other_funcs)}) ---")
    for addr, taille, nom in other_funcs[:10]:
        taille_dec = int(taille, 16) if taille != '?' else 0
        print(f"    0x{addr} [{taille_dec:4d} B] {nom}")
    if len(other_funcs) > 10:
        print(f"    ... et {len(other_funcs) - 10} autres")

    # ── 5. Rapport de securite ─────────────────────────────────
    print("\n" + "=" * 60)
    print("  RAPPORT DE SECURITE")
    print("=" * 60)

    problemes = []
    if secrets:
        problemes.append(("CRITIQUE", "PIN/secret visible dans les chaines du binaire (V1)"))
    if any('0000' in s for s in chaines):
        problemes.append(("CRITIQUE", "PIN par defaut '0000' present en clair"))
    if any('bb>' in s or 'connecte' in s for s in chaines):
        problemes.append(("INFO", "Prompts et messages d'erreur revelent la logique d'authentification"))
    if fdr:
        problemes.append(("MOYEN", "Donnees FDR stockees en clair dans le binaire"))
    if any('comparer_pin' in f[2] for f in fonctions):
        problemes.append(("INFO", "Fonction 'comparer_pin' visible dans les symboles (binaire non-strippe)"))

    for niveau, desc in problemes:
        print(f"  [{niveau:8s}] {desc}")

    if not problemes:
        print("  Aucun probleme detecte (binaire bien protege).")

    print(f"\n  Total : {len(problemes)} observation(s)")
    print("=" * 60)


if __name__ == '__main__':
    main()
