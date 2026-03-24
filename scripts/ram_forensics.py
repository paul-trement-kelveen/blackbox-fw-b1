#!/usr/bin/env python3
"""
ram_forensics.py — Analyse forensique d'un dump RAM BlackBox

Usage :
  1) D'abord, extraire la RAM avec OpenOCD :
     openocd -f interface/stlink.cfg -f target/stm32f7x.cfg \
       -c "init; halt; dump_image ram_dump.bin 0x20000000 0x50000; resume; exit"

  2) Puis analyser le dump :
     python ram_forensics.py ram_dump.bin

Ce script cherche automatiquement :
  - Les chaines lisibles (comme strings)
  - Les logs FDR en clair
  - Le PIN dans la memoire
  - Les commandes dans l'historique
  - Les marqueurs FWDUMP
"""

import sys
import os


def extraire_chaines(data, min_len=4):
    """Extrait les chaines ASCII lisibles d'au moins min_len caracteres."""
    chaines = []
    current = []
    offset_debut = 0

    for i, b in enumerate(data):
        if 32 <= b < 127:
            if not current:
                offset_debut = i
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                chaines.append((offset_debut, ''.join(current)))
            current = []

    if len(current) >= min_len:
        chaines.append((offset_debut, ''.join(current)))

    return chaines


def chercher_pattern(data, pattern_bytes):
    """Cherche un pattern d'octets dans les donnees et retourne les offsets."""
    offsets = []
    idx = 0
    while True:
        idx = data.find(pattern_bytes, idx)
        if idx == -1:
            break
        offsets.append(idx)
        idx += 1
    return offsets


def analyser_ram(filepath):
    """Analyse complete d'un dump RAM."""
    if not os.path.exists(filepath):
        print(f"[ERREUR] Fichier '{filepath}' introuvable.")
        sys.exit(1)

    with open(filepath, 'rb') as f:
        data = f.read()

    taille = len(data)
    base_addr = 0x20000000  # adresse de base de la RAM STM32

    print(f"=== Analyse forensique RAM ===")
    print(f"  Fichier    : {filepath}")
    print(f"  Taille     : {taille} octets ({taille / 1024:.1f} KB)")
    print(f"  Adresse RAM: 0x{base_addr:08X} - 0x{base_addr + taille - 1:08X}")
    print()

    # 1. Chaines lisibles
    chaines = extraire_chaines(data, 4)
    print(f"=== Chaines lisibles ({len(chaines)} trouvees) ===")
    for offset, s in chaines:
        addr = base_addr + offset
        print(f"  0x{addr:08X} [{offset:6d}] : \"{s}\"")
    print()

    # 2. Recherche des logs FDR
    print("=== Recherche de logs FDR (flight data) ===")
    fdr_keywords = [b'ALT=', b'SPD=', b'HDG=', b'ENG', b'ALERT:', b'GPS:', b'T+0']
    for kw in fdr_keywords:
        offsets = chercher_pattern(data, kw)
        for off in offsets:
            addr = base_addr + off
            # Extraire le contexte (80 octets autour)
            start = max(0, off - 10)
            end = min(taille, off + 70)
            contexte = data[start:end]
            texte = contexte.decode('ascii', errors='replace')
            texte = ''.join(c if 32 <= ord(c) < 127 else '.' for c in texte)
            print(f"  0x{addr:08X} : {kw.decode()} → \"{texte}\"")

    print()

    # 3. Recherche du PIN
    print("=== Recherche du PIN ===")
    # Chercher des sequences de 4 chiffres
    pin_patterns = [b'0000', b'1234', b'9999', b'1111']
    for pin in pin_patterns:
        offsets = chercher_pattern(data, pin)
        if offsets:
            for off in offsets:
                addr = base_addr + off
                # Verifier le contexte (est-ce un PIN ou du hasard ?)
                before = data[max(0, off-20):off].decode('ascii', errors='replace')
                after = data[off:off+20].decode('ascii', errors='replace')
                contexte = (before + after).replace('\x00', '.')
                print(f"  PIN candidat '{pin.decode()}' a 0x{addr:08X} : contexte=\"{contexte}\"")

    print()

    # 4. Recherche de commandes connues
    print("=== Recherche de commandes dans l'historique ===")
    commandes = [b'login ', b'logout', b'log read', b'log write', b'log clear',
                 b'history', b'fwdump', b'su ', b'help', b'status', b'sensor']
    for cmd in commandes:
        offsets = chercher_pattern(data, cmd)
        if offsets:
            for off in offsets:
                addr = base_addr + off
                end = min(taille, off + 60)
                texte = data[off:end].decode('ascii', errors='replace')
                texte = texte.split('\x00')[0]  # couper au premier null
                print(f"  0x{addr:08X} : \"{texte}\"")

    print()

    # 5. Recherche des marqueurs FWDUMP
    print("=== Recherche de marqueurs FWDUMP ===")
    fwdump_debut = chercher_pattern(data, b'\xBB\xAA')
    fwdump_fin = chercher_pattern(data, b'\xEE\xFF')
    if fwdump_debut:
        for off in fwdump_debut:
            print(f"  Marqueur debut (BB AA) a 0x{base_addr + off:08X}")
    if fwdump_fin:
        for off in fwdump_fin:
            print(f"  Marqueur fin (EE FF) a 0x{base_addr + off:08X}")
    if not fwdump_debut and not fwdump_fin:
        print("  Aucun marqueur FWDUMP en RAM (normal — les marqueurs sont en Flash/rodata)")

    print()

    # 6. Statistiques memoire
    print("=== Statistiques memoire ===")
    zero_count = data.count(b'\x00')
    ff_count = data.count(b'\xFF')
    print(f"  Octets a zero (0x00) : {zero_count} ({100*zero_count/taille:.1f}%)")
    print(f"  Octets a FF          : {ff_count} ({100*ff_count/taille:.1f}%)")
    print(f"  Octets non-zero      : {taille - zero_count} ({100*(taille-zero_count)/taille:.1f}%)")

    # Zone .bss (ou sont les logs et l'historique)
    bss_offset = 0x19C  # 0x2000019C - 0x20000000
    bss_size = 0xF0C     # taille de .bss
    if bss_offset + bss_size <= taille:
        bss_data = data[bss_offset:bss_offset + bss_size]
        bss_used = sum(1 for b in bss_data if b != 0)
        print(f"\n  Zone .bss (logs + historique) :")
        print(f"    Adresse : 0x{base_addr + bss_offset:08X} - 0x{base_addr + bss_offset + bss_size:08X}")
        print(f"    Taille  : {bss_size} octets")
        print(f"    Utilise : {bss_used} octets ({100*bss_used/bss_size:.1f}%)")

    print()
    print("=== Fin de l'analyse ===")


def main():
    if len(sys.argv) < 2:
        print("Usage : python ram_forensics.py <fichier_dump_ram.bin>")
        print()
        print("Pour creer le dump RAM :")
        print("  openocd -f interface/stlink.cfg -f target/stm32f7x.cfg \\")
        print('    -c "init; halt; dump_image ram_dump.bin 0x20000000 0x50000; resume; exit"')
        sys.exit(1)

    analyser_ram(sys.argv[1])


if __name__ == '__main__':
    main()
