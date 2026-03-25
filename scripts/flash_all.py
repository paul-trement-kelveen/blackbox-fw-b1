#!/usr/bin/env python3
"""
flash_all.py — Outil de flash en masse pour les cartes BlackBox
GUARDIA Cybersecurite B1

Detecte automatiquement les sondes ST-Link connectees, identifie le type
de carte (F7 ou F2) via le Device ID, et flashe le bon firmware.

Sequence par carte :
  1. Desactiver la protection Flash (RDP → level 0)
  2. Full chip erase
  3. Flash du firmware (.elf)
  4. Verification
  5. Demarrage

Usage :
    python flash_all.py              # Flash toutes les cartes detectees
    python flash_all.py --list       # Liste les cartes sans flasher
    python flash_all.py --only f7    # Flash seulement les F7
    python flash_all.py --only f2    # Flash seulement les F2
"""

import argparse
import os
import re
import subprocess
import sys
import time

try:
    import serial
    import serial.tools.list_ports
    HAS_PYSERIAL = True
except ImportError:
    HAS_PYSERIAL = False

# ── Chemins des firmwares (relatifs a la racine du projet) ──────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

FIRMWARE = {
    "f7": os.path.join(PROJECT_ROOT, "blackbox-f7", "Debug", "blackbox-f7.elf"),
    "f2": os.path.join(PROJECT_ROOT, "blackbox-f2", "Debug", "blackbox-f2.elf"),
}

# ── Device IDs STM32 (DBGMCU_IDCODE & 0xFFF) ──────────────────────────
DEVID_MAP = {
    0x451: "f7",   # STM32F76x / F75x
    0x449: "f7",   # STM32F74x / F75x (alt)
    0x411: "f2",   # STM32F2xx
}

CHIP_NAMES = {
    "f7": "STM32F756ZG (Cortex-M7)",
    "f2": "STM32F207ZG (Cortex-M3)",
}

# ── Chemins possibles pour STM32_Programmer_CLI ─────────────────────────
CLI_PATHS = [
    r"C:\Program Files\STMicroelectronics\STM32Cube\STM32CubeProgrammer\bin\STM32_Programmer_CLI.exe",
    r"C:\ST\STM32CubeIDE_2.1.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.cubeprogrammer.win32_2.2.400.202601091506\tools\bin\STM32_Programmer_CLI.exe",
]


def find_cli():
    """Trouve STM32_Programmer_CLI.exe sur le systeme."""
    for path in CLI_PATHS:
        if os.path.isfile(path):
            return path
    try:
        result = subprocess.run(
            ["where", "STM32_Programmer_CLI"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip().split("\n")[0]
    except Exception:
        pass
    return None


def run_cli(cli_path, args, timeout=30):
    """Execute STM32_Programmer_CLI avec des arguments et retourne la sortie."""
    cmd = [cli_path] + args
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout + result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]", -1
    except Exception as e:
        return f"[ERROR] {e}", -1


def list_probes(cli_path):
    """Liste les sondes ST-Link connectees. Retourne [serial_number]."""
    output, _ = run_cli(cli_path, ["--list"], timeout=15)
    probes = []
    probe_blocks = re.split(r"ST-Link Probe \d+", output)
    for block in probe_blocks[1:]:
        sn_match = re.search(r"ST-LINK SN\s*:\s*(\S+)", block)
        if sn_match:
            probes.append(sn_match.group(1))
    return probes


def detect_chip(cli_path, serial_number):
    """Connecte a une sonde et detecte le type de chip. Retourne 'f7', 'f2' ou None."""
    # Tenter connexion normale d'abord
    output, rc = run_cli(
        cli_path,
        ["--connect", "port=SWD", f"sn={serial_number}"],
        timeout=15
    )

    # Si connexion echoue, tenter sous reset (carte protegee)
    if rc != 0:
        output, rc = run_cli(
            cli_path,
            ["--connect", "port=SWD", f"sn={serial_number}", "reset=HWrst"],
            timeout=15
        )

    # Chercher "Device ID" dans la sortie
    devid_match = re.search(r"Device ID\s*:?\s*0x([0-9a-fA-F]+)", output)
    if devid_match:
        devid = int(devid_match.group(1), 16) & 0xFFF
        return DEVID_MAP.get(devid)

    # Fallback: chercher le nom du device
    if "STM32F7" in output or "F756" in output or "F746" in output:
        return "f7"
    if "STM32F2" in output or "F207" in output:
        return "f2"

    name_match = re.search(r"Device name\s*:?\s*(STM32\S+)", output)
    if name_match:
        name = name_match.group(1).upper()
        if "F7" in name:
            return "f7"
        if "F2" in name:
            return "f2"

    return None


def unlock_rdp(cli_path, serial_number):
    """Desactive la protection Flash (RDP → level 0). Retourne (success, message)."""
    output, rc = run_cli(
        cli_path,
        [
            "--connect", "port=SWD", f"sn={serial_number}", "reset=HWrst",
            "-ob", "RDP=0xAA",
        ],
        timeout=30
    )
    if rc == 0 and "Option Bytes successfully programmed" in output:
        return True, "RDP desactive"
    if rc == 0:
        return True, "RDP OK"
    # Si deja en level 0, ca peut echouer "silencieusement"
    if "Option Bytes successfully" in output:
        return True, "RDP deja level 0"
    error_match = re.search(r"Error[: ]+(.+)", output)
    error_msg = error_match.group(1).strip() if error_match else f"Exit code {rc}"
    return False, f"RDP echec: {error_msg}"


def erase_chip(cli_path, serial_number):
    """Full chip erase. Retourne (success, message)."""
    output, rc = run_cli(
        cli_path,
        [
            "--connect", "port=SWD", f"sn={serial_number}",
            "--erase", "all",
        ],
        timeout=60
    )
    if rc == 0 and "Mass erase successfully achieved" in output:
        return True, "Erase OK"
    if rc == 0:
        return True, "Erase OK"

    # Si erase echoue (protection), tenter sous reset
    output2, rc2 = run_cli(
        cli_path,
        [
            "--connect", "port=SWD", f"sn={serial_number}", "reset=HWrst",
            "--erase", "all",
        ],
        timeout=60
    )
    if rc2 == 0:
        return True, "Erase OK (via HW reset)"

    error_match = re.search(r"Error[: ]+(.+)", output + output2)
    error_msg = error_match.group(1).strip() if error_match else f"Exit code {rc}"
    return False, f"Erase echec: {error_msg}"


def flash_board(cli_path, serial_number, elf_path):
    """Flashe un firmware sur une carte via SWD. Retourne (success, message)."""
    if not os.path.isfile(elf_path):
        return False, f"Firmware introuvable : {elf_path}"

    output, rc = run_cli(
        cli_path,
        [
            "--connect", "port=SWD", f"sn={serial_number}",
            "--download", elf_path,
            "-V",
            "--start", "0x08000000",
        ],
        timeout=60
    )

    if rc == 0 and "File download complete" in output:
        if "Download verified successfully" in output:
            return True, "Flash + verify OK"
        return True, "Flash OK"
    if rc == 0:
        return True, "Flash OK (exit 0)"

    error_match = re.search(r"Error[: ]+(.+)", output)
    error_msg = error_match.group(1).strip() if error_match else f"Exit code {rc}"
    return False, error_msg


def verify_rdp(cli_path, serial_number):
    """Verifie que RDP est bien level 0 (ouvert). Retourne (ok, message)."""
    output, rc = run_cli(
        cli_path,
        ["--connect", "port=SWD", f"sn={serial_number}", "-ob", "displ"],
        timeout=15
    )
    # Chercher "RDP" dans la sortie des option bytes
    rdp_match = re.search(r"RDP\s*:?\s*0x([0-9a-fA-F]+)", output)
    if rdp_match:
        rdp_val = int(rdp_match.group(1), 16)
        if rdp_val == 0xAA:
            return True, "RDP = 0xAA (level 0, ouvert)"
        elif rdp_val == 0xCC:
            return False, f"RDP = 0x{rdp_val:02X} (level 2, VERROUILLE PERMANENT)"
        else:
            return False, f"RDP = 0x{rdp_val:02X} (level 1, protege)"
    # Fallback: chercher "Read Out Protection" ou "Level"
    if "Level 0" in output or "level 0" in output:
        return True, "RDP level 0 (ouvert)"
    if "Level 2" in output:
        return False, "RDP level 2 (VERROUILLE PERMANENT)"
    if "Level 1" in output:
        return False, "RDP level 1 (protege)"
    return False, "RDP inconnu (impossible de lire les option bytes)"


def find_stlink_com_ports():
    """Detecte les ports COM des ST-Link VCP. Retourne {sn_partiel: port_name}."""
    if not HAS_PYSERIAL:
        return {}
    ports = {}
    for port in serial.tools.list_ports.comports():
        desc = (port.description or "").lower()
        hwid = (port.hwid or "").upper()
        if "stlink" in desc or "st-link" in desc or "stmicroelectronics" in desc:
            # Extraire le SN du hwid (format: USB VID:PID=0483:374B SER=xxxx)
            sn_match = re.search(r"SER=([0-9A-Fa-f]+)", hwid)
            sn = sn_match.group(1) if sn_match else ""
            ports[sn] = port.device
    return ports


def match_com_port(stlink_sn, com_ports):
    """Associe un SN ST-Link a un port COM. Retourne le port ou None."""
    if not com_ports:
        return None
    # Correspondance exacte
    if stlink_sn in com_ports:
        return com_ports[stlink_sn]
    # Correspondance partielle (le SN USB peut etre tronque)
    for usb_sn, port in com_ports.items():
        if usb_sn and (stlink_sn.startswith(usb_sn) or usb_sn.startswith(stlink_sn)):
            return port
    # Si une seule sonde, on peut l'associer directement
    if len(com_ports) == 1:
        return list(com_ports.values())[0]
    return None


def test_uart(com_port, timeout_s=4):
    """
    Teste la communication UART sur un port COM.
    Envoie \\r\\n, attend la reponse, cherche le prompt 'bb>' ou la banniere.
    Retourne (ok, message).
    """
    if not HAS_PYSERIAL:
        return False, "pyserial non installe (pip install pyserial)"
    try:
        ser = serial.Serial(com_port, 115200, timeout=timeout_s)
    except serial.SerialException as e:
        return False, f"Impossible d'ouvrir {com_port}: {e}"

    try:
        # Vider le buffer
        ser.reset_input_buffer()

        # Envoyer un retour chariot pour declencher le prompt
        time.sleep(0.3)
        ser.write(b"\r\n")
        time.sleep(0.5)

        # Lire tout ce qui arrive
        data = b""
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            chunk = ser.read(ser.in_waiting or 1)
            if chunk:
                data += chunk
            if b"bb>" in data or b"bb [" in data:
                break

        text = data.decode("ascii", errors="replace").strip()

        if "bb>" in text or "bb [connecte]>" in text or "bb [sudo]>" in text:
            return True, f"Prompt ok ({com_port})"
        if "BLACKBOX" in text.upper() or "FDR" in text.upper():
            return True, f"Banniere ok ({com_port})"
        if text:
            # On a recu quelque chose mais pas le prompt attendu
            preview = text[:60].replace("\r", "").replace("\n", " ")
            return False, f"Reponse inattendue: '{preview}...'"
        return False, f"Pas de reponse UART sur {com_port}"
    finally:
        ser.close()



def flash_sequence(cli_path, serial_number, chip, elf_path):
    """
    Sequence complete pour une carte :
      1. Unlock RDP (desactive protection Flash)
      2. Full chip erase
      3. Flash firmware
    Retourne (success, message, duree).
    """
    t0 = time.time()
    steps = []

    # Etape 1 : Unlock RDP
    ok, msg = unlock_rdp(cli_path, serial_number)
    steps.append(f"RDP:{msg}")
    if not ok:
        dt = time.time() - t0
        return False, " | ".join(steps), dt

    # Petite pause pour laisser le ST-Link se re-synchro apres RDP change
    time.sleep(1)

    # Etape 2 : Full erase
    ok, msg = erase_chip(cli_path, serial_number)
    steps.append(f"Erase:{msg}")
    if not ok:
        dt = time.time() - t0
        return False, " | ".join(steps), dt

    # Etape 3 : Flash + verify + start
    ok, msg = flash_board(cli_path, serial_number, elf_path)
    steps.append(msg)

    dt = time.time() - t0
    return ok, " | ".join(steps) if not ok else msg, dt


def print_header():
    print()
    print("=" * 64)
    print("  BLACKBOX MASS FLASHER -- GUARDIA Cybersecurite B1")
    print("  Sequence : RDP unlock > full erase > flash > verify > start")
    print("=" * 64)
    print()


def print_table(rows, headers):
    """Affiche un tableau formate en texte."""
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    fmt = "  ".join(f"{{:<{w}}}" for w in col_widths)
    print(fmt.format(*headers))
    print(fmt.format(*["-" * w for w in col_widths]))
    for row in rows:
        print(fmt.format(*row))


def main():
    parser = argparse.ArgumentParser(
        description="Flash en masse des cartes BlackBox (F7/F2)"
    )
    parser.add_argument(
        "--list", action="store_true",
        help="Liste les cartes detectees sans flasher"
    )
    parser.add_argument(
        "--only", choices=["f7", "f2"],
        help="Flash seulement un type de carte"
    )
    args = parser.parse_args()

    print_header()

    # 1. Trouver STM32_Programmer_CLI
    cli = find_cli()
    if not cli:
        print("[ERREUR] STM32_Programmer_CLI.exe introuvable.")
        print("Installez STM32CubeProgrammer ou ajoutez-le au PATH.")
        sys.exit(1)
    print(f"[OK] Programmer CLI : {os.path.basename(cli)}")

    # 2. Verifier les firmwares
    for variant, path in FIRMWARE.items():
        if os.path.isfile(path):
            size_kb = os.path.getsize(path) / 1024
            print(f"[OK] Firmware {variant.upper()} : {os.path.basename(path)} ({size_kb:.0f} KB)")
        else:
            print(f"[!!] Firmware {variant.upper()} : INTROUVABLE ({path})")
            if not args.list:
                print(f"     Compilez le projet {variant.upper()} dans CubeIDE d'abord.")

    print()

    # 3. Lister les sondes
    print("Recherche des sondes ST-Link...")
    probes = list_probes(cli)

    if not probes:
        print("[ERREUR] Aucune sonde ST-Link detectee.")
        print("Verifiez les cables USB et les drivers ST-Link.")
        sys.exit(1)

    print(f"[OK] {len(probes)} sonde(s) detectee(s)")
    print()

    # 4. Detecter le type de chaque carte
    boards = []
    for i, sn in enumerate(probes):
        sys.stdout.write(f"\r  Detection carte {i+1}/{len(probes)} (SN: {sn[:8]}...)  ")
        sys.stdout.flush()
        chip = detect_chip(cli, sn)
        chip_name = CHIP_NAMES.get(chip, "??? (non identifie)")
        boards.append((sn, chip, chip_name))
    print()
    print()

    # 5. Afficher le tableau
    table_rows = []
    for i, (sn, chip, name) in enumerate(boards):
        variant = chip.upper() if chip else "???"
        table_rows.append((str(i + 1), sn[:16] + "...", variant, name))

    print_table(
        table_rows,
        ["#", "ST-Link SN", "Type", "Chip"]
    )
    print()

    # Stats
    n_f7 = sum(1 for _, c, _ in boards if c == "f7")
    n_f2 = sum(1 for _, c, _ in boards if c == "f2")
    n_unk = sum(1 for _, c, _ in boards if c is None)
    print(f"  Resume : {n_f7} x F7, {n_f2} x F2", end="")
    if n_unk:
        print(f", {n_unk} x non identifie(s)", end="")
    print()

    if args.list:
        print("\n  Mode --list : pas de flash.")
        return

    # 6. Filtrer selon --only
    to_flash = []
    for sn, chip, name in boards:
        if chip is None:
            print(f"  [SKIP] SN {sn[:16]}... -- type inconnu, impossible de flasher")
            continue
        if args.only and chip != args.only:
            continue
        fw = FIRMWARE.get(chip)
        if not os.path.isfile(fw):
            print(f"  [SKIP] SN {sn[:16]}... -- firmware {chip.upper()} introuvable")
            continue
        to_flash.append((sn, chip, name, fw))

    if not to_flash:
        print("\n  Aucune carte a flasher.")
        return

    # 7. Confirmation
    print(f"\n  {len(to_flash)} carte(s) a flasher.")
    print("  Sequence par carte : RDP unlock > erase all > flash > verify > start")
    try:
        answer = input("  Continuer ? [O/n] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = "n"
    if answer and answer not in ("o", "y", "oui", "yes", ""):
        print("  Annule.")
        return

    # 8. Flash sequence par carte
    print()
    results = []
    for i, (sn, chip, name, fw) in enumerate(to_flash):
        label = f"[{i+1}/{len(to_flash)}] {chip.upper()} (SN: {sn[:8]}...)"

        # Etape 1 : RDP unlock
        sys.stdout.write(f"  {label} -- RDP unlock...")
        sys.stdout.flush()
        rdp_ok, rdp_msg = unlock_rdp(cli, sn)
        if not rdp_ok:
            print(f"\r  {label} -- ECHEC RDP : {rdp_msg}")
            results.append((str(i + 1), chip.upper(), sn[:16] + "...", "ECHEC", "-", rdp_msg))
            continue

        # Verifier que RDP est bien ouvert
        rdp_check, rdp_detail = verify_rdp(cli, sn)
        if not rdp_check:
            print(f"\r  {label} -- RDP toujours protege : {rdp_detail}")
            results.append((str(i + 1), chip.upper(), sn[:16] + "...", "ECHEC", "-", rdp_detail))
            continue

        time.sleep(1)

        # Etape 2 : Erase all
        sys.stdout.write(f"\r  {label} -- erase all...        ")
        sys.stdout.flush()
        erase_ok, erase_msg = erase_chip(cli, sn)
        if not erase_ok:
            print(f"\r  {label} -- ECHEC erase : {erase_msg}")
            results.append((str(i + 1), chip.upper(), sn[:16] + "...", "ECHEC", "-", erase_msg))
            continue

        # Etape 3 : Flash + verify + start
        sys.stdout.write(f"\r  {label} -- flash + verify...   ")
        sys.stdout.flush()
        t0 = time.time()
        flash_ok, flash_msg = flash_board(cli, sn, fw)
        dt = time.time() - t0

        status = "OK" if flash_ok else "ECHEC"
        results.append((str(i + 1), chip.upper(), sn[:16] + "...", status, f"{dt:.1f}s", flash_msg))

        if flash_ok:
            print(f"\r  {label} -- OK ({dt:.1f}s)                ")
        else:
            print(f"\r  {label} -- ECHEC flash : {flash_msg}")

    # 9. Rapport final
    print()
    print("=" * 64)
    print("  RAPPORT DE FLASH")
    print("=" * 64)
    print()
    print_table(
        results,
        ["#", "Type", "ST-Link SN", "Status", "Duree", "Detail"]
    )

    n_ok = sum(1 for r in results if r[3] == "OK")
    n_fail = len(results) - n_ok
    print()
    print(f"  {n_ok}/{len(results)} cartes flashees avec succes.", end="")
    if n_fail:
        print(f"  {n_fail} echec(s).", end="")
    print()

    # 10. Verification post-flash (UART)
    flashed_ok = [(sn, chip) for (sn, chip, _, fw), r
                  in zip(to_flash, results) if r[3] == "OK"]

    if flashed_ok and HAS_PYSERIAL:
        print()
        print("=" * 64)
        print("  VERIFICATION POST-FLASH (UART + RDP)")
        print("=" * 64)
        print()

        # Detecter les ports COM ST-Link
        com_ports = find_stlink_com_ports()
        if com_ports:
            print(f"  [OK] {len(com_ports)} port(s) COM ST-Link detecte(s)")
            for usb_sn, port in com_ports.items():
                print(f"       {port} (SN: {usb_sn[:16]}...)" if usb_sn else f"       {port}")
        else:
            print("  [!!] Aucun port COM ST-Link detecte (VCP driver installe ?)")

        print()
        uart_results = []

        for sn, chip in flashed_ok:
            label = f"{chip.upper()} (SN: {sn[:8]}...)"

            # Test RDP
            rdp_ok, rdp_msg = verify_rdp(cli, sn)
            rdp_status = "OK" if rdp_ok else "ECHEC"

            # Test UART
            com = match_com_port(sn, com_ports)
            if com:
                # Laisser le firmware booter
                time.sleep(1)
                uart_ok, uart_msg = test_uart(com)
                uart_status = "OK" if uart_ok else "ECHEC"
            else:
                uart_ok = False
                uart_msg = "Port COM non trouve"
                uart_status = "SKIP"

            uart_results.append((label, rdp_status, rdp_msg, uart_status, uart_msg))
            print(f"  {label}  RDP:{rdp_status}  UART:{uart_status}")

        # Tableau verification
        print()
        print_table(
            [(r[0], r[1], r[2], r[3], r[4]) for r in uart_results],
            ["Carte", "RDP", "Detail RDP", "UART", "Detail UART"]
        )

        n_uart_ok = sum(1 for r in uart_results if r[3] == "OK")
        n_rdp_ok = sum(1 for r in uart_results if r[1] == "OK")
        print()
        print(f"  RDP ouvert : {n_rdp_ok}/{len(uart_results)}")
        print(f"  UART ok    : {n_uart_ok}/{len(uart_results)}")

    elif flashed_ok and not HAS_PYSERIAL:
        print()
        print("  [INFO] pyserial non installe -- test UART ignore")
        print("         pip install pyserial")

        # Verification RDP seulement
        print()
        print("  Verification RDP :")
        for sn, chip in flashed_ok:
            label = f"{chip.upper()} (SN: {sn[:8]}...)"
            rdp_ok, rdp_msg = verify_rdp(cli, sn)
            status = "OK" if rdp_ok else "ECHEC"
            print(f"    {label} -- RDP: {status} -- {rdp_msg}")

    print()


if __name__ == "__main__":
    main()
