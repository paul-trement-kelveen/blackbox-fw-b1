# BlackBox FDR — Firmware Source

**B1 Cybersécurité — GUARDIA**

Ce dépôt contient le code source du firmware BlackBox FDR pour les deux
variantes de la carte Nucleo-144.

## Contenu

```
blackbox-f7/   ← Firmware STM32F756ZG  (Cortex-M7, 216 MHz, 1 MB Flash)
blackbox-f2/   ← Firmware STM32F207ZG  (Cortex-M3, 120 MHz, 1 MB Flash)
```

## Prise en main

1. Ouvrez **STM32CubeIDE**
2. `File → Import → Existing Projects into Workspace`
3. Sélectionnez le dossier `blackbox-f7/` ou `blackbox-f2/`
4. Compilez (`Ctrl+B`) puis flashez (`Run → Run`)

Référez-vous au document **01_SETUP_ETUDIANTS.md** distribué en cours
pour les instructions détaillées d'installation et de configuration.

## Architecture

| Fichier | Rôle |
|---------|------|
| `bb_config.h` | Constantes (PIN, clé XOR, limites) |
| `bb_auth.c/h` | Login, logout, su |
| `bb_logs.c/h` | Écriture/lecture/effacement logs FDR |
| `bb_fwdump.c/h` | Export données (SPI) |
| `bb_shell.c/h` | Communication UART |
| `bb_leds.c/h` | Indicateurs visuels |
| `bb_status.c/h` | Commandes status/sensor/version |
| `blackbox.c/h` | Dispatcher principal (boucle `while(1)`) |
