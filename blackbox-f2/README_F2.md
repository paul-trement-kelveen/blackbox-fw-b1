# BlackBox F2 — STM32F207ZGTx (Nucleo-144 F2)

Portage du firmware BlackBox pour la carte **NUCLEO-F207ZG**.

## Différences F7 → F2

| Fonctionnalité | F7 (STM32F756ZG) | F2 (STM32F207ZG) |
|----------------|:----------------:|:----------------:|
| Cortex-M | M7 @ 216 MHz | M3 @ 120 MHz |
| UART3 (PD8/PD9) | ✓ | ✓ |
| SPI1 (PA4-PA7) | ✓ | ✓ |
| GPIO LEDs (PB0/7/14) | ✓ | ✓ |
| HAL_RNG | ✓ | ✓ |
| HAL_HASH (SHA-256 HW) | ✓ | ✗ |
| SHA-256 (software `bb_sha256`) | — | ✓ |

## Fichiers spécifiques F2

| Fichier | Rôle |
|---------|------|
| `Core/Inc/bb_sha256.h` | Interface SHA-256 software |
| `Core/Src/bb_sha256.c` | Implémentation SHA-256 (domaine public) |
| `Core/Inc/blackbox.h` | `#include "stm32f2xx_hal.h"` (au lieu de f7) |
| `Core/Src/bb_auth.c` | Sans `extern HASH_HandleTypeDef`, avec `#include "bb_sha256.h"` |
| `Core/Src/bb_status.c` | FW_TARGET = "STM32F207ZG", FW_CPU = "Cortex-M3 @ 120 MHz" |
| `Core/Src/blackbox.c` | Message de boot indique F2 |

## Fichiers identiques F7 ↔ F2

Ces fichiers sont les mêmes sur les deux cibles :
- `bb_config.h`, `bb_fwdump.h`, `bb_logs.h`, `bb_shell.h`, `bb_leds.h`, `bb_status.h`, `bb_auth.h`
- `bb_fwdump.c`, `bb_logs.c`, `bb_shell.c`, `bb_leds.c`

## Configuration CubeMX pour F2

Créer un nouveau projet CubeMX avec `STM32F207ZGTx` et activer :

| Périphérique | Config |
|-------------|--------|
| USART3 | Asynchrone 115200, PD8=TX, PD9=RX |
| SPI1 | Full-Duplex Master, PA4=NSS(SW), PA5=SCK, PA7=MOSI |
| RNG | Activé (pour C10) |
| GPIO | PB0=LD1, PB7=LD2, PB14=LD3 (Output Push-Pull) |
| ~~HASH~~ | **Non disponible sur F207** — utiliser `bb_sha256.c` |

## Correction C9 sur F2 (SHA-256 software)

Au lieu de `HAL_HASH_SHA256_Start()`, utiliser :

```c
#include "bb_sha256.h"

uint8_t digest[32];
bb_sha256((uint8_t *)pin_saisi, strlen(pin_saisi), digest);
if (memcmp(digest, PIN_HASH, 32) == 0) {
    /* connexion reussie */
}
```

Interface identique du point de vue de l'étudiant.
`scripts/hash_pin.py` génère le même tableau C pour F2 et F7.

## Ajouter les fichiers au build CubeIDE

Dans STM32CubeIDE, clic droit sur `Core/Src/` → **Add existing files** :
- `bb_auth.c`, `bb_logs.c`, `bb_fwdump.c`, `bb_shell.c`, `bb_leds.c`, `bb_status.c`, `blackbox.c`
- **`bb_sha256.c`** ← spécifique F2

Appeler `blackbox_run(&huart3)` depuis `main.c` (identique F7).

## Données FDR

Au boot, 5 enregistrements de vol (Flight Data Recorder) sont automatiquement chargés,
identiques à la version F7. Le scénario et les vulnérabilités sont les mêmes.
