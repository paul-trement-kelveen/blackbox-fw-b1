/*
 * bb_fwdump.c — Export des logs vers SPI1 (FWDUMP)
 *
 * Responsabilite unique : serialiser les logs et les envoyer
 * vers un dispositif externe via le bus SPI1.
 *
 * Etat actuel (template Phase 2) :
 *   L'envoi se fait encore sur UART — le SPI n'est pas implemente.
 *   Les donnees ne sont pas chiffrees.
 *
 * Vulnerabilites presentes :
 *   V7 — donnees envoyees en clair (pas de XOR)
 *   V9 — pas de verification d'integrite (pas de checksum/CRC)
 *
 * ┌───────────────────────────────────────────────────────────────────┐
 * │ VULNERABILITE V9 — Pas de verification d'integrite (CWE-354)     │
 * │                                                                   │
 * │ Incident reel : attaque SolarWinds / SUNBURST (2020).            │
 * │ Des attaquants ont modifie des mises a jour logicielles en       │
 * │ transit. L'absence de verification d'integrite (signature,       │
 * │ checksum) a permis de distribuer du code malveillant a 18 000   │
 * │ organisations sans detection.                                    │
 * │                                                                   │
 * │ Ici, la trame FWDUMP n'a ni CRC ni HMAC. Un attaquant sur le   │
 * │ bus SPI (man-in-the-middle) peut modifier les logs en transit    │
 * │ sans que le recepteur detecte l'alteration.                      │
 * │                                                                   │
 * │ Correction C13 : ajouter un CRC-8 ou un XOR-checksum en fin    │
 * │ de trame. Le recepteur recalcule et compare.                    │
 * └───────────────────────────────────────────────────────────────────┘
 *
 * Corrections attendues :
 *   C7  — remplacer l'envoi UART par HAL_SPI_Transmit
 *   C8  — XOR chaque octet de data avec XOR_KEY avant envoi SPI
 *   C13 — ajouter un checksum de trame (CRC-8 ou XOR de tous les octets)
 *
 * Brochage SPI1 sur Nucleo-144 F756ZG :
 *   PA4 = NSS  (chip select, gere en software)
 *   PA5 = SCK  (horloge)
 *   PA6 = MISO (non utilise pour l'envoi)
 *   PA7 = MOSI (donnees vers le recepteur)
 */

#include "bb_fwdump.h"
#include "bb_auth.h"
#include "bb_logs.h"
#include "bb_shell.h"
#include "bb_config.h"
#include <string.h>
#include <stdio.h>

/* Peripherique SPI genere par CubeMX (utilise apres correction C7) */
extern SPI_HandleTypeDef hspi1;

/* ── Constantes de trame ────────────────────────────────────── */

#define TRAME_DEBUT_0   0xBB
#define TRAME_DEBUT_1   0xAA
#define TRAME_FIN_0     0xEE
#define TRAME_FIN_1     0xFF

/* ── Fonctions privees ──────────────────────────────────────── */

/*
 * envoyer_octet_spi — envoie un seul octet via SPI1.
 *
 * TODO C7 : remplacer l'envoi UART par HAL_SPI_Transmit :
 *   HAL_SPI_Transmit(&hspi1, &octet, 1, 100);
 *
 * TODO C8 : chiffrer l'octet avant envoi.
 *   ATTENTION : si C6 est implemente, logs_get() retourne deja des
 *   octets XOR'd. Dans ce cas, transmettez-les directement (pas de
 *   XOR supplementaire — sinon double-XOR = plaintext sur le bus).
 *   Si C6 n'est PAS fait : XOR ici avant envoi.
 *
 *   Autrement dit : C6 OU C8 chiffre, pas les deux.
 *   Choisissez l'un des deux selon votre implementation.
 */
static void envoyer_octet_spi(uint8_t octet)
{
    /* TODO C7 : remplacer cet envoi UART par HAL_SPI_Transmit */
    /* TODO C8 : voir commentaire ci-dessus (attention double-XOR) */

    /* Version temporaire (VULNERABILITE V7) : envoi sur UART en clair */
    char tmp[4];
    snprintf(tmp, sizeof(tmp), "%02X ", octet);
    shell_envoyer(tmp);
}

static void envoyer_trame_debut(uint8_t nb)
{
    envoyer_octet_spi(TRAME_DEBUT_0);
    envoyer_octet_spi(TRAME_DEBUT_1);
    envoyer_octet_spi(nb);
}

static void envoyer_trame_fin(void)
{
    envoyer_octet_spi(TRAME_FIN_0);
    envoyer_octet_spi(TRAME_FIN_1);
}

/* ── Fonction publique ──────────────────────────────────────── */

void fwdump_cmd_executer(void)
{
    if (!auth_est_connecte()) {
        shell_envoyer("Erreur : vous devez etre connecte.\r\n");
        return;
    }

    int nb = logs_count();
    if (nb == 0) {
        shell_envoyer("Aucun log a exporter.\r\n");
        return;
    }

    shell_envoyer("FWDUMP debut : ");

    envoyer_trame_debut((uint8_t)nb);

    for (int i = 0; i < nb; i++) {
        const char *log = logs_get(i);
        if (log == NULL) continue;

        uint8_t longueur = (uint8_t)strlen(log);
        envoyer_octet_spi(longueur);

        /* Envoyer les octets du message */
        for (int j = 0; j < longueur; j++) {
            envoyer_octet_spi((uint8_t)log[j]);
        }
    }

    envoyer_trame_fin();

    /* VULNERABILITE V9 : pas de checksum / CRC.
     *
     * TODO C13 : ajouter un octet de verification AVANT envoyer_trame_fin().
     * Methode simple — XOR checksum :
     *   uint8_t checksum = 0;
     *   // XOR de tous les octets envoyes (debut, longueur, data)
     *   checksum ^= TRAME_DEBUT_0;
     *   checksum ^= TRAME_DEBUT_1;
     *   checksum ^= (uint8_t)nb;
     *   for (int i = 0; i < nb; i++) {
     *       const char *l = logs_get(i);
     *       uint8_t len = (uint8_t)strlen(l);
     *       checksum ^= len;
     *       for (int j = 0; j < len; j++)
     *           checksum ^= (uint8_t)l[j];
     *   }
     *   envoyer_octet_spi(checksum);
     *
     * Le recepteur (spi_receive.py) recalcule le XOR et compare.
     * Si ca ne matche pas → les donnees ont ete modifiees en transit.
     */

    shell_envoyer("\r\nFWDUMP fin.\r\n");
}
