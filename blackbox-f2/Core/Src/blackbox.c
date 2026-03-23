/*
 * blackbox.c — Point d'entree et boucle principale du firmware BlackBox
 * Version F2 : STM32F207ZGTx (Nucleo-144 F2)
 *
 * Identique a la version F7 sauf :
 *   - Message de boot indique "F2 — STM32F207ZG"
 *   - C9 : le hash SHA-256 utilise bb_sha256() (software), pas HAL_HASH
 *   - C10 : HAL_RNG disponible sur F207ZG (meme API que F7)
 *
 * Ce fichier contient uniquement :
 *   1. L'initialisation de tous les modules
 *   2. La boucle principale (while 1)
 *   3. Le dispatcher de commandes
 *
 * Toute la logique metier est dans les modules :
 *   bb_auth.c    — authentification
 *   bb_logs.c    — gestion des logs
 *   bb_fwdump.c  — export SPI
 *   bb_shell.c   — communication UART
 *   bb_leds.c    — indicateurs visuels (LEDs)
 *   bb_status.c  — informations systeme et capteurs
 *
 * VULNERABILITE VH4 (cachee) :
 *   La commande "su" est dispatchee sans verifier auth_est_connecte().
 *   Un attaquant peut tenter de devenir sudo sans avoir fait login.
 *   Correction C11 : ajouter cette verification dans auth_cmd_su().
 *
 * VULNERABILITE VH5 (cachee) :
 *   La commande "history" est dispatchee sans verifier auth_est_connecte().
 *   Combine avec V2 (PIN en clair dans l'historique), un attaquant peut
 *   voir le PIN sans meme etre connecte.
 *   Correction C14 : ajouter la verification avant shell_cmd_historique().
 */

#include "blackbox.h"
#include "bb_config.h"
#include "bb_shell.h"
#include "bb_auth.h"
#include "bb_logs.h"
#include "bb_fwdump.h"
#include "bb_leds.h"
#include "bb_status.h"
#include <string.h>
#include <stdio.h>

/* Peripherique HAL genere par CubeMX (pour correction C10 : cle aleatoire) */
extern RNG_HandleTypeDef hrng;

/* ── Fonctions privees ──────────────────────────────────────── */

static void afficher_prompt(void)
{
    char prompt[32];

    if (auth_est_sudo())
        snprintf(prompt, sizeof(prompt), "bb [sudo]> ");
    else if (auth_est_connecte())
        snprintf(prompt, sizeof(prompt), "bb [connecte]> ");
    else
        snprintf(prompt, sizeof(prompt), "bb> ");

    shell_envoyer(prompt);
}

static void message_bienvenue(void)
{
    shell_envoyer("\r\n");
    shell_envoyer("============================================\r\n");
    shell_envoyer("  BLACKBOX FDR  |  Flight Data Recorder\r\n");
    shell_envoyer("  B1 Cybersecurite — GUARDIA\r\n");
    shell_envoyer("  Firmware v2.2  —  F2 / STM32F207ZG\r\n");
    shell_envoyer("============================================\r\n");
    shell_envoyer("  Vol AF-7721 | LFPG (CDG) | 2025-11-14\r\n");
    shell_envoyer("  Status: 5 enregistrements FDR charges\r\n");
    shell_envoyer("============================================\r\n");
    shell_envoyer("Tapez 'help' pour voir les commandes.\r\n");
    shell_envoyer("\r\n");
}

/* ── Point d'entree ─────────────────────────────────────────── */

void blackbox_run(UART_HandleTypeDef *huart)
{
    /* Initialisation des modules */
    shell_init(huart);
    auth_init();
    logs_init();
    leds_init();

    /* Flash des 3 LEDs au boot (confirmation visuelle) */
    leds_boot_flash();

    /* Chargement des donnees FDR (boite noire) au boot.
     * Simule les derniers enregistrements avant un incident. */
    logs_precharger_fdr();

    /* TODO C10 : generer une cle XOR aleatoire via RNG.
     *
     * Le peripherique RNG (Random Number Generator) du STM32 genere
     * de vrais nombres aleatoires a partir du bruit electrique interne.
     *
     * Exemple :
     *   uint32_t rng_val;
     *   if (HAL_RNG_GenerateRandomNumber(&hrng, &rng_val) == HAL_OK)
     *       xor_key = (uint8_t)(rng_val & 0xFF);
     *
     * Pour stocker la cle dynamique :
     *   1. Ajouter dans bb_config.h  : extern uint8_t xor_key;
     *   2. Ajouter dans blackbox.c   : uint8_t xor_key = XOR_KEY;
     *   3. Dans bb_logs.c et bb_fwdump.c : utiliser xor_key au lieu de XOR_KEY
     */

    message_bienvenue();

    char commande[CMD_SIZE];

    while (1)
    {
        /* VULNERABILITE V8 : la session ne s'expire jamais.
         *
         * TODO C12 : ajouter ici, avant le prompt :
         *   auth_verifier_timeout();
         *
         * Et apres l'execution de chaque commande :
         *   auth_touch_session();
         *
         * Real-world : botnet Mirai (2016) — sessions IoT persistantes.
         * CVE-2019-16278 : session sans expiration dans Nostromo.
         */
        afficher_prompt();
        shell_lire_ligne(commande, sizeof(commande));

        if (strlen(commande) == 0) continue;

        /* Sauvegarder dans l'historique AVANT d'executer.
         * VULNERABILITE V2 : "login XXXX" est stocke en clair.
         * Correction C4 : implementee dans shell_historique_ajouter(). */
        shell_historique_ajouter(commande);

        /* ── Dispatcher ────────────────────────────────────────
         * Chaque branche teste une commande et appelle le module
         * correspondant. La syntaxe "commande + 6" est du calcul
         * de pointeur : elle saute les 6 premiers caracteres pour
         * isoler l'argument. Ex : "login 0000" + 6 = "0000"
         * ──────────────────────────────────────────────────────── */

        if (strcmp(commande, "help") == 0) {
            shell_cmd_aide();

        } else if (strncmp(commande, "login ", 6) == 0) {
            auth_cmd_login(commande + 6);
            leds_maj_etat();

        } else if (strcmp(commande, "logout") == 0) {
            auth_cmd_logout();
            leds_maj_etat();

        } else if (strncmp(commande, "log write ", 10) == 0) {
            logs_cmd_ecrire(commande + 10);

        } else if (strcmp(commande, "log read") == 0) {
            logs_cmd_lire();

        } else if (strcmp(commande, "log clear") == 0) {
            logs_cmd_effacer();

        } else if (strcmp(commande, "history") == 0) {
            /* VH5 : history dispatche sans verifier auth_est_connecte().
             *
             * Un attaquant non connecte peut voir l'historique, qui
             * contient potentiellement "login 0000" en clair (si V2
             * n'est pas corrigee).
             *
             * Incident reel : CVE-2023-46747 (F5 BIG-IP, CVSS 9.8).
             * Fuite d'informations sensibles a travers un endpoint
             * accessible sans authentification.
             *
             * Correction C14 : ajouter la verification dans
             * shell_cmd_historique() ou ici dans le dispatcher. */
            shell_cmd_historique();

        } else if (strcmp(commande, "fwdump") == 0) {
            fwdump_cmd_executer();

        } else if (strncmp(commande, "su ", 3) == 0) {
            /* VH4 : su dispatche sans verifier auth_est_connecte().
             * Correction dans auth_cmd_su() — TODO C11. */
            auth_cmd_su(commande + 3);
            leds_maj_etat();

        } else if (strcmp(commande, "status") == 0) {
            status_cmd_afficher();

        } else if (strcmp(commande, "sensor") == 0) {
            sensor_cmd_lire();

        } else if (strcmp(commande, "version") == 0) {
            /* Commande NON DOCUMENTEE — fuite d'info volontaire.
             * Accessible sans auth (comme un serveur HTTP non durci).
             * A trouver via "strings" sur le binaire ou brute-force shell. */
            version_cmd_afficher();

        } else {
            shell_envoyer("Commande inconnue. Tapez 'help'.\r\n");
        }
    }
}
