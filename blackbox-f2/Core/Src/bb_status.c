/*
 * bb_status.c — Commandes d'information systeme
 *
 * Ce module fournit trois commandes pour visualiser l'etat du systeme :
 *
 *   "status"  — resume de l'etat (uptime, logs, auth)
 *   "sensor"  — lecture de capteurs internes (temperature, Vdd, RAM)
 *   "version" — informations firmware detaillees (commande cachee)
 *
 * Pour la retro-conception :
 *   - Les chaines de version sont detectables avec "strings" sur le .elf
 *   - Le format SENSOR:<type>=<valeur> peut etre decode depuis un dump UART
 *   - La commande "version" n'est pas listee dans le help
 *
 * Dependances :
 *   - bb_shell.h   : shell_envoyer()
 *   - bb_auth.h    : auth_est_connecte(), auth_est_sudo()
 *   - bb_logs.h    : logs_count()
 *   - bb_config.h  : MAX_LOGS, LOG_SIZE
 *   - HAL          : HAL_GetTick()
 */

#include "bb_status.h"
#include "bb_shell.h"
#include "bb_auth.h"
#include "bb_logs.h"
#include "bb_config.h"
#include <stdio.h>
#include <string.h>
/* Peripherique RNG pour generer des donnees de capteur pseudo-realistes */
extern RNG_HandleTypeDef hrng;

/* ── Chaines de version ──────────────────────────────────────
 * Visibles avec "strings blackbox-f7.elf | grep -i version"
 * Les etudiants peuvent retrouver ces informations dans le binaire
 * AVANT d'avoir le code source (Phase 1A — retro-conception).
 * ──────────────────────────────────────────────────────────── */

static const char FW_NAME[]    = "BlackBox FDR";
static const char FW_VERSION[] = "v2.2";
static const char FW_BUILD[]   = __DATE__ " " __TIME__;
static const char FW_TARGET[]  = "STM32F207ZG";
static const char FW_CPU[]     = "Cortex-M3 @ 120 MHz";
static const char FW_AUTHOR[]  = "GUARDIA Cybersec B1";

/* Signature cachee dans le binaire — retrouvable avec strings */
static const char FW_SECRET_TAG[] = "<<BLACKBOX_BUILD_SIGNATURE_2025>>";

/* ── Fonctions privees ──────────────────────────────────────── */

static void afficher_uptime(void)
{
    uint32_t ms = HAL_GetTick();
    uint32_t sec = ms / 1000;
    uint32_t min = sec / 60;
    uint32_t hrs = min / 60;

    char buf[64];
    snprintf(buf, sizeof(buf), "  Uptime    : %lu h %02lu min %02lu sec\r\n",
             (unsigned long)hrs,
             (unsigned long)(min % 60),
             (unsigned long)(sec % 60));
    shell_envoyer(buf);
}

/* ── Fonctions publiques ────────────────────────────────────── */

void status_cmd_afficher(void)
{
    char buf[96];

    shell_envoyer("--- STATUS " FDR_SERIAL_NO " ---\r\n");

    /* Uptime toujours visible */
    afficher_uptime();

    /* Nombre d'enregistrements — visible sans authentification
     * (monitoring externe, affichage cockpit) */
    snprintf(buf, sizeof(buf), "  FDR       : %d enreg. / %d max\r\n",
             logs_count(), MAX_LOGS);
    shell_envoyer(buf);

    if (!auth_est_connecte()) {
        shell_envoyer("  Auth      : non connecte\r\n");
        shell_envoyer("  (connectez-vous pour plus d'infos)\r\n");
        shell_envoyer("---------------------\r\n");
        return;
    }

    /* Etat auth */
    if (auth_est_sudo())
        shell_envoyer("  Auth      : SUDO\r\n");
    else
        shell_envoyer("  Auth      : CREW\r\n");

    /* Version courte */
    snprintf(buf, sizeof(buf), "  Firmware  : %s %s\r\n", FW_NAME, FW_VERSION);
    shell_envoyer(buf);

    /* Memoire */
    snprintf(buf, sizeof(buf), "  RAM logs  : %d o / %d max\r\n",
             logs_count() * LOG_SIZE, MAX_LOGS * LOG_SIZE);
    shell_envoyer(buf);

    /* Standard */
    shell_envoyer("  Standard  : " FDR_STD_REF "\r\n");

    shell_envoyer("---------------------\r\n");
}

void sensor_cmd_lire(void)
{
    if (!auth_est_connecte()) {
        shell_envoyer("Erreur : vous devez etre connecte.\r\n");
        return;
    }

    char buf[80];

    shell_envoyer("--- SENSOR DATA ---\r\n");

    /* Temperature interne — utilise le RNG comme source d'entropie
     * pour simuler une variation realiste autour de 35°C.
     * Sur un vrai produit, on utiliserait l'ADC + canal temperature interne.
     *
     * Pour la retro-conception :
     *   Le format "SENSOR:<type>=<valeur><unite>" est un protocole
     *   a decoder par les etudiants depuis un dump UART brut. */
    uint32_t rng_val = 0;
    if (HAL_RNG_GenerateRandomNumber(&hrng, &rng_val) == HAL_OK) {
        int temp_base = 33;
        int temp_var  = (int)(rng_val % 8);  /* variation 0-7 */
        snprintf(buf, sizeof(buf), "  SENSOR:TEMP=%d.%dC\r\n",
                 temp_base + temp_var / 2, (temp_var % 2) * 5);
    } else {
        snprintf(buf, sizeof(buf), "  SENSOR:TEMP=ERR\r\n");
    }
    shell_envoyer(buf);

    /* Tension Vdd estimee — simulee via RNG */
    if (HAL_RNG_GenerateRandomNumber(&hrng, &rng_val) == HAL_OK) {
        int vdd_mv = 3250 + (int)(rng_val % 100);  /* 3.25 - 3.35V */
        snprintf(buf, sizeof(buf), "  SENSOR:VDD=%d.%02dV\r\n",
                 vdd_mv / 1000, (vdd_mv % 1000) / 10);
    } else {
        snprintf(buf, sizeof(buf), "  SENSOR:VDD=ERR\r\n");
    }
    shell_envoyer(buf);

    /* Utilisation memoire logs */
    int pct = (logs_count() * 100) / MAX_LOGS;
    snprintf(buf, sizeof(buf), "  SENSOR:MEM=%d%%\r\n", pct);
    shell_envoyer(buf);

    /* Uptime en secondes (format machine) */
    snprintf(buf, sizeof(buf), "  SENSOR:UPTIME=%lus\r\n",
             (unsigned long)(HAL_GetTick() / 1000));
    shell_envoyer(buf);

    shell_envoyer("-------------------\r\n");
}

void version_cmd_afficher(void)
{
    char buf[96];

    shell_envoyer("=== FIRMWARE INFO ===\r\n");

    snprintf(buf, sizeof(buf), "  Name    : %s\r\n", FW_NAME);
    shell_envoyer(buf);

    snprintf(buf, sizeof(buf), "  Version : %s\r\n", FW_VERSION);
    shell_envoyer(buf);

    snprintf(buf, sizeof(buf), "  Build   : %s\r\n", FW_BUILD);
    shell_envoyer(buf);

    snprintf(buf, sizeof(buf), "  Target  : %s\r\n", FW_TARGET);
    shell_envoyer(buf);

    snprintf(buf, sizeof(buf), "  CPU     : %s\r\n", FW_CPU);
    shell_envoyer(buf);

    snprintf(buf, sizeof(buf), "  Unit    : %s\r\n", FDR_SERIAL_NO);
    shell_envoyer(buf);

    snprintf(buf, sizeof(buf), "  Std     : %s\r\n", FDR_STD_REF);
    shell_envoyer(buf);

    snprintf(buf, sizeof(buf), "  Author  : %s\r\n", FW_AUTHOR);
    shell_envoyer(buf);

    /* Memoire */
    snprintf(buf, sizeof(buf), "  Log RAM : %d x %d = %d o\r\n",
             MAX_LOGS, LOG_SIZE, MAX_LOGS * LOG_SIZE);
    shell_envoyer(buf);

    snprintf(buf, sizeof(buf), "  History : %d x %d = %d o\r\n",
             MAX_HISTORY, CMD_SIZE, MAX_HISTORY * CMD_SIZE);
    shell_envoyer(buf);

    shell_envoyer("=====================\r\n");

    (void)FW_SECRET_TAG;
}
