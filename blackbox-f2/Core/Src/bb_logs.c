/*
 * bb_logs.c — Gestion des logs en memoire RAM
 *
 * Responsabilite unique : stocker et restituer les messages de log.
 *
 * Vulnerabilites presentes :
 *   V4 — logs_cmd_lire() ne verifie pas auth_est_connecte()
 *   V5 — logs_cmd_effacer() ne fait que nb_logs = 0 (pas de memset)
 *   V6 — les messages sont stockes en clair (pas de XOR)
 *
 * ┌─────────────────────────────────────────────────────────────┐
 * │ EXERCICE DEBUGGER — V5 (Phase 1, section 3b)                │
 * │ 1. Placez un point d'arret sur "nb_logs = 0" (logs_effacer) │
 * │ 2. Ecrivez 2 logs, tapez "log clear"                        │
 * │ 3. Quand le debugger s'arrete, ouvrez Memory Browser        │
 * │    et cherchez l'adresse de la variable logs[]              │
 * │ 4. Que voyez-vous ? Les donnees sont-elles effacees ?       │
 * └─────────────────────────────────────────────────────────────┘
 */

#include "bb_logs.h"
#include "bb_auth.h"
#include "bb_shell.h"
#include <string.h>
#include <stdio.h>

/* ── Etat interne ───────────────────────────────────────────── */

static char logs[MAX_LOGS][LOG_SIZE];
static int  nb_logs = 0;

/* ── Fonctions publiques ────────────────────────────────────── */

void logs_init(void)
{
    memset(logs, 0, sizeof(logs));
    nb_logs = 0;
}

int logs_count(void)
{
    return nb_logs;
}

const char *logs_get(int index)
{
    if (index < 0 || index >= nb_logs) return NULL;
    return logs[index];
}

void logs_cmd_ecrire(const char *message)
{
    if (!auth_est_connecte()) {
        shell_envoyer("Erreur : vous devez etre connecte.\r\n");
        return;
    }
    if (nb_logs >= MAX_LOGS) {
        shell_envoyer("Erreur : memoire pleine (10 logs max).\r\n");
        return;
    }

    /* VULNERABILITE V6 : stockage en clair.
     * Correction C6 : XOR chaque octet avec XOR_KEY avant strncpy.
     * Exemple :
     *   int len = strlen(message);
     *   if (len > LOG_SIZE - 1) len = LOG_SIZE - 1;
     *   for (int j = 0; j < len; j++)
     *       logs[nb_logs][j] = message[j] ^ XOR_KEY;
     *   logs[nb_logs][len] = '\0';
     */
    strncpy(logs[nb_logs], message, LOG_SIZE - 1);
    logs[nb_logs][LOG_SIZE - 1] = '\0';
    nb_logs++;

    shell_envoyer("Log enregistre.\r\n");
}

void logs_cmd_lire(void)
{
    /*
     * VULNERABILITE V4 : aucune verification de connexion.
     * Correction C3 : ajouter en debut de fonction :
     *   if (!auth_est_connecte()) {
     *       shell_envoyer("Erreur : vous devez etre connecte.\r\n");
     *       return;
     *   }
     */
    if (nb_logs == 0) {
        shell_envoyer("Aucun log enregistre.\r\n");
        return;
    }

    char ligne[LOG_SIZE + 16];
    for (int i = 0; i < nb_logs; i++) {
        /* VULNERABILITE V6 : affichage en clair.
         * Correction C6 : dechiffrer avec XOR avant affichage. */
        snprintf(ligne, sizeof(ligne), "[%d] %s\r\n", i + 1, logs[i]);
        shell_envoyer(ligne);
    }
}

void logs_cmd_effacer(void)
{
    if (!auth_est_connecte()) {
        shell_envoyer("Erreur : vous devez etre connecte.\r\n");
        return;
    }

    /*
     * VULNERABILITE V5 : seul le compteur est remis a zero.
     * Les donnees restent en RAM, lisibles avec un debugger.
     *
     * Correction C5 : ajouter AVANT nb_logs = 0 :
     *   memset(logs, 0, sizeof(logs));
     *
     * ┌─────────────────────────────────────────────────────────┐
     * │ EXERCICE DEBUGGER : verifier V5                         │
     * │ Placez un point d'arret sur "nb_logs = 0".              │
     * │ Inspectez logs[0] dans le Memory Browser.               │
     * │ Appuyez sur "Continue" puis inspectez a nouveau.        │
     * │ Les octets sont-ils a 0x00 ? Ou toujours presents ?     │
     * └─────────────────────────────────────────────────────────┘
     */
    nb_logs = 0;    /* <── POINT D'ARRET ICI pour observer V5 */

    shell_envoyer("Logs effaces.\r\n");
}

/* ── Donnees FDR pre-chargees ─────────────────────────────────
 *
 * Simule les derniers enregistrements d'une boite noire (FDR)
 * avant un incident. Les donnees suivent un format inspire des
 * vrais parametres DFDR (Digital Flight Data Recorder) :
 *
 *   T+<sec> | ALT=<ft> SPD=<kt> HDG=<deg> | GPS:<lat,lon>
 *   T+<sec> | ENG<n> <param> | ALERT <code>
 *
 * Scenario : vol AF-7721, approche de nuit sur LFPG (CDG).
 * Panne moteur 1 a basse altitude, tentative de remise de gaz.
 *
 * Ces donnees font partie de l'investigation lors du War Day :
 * les etudiants doivent pouvoir les lire, les proteger (C6),
 * les exporter (fwdump), et empecher un attaquant d'y acceder.
 * ─────────────────────────────────────────────────────────────── */

static void inserer_log_brut(const char *msg)
{
    if (nb_logs >= MAX_LOGS) return;
    strncpy(logs[nb_logs], msg, LOG_SIZE - 1);
    logs[nb_logs][LOG_SIZE - 1] = '\0';
    nb_logs++;
}

void logs_precharger_fdr(void)
{
    inserer_log_brut("T+0312 ALT=3200ft SPD=145kt HDG=268 FLAPS=30");
    inserer_log_brut("T+0314 ALT=2800ft SPD=138kt HDG=268 ILS:LOC+GS");
    inserer_log_brut("T+0316 ALT=2400ft ENG1:N1=0% ALERT:ENG_FAIL_1");
    inserer_log_brut("T+0318 ALT=2100ft SPD=128kt TOGA ALERT:PULL_UP");
    inserer_log_brut("T+0320 ALT=1950ft ENG2:N1=97% HDG=275 GPS:49.0128,2.5441");
}
