/*
 * bb_shell.c — Couche communication UART (shell)
 *
 * Responsabilite unique : tout ce qui touche a l'UART.
 * Aucune logique metier dans ce fichier.
 *
 * Vulnerabilites presentes :
 *   V2  — historique stocke les commandes login en clair
 *   VH2 — echo UART expose le PIN pendant la saisie
 *   VH3 — historique circulaire (voir shell_historique_ajouter)
 */

#include "bb_shell.h"
#include "bb_config.h"
#include <string.h>
#include <stdio.h>

/* ── Etat interne ───────────────────────────────────────────── */

static UART_HandleTypeDef *uart_handle;

/* VULNERABILITE V2 : les commandes "login XXXX" sont stockees en clair.
 * L'historique est circulaire : quand il est plein, la plus ancienne
 * entree est ecrasee (contrairement a la version precedente). */
static char historique[MAX_HISTORY][CMD_SIZE];
static int  nb_historique = 0;   /* total commandes ajoutees (peut depasser MAX_HISTORY) */

/* ── Fonctions privees ──────────────────────────────────────── */

static int indice_historique(int rang)
{
    /* Calcule l'indice reel dans le tableau circulaire.
     * rang 0 = la plus ancienne commande stockee.
     *
     * Exemple : MAX_HISTORY=4, nb_historique=6
     *   On a ecrit aux positions 0,1,2,3,0,1 (ecrasement circulaire).
     *   debut = 6 % 4 = 2  (la plus ancienne est a l'indice 2)
     *   rang 0 => (2+0) % 4 = 2  (plus ancienne)
     *   rang 1 => (2+1) % 4 = 3
     *   rang 2 => (2+2) % 4 = 0
     *   rang 3 => (2+3) % 4 = 1  (plus recente)
     */
    int debut = nb_historique > MAX_HISTORY ? (nb_historique % MAX_HISTORY) : 0;
    return (debut + rang) % MAX_HISTORY;
}

/* ── Fonctions publiques ────────────────────────────────────── */

void shell_init(UART_HandleTypeDef *huart)
{
    uart_handle = huart;
    memset(historique, 0, sizeof(historique));
    nb_historique = 0;
}

void shell_envoyer(const char *texte)
{
    if (uart_handle == NULL) return;
    HAL_UART_Transmit(uart_handle, (uint8_t *)texte, strlen(texte), 1000);
}

void shell_lire_ligne(char *buf, int max)
{
    int     i = 0;
    uint8_t c;

    while (i < max) {
        HAL_UART_Receive(uart_handle, &c, 1, HAL_MAX_DELAY);

        /* VH2 : echo systematique de chaque caractere, y compris le PIN.
         * Un equipement branche sur le bus UART voit tout en clair.
         * Correction possible : ne pas faire d'echo pendant la saisie d'un PIN. */
        HAL_UART_Transmit(uart_handle, &c, 1, 100);

        if (c == '\r' || c == '\n') break;

        if (c == 127 || c == '\b') {   /* Backspace */
            if (i > 0) i--;
            continue;
        }

        buf[i++] = (char)c;
    }
    buf[i] = '\0';
    shell_envoyer("\r\n");
}

void shell_cmd_aide(void)
{
    shell_envoyer("Commandes disponibles :\r\n");
    shell_envoyer("  login <PIN>       — se connecter\r\n");
    shell_envoyer("  logout            — se deconnecter\r\n");
    shell_envoyer("  log write <msg>   — enregistrer un message\r\n");
    shell_envoyer("  log read          — lire les messages\r\n");
    shell_envoyer("  log clear         — effacer les messages\r\n");
    shell_envoyer("  history           — voir l'historique\r\n");
    shell_envoyer("  fwdump            — exporter les logs (SPI1)\r\n");
    shell_envoyer("  su <PIN>          — mode sudo\r\n");
    shell_envoyer("  status            — etat du systeme\r\n");
    shell_envoyer("  sensor            — capteurs internes\r\n");
    shell_envoyer("  help              — cette aide\r\n");
}

void shell_historique_ajouter(const char *commande)
{
    /* Stockage circulaire : ecrase la plus ancienne entree quand plein.
     * VULNERABILITE V2 : si commande = "login 5678", le PIN est stocke
     * en clair a l'indice (nb_historique % MAX_HISTORY).
     * Correction C4 : tester strncmp(commande, "login ", 6) et stocker
     *                 "login [***]" a la place. */
    int idx = nb_historique % MAX_HISTORY;
    strncpy(historique[idx], commande, CMD_SIZE - 1);
    historique[idx][CMD_SIZE - 1] = '\0';
    nb_historique++;
}

void shell_cmd_historique(void)
{
    int total = nb_historique > MAX_HISTORY ? MAX_HISTORY : nb_historique;

    if (total == 0) {
        shell_envoyer("Historique vide.\r\n");
        return;
    }

    char ligne[CMD_SIZE + 8];
    for (int rang = 0; rang < total; rang++) {
        int idx = indice_historique(rang);
        snprintf(ligne, sizeof(ligne), "[%d] %s\r\n", rang + 1, historique[idx]);
        shell_envoyer(ligne);
    }
}
