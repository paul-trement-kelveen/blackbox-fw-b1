/*
 * bb_shell.h — Interface de communication UART (couche shell)
 *
 * Ce module gere tout ce qui touche a l'UART :
 *   - envoi de texte vers PuTTY
 *   - lecture d'une ligne tapee par l'utilisateur
 *   - affichage de l'aide et de l'historique
 *
 * Aucune logique metier ici — juste de la communication.
 */

#ifndef BB_SHELL_H
#define BB_SHELL_H

#include "stm32f7xx_hal.h"

/* ── Initialisation ─────────────────────────────────────────── */

/* Doit etre appele une fois avant tout autre appel shell.
 * Enregistre le handle UART utilise par les autres fonctions. */
void shell_init(UART_HandleTypeDef *huart);

/* ── Communication ──────────────────────────────────────────── */

/* Envoie une chaine de caracteres sur l'UART. */
void shell_envoyer(const char *texte);

/* Lit une ligne saisie au clavier (s'arrete sur Entree).
 * Ecrit le resultat dans buf (max caracteres maximum, \0 inclus). */
void shell_lire_ligne(char *buf, int max);

/* ── Commandes shell ────────────────────────────────────────── */

/* Affiche la liste des commandes disponibles. */
void shell_cmd_aide(void);

/* Ajoute une commande dans l'historique circulaire.
 * Si l'historique est plein, ecrase la plus ancienne entree. */
void shell_historique_ajouter(const char *commande);

/* Affiche toutes les commandes de l'historique. */
void shell_cmd_historique(void);

#endif /* BB_SHELL_H */
