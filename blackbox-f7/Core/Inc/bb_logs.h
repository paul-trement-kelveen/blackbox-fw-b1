/*
 * bb_logs.h — Interface de gestion des logs
 *
 * Ce module gere le stockage des messages de log en RAM.
 *
 * Les logs sont des messages texte de max LOG_SIZE caracteres.
 * Ils sont stockes dans un tableau statique (pas de malloc).
 *
 * Acces en lecture via logs_get() et logs_count()
 * pour que d'autres modules (ex: bb_fwdump) puissent les lire.
 */

#ifndef BB_LOGS_H
#define BB_LOGS_H

#include "bb_config.h"

/* ── Initialisation ─────────────────────────────────────────── */

/* Vide tous les logs et remet le compteur a zero. */
void logs_init(void);

/* ── Acces aux donnees (lecture seule) ──────────────────────── */

/* Retourne le nombre de logs actuellement stockes. */
int logs_count(void);

/* Retourne un pointeur vers le log a l'index donne (0 = premier).
 * Retourne NULL si l'index est hors limites.
 *
 * Important pour C6 + C8 :
 *   Cette fonction retourne les octets RAW stockes dans logs[].
 *   Apres C6, ces octets sont XOR'd (chiffres).
 *   bb_fwdump.c (C7/C8) doit donc envoyer ces octets SANS re-XOR,
 *   car ils sont deja proteges.
 *   Si C8 XOR a nouveau => double-XOR => plaintext sur le bus SPI. */
const char *logs_get(int index);

/* ── Donnees de vol pre-chargees ──────────────────────────────── */

/* Charge des enregistrements FDR fictifs au demarrage.
 * Simule les dernieres donnees de boite noire avant un incident. */
void logs_precharger_fdr(void);

/* ── Commandes ──────────────────────────────────────────────── */

/* Enregistre un nouveau message.
 * Verifie auth_est_connecte() — erreur si non connecte.
 * VULNERABILITE V6 : stocke le message en clair (pas de XOR). */
void logs_cmd_ecrire(const char *message);

/* Affiche tous les logs sur l'UART.
 * VULNERABILITE V4 : ne verifie pas auth_est_connecte(). */
void logs_cmd_lire(void);

/* Efface les logs.
 * Verifie auth_est_connecte() — erreur si non connecte.
 * VULNERABILITE V5 : remet seulement le compteur a zero (pas de memset). */
void logs_cmd_effacer(void);

#endif /* BB_LOGS_H */
