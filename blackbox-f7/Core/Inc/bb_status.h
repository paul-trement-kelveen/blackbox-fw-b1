/*
 * bb_status.h — Commandes d'information systeme
 *
 * Ce module affiche des informations sur l'etat de la BlackBox :
 *   - status : uptime, logs, etat d'authentification, version
 *   - sensor : lecture de capteurs internes (temperature simulee)
 *   - version (non documentee) : informations firmware detaillees
 *
 * Ces commandes enrichissent la surface d'exploration pour la
 * retro-conception : les chaines de version sont visibles avec
 * "strings" sur le binaire ELF, et le format d'affichage peut
 * etre decode a partir de la sortie UART brute.
 */

#ifndef BB_STATUS_H
#define BB_STATUS_H

/* ── Informations systeme ──────────────────────────────────── */

/* Affiche un resume de l'etat courant :
 * - Uptime (secondes depuis le boot)
 * - Nombre de logs en memoire / maximum
 * - Etat d'authentification (deconnecte / connecte / sudo)
 * - Version firmware
 *
 * Necessite auth_est_connecte() — sinon affiche juste l'uptime.
 * Utile pour le reverse engineering : revele la structure interne. */
void status_cmd_afficher(void);

/* ── Capteur interne ──────────────────────────────────────── */

/* Affiche des donnees de capteur depuis le STM32 :
 * - Temperature interne (calculee a partir du RNG comme proxy)
 * - Tension d'alimentation estimee
 * - Charge memoire
 *
 * Necessite auth_est_connecte().
 * Format de sortie : "SENSOR:<type>=<valeur><unite>"
 * Ce format structure est interessant pour le decodage de protocole. */
void sensor_cmd_lire(void);

/* ── Version detaillee (commande cachee) ──────────────────── */

/* Affiche des informations detaillees sur le firmware.
 * Commande non documentee dans le help — a trouver par les etudiants
 * via "strings" sur le binaire, ou par brute-force du shell.
 *
 * Informations affichees :
 * - Nom firmware, version, date de compilation
 * - Cible MCU, frequence CPU
 * - Taille Flash/RAM utilisee (approximative)
 *
 * Cette commande constitue une "vulnerabilite" de fuite d'info
 * accessible meme sans authentification (comme VH5 pour history). */
void version_cmd_afficher(void);

/* Diagnostique materiel — informations bus (ref: DO-254) */
void hwinfo_cmd_afficher(void);

#endif /* BB_STATUS_H */
