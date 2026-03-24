/*
 * bb_auth.h — Interface d'authentification
 *
 * Ce module gere :
 *   - la verification du PIN (login / su)
 *   - l'etat de la session (connecte, sudo)
 *   - le compteur de tentatives (a implementer en C2)
 *
 * Les autres modules interrogent l'etat via les fonctions
 * auth_est_connecte() et auth_est_sudo().
 */

#ifndef BB_AUTH_H
#define BB_AUTH_H

/* ── Initialisation ─────────────────────────────────────────── */

/* Remet l'etat d'authentification a zero (session fermee). */
void auth_init(void);

/* ── Interrogation de l'etat ────────────────────────────────── */

/* Retourne 1 si une session crew est ouverte, 0 sinon. */
int auth_est_connecte(void);

/* Retourne 1 si le mode sudo est actif, 0 sinon. */
int auth_est_sudo(void);

/* ── Commandes ──────────────────────────────────────────────── */

/* Tente une connexion avec le PIN fourni.
 * Affiche "Connexion reussie." ou "PIN incorrect." sur l'UART. */
void auth_cmd_login(const char *pin);

/* Ferme la session courante. */
void auth_cmd_logout(void);

/* Tente une elevation de privilege (mode sudo).
 * TODO C11 : a implementer. */
void auth_cmd_su(const char *pin);

/* ── Gestion session (V8 / C12) ──────────────────────────────── */

/* Met a jour le timestamp de derniere activite.
 * A appeler dans blackbox.c apres chaque commande (correction C12). */
void auth_touch_session(void);

/* Verifie si la session a expire.
 * VULNERABILITE V8 : cette fonction existe mais n'est pas appelee.
 * TODO C12 : appeler dans la boucle de blackbox.c. */
void auth_verifier_timeout(void);

#endif /* BB_AUTH_H */
