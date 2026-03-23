/*
 * bb_leds.h — Indicateurs visuels (LEDs Nucleo-144)
 *
 * Ce module pilote les 3 LEDs utilisateur du Nucleo-144 F756ZG
 * pour indiquer l'etat de la BlackBox :
 *
 *   LD1 (Vert, PB0)  — connecte (login reussi)
 *   LD2 (Bleu, PB7)  — mode sudo (su reussi)
 *   LD3 (Rouge, PB14) — alerte (echec login, lockout, erreur)
 *
 * Brochage physique :
 *   PB0  = CN10 pin 31  (LD1 Green)
 *   PB7  = CN11 pin 21  (LD2 Blue)
 *   PB14 = CN12 pin 28  (LD3 Red)
 *
 * Fonctionnement : ecriture directe (push-pull, actif haut).
 *   HAL_GPIO_WritePin(GPIOB, LD1_Pin, GPIO_PIN_SET)   => LED allumee
 *   HAL_GPIO_WritePin(GPIOB, LD1_Pin, GPIO_PIN_RESET) => LED eteinte
 *
 * Ce fichier fait partie de l'architecture bb_* multi-module.
 * Les LEDs sont deja configurees par CubeMX dans MX_GPIO_Init().
 */

#ifndef BB_LEDS_H
#define BB_LEDS_H

#include "main.h"   /* LD1_Pin, LD2_Pin, LD3_Pin, GPIOB */

/* ── Initialisation ─────────────────────────────────────────── */

/* Eteint toutes les LEDs. Appeler au demarrage. */
void leds_init(void);

/* ── Mise a jour de l'etat ────────────────────────────────── */

/* Met a jour les LEDs en fonction de l'etat courant :
 *   - Vert  ON  si connecte
 *   - Bleu  ON  si sudo
 *   - Vert et Bleu OFF si deconnecte
 */
void leds_maj_etat(void);

/* ── Signaux d'alerte ─────────────────────────────────────── */

/* Fait clignoter la LED rouge 'n' fois.
 * Utilise pour signaler une erreur (echec login, commande refusee).
 * Bloquant : dure n * 200ms. */
void leds_alerte(int n);

/* Allume toutes les LEDs 500ms puis les eteint.
 * Feedback visuel au boot pour confirmer que le firmware tourne. */
void leds_boot_flash(void);

#endif /* BB_LEDS_H */
