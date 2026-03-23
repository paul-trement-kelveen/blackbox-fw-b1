/*
 * bb_leds.c — Indicateurs visuels (LEDs Nucleo-144)
 *
 * Pilote les 3 LEDs utilisateur pour donner un feedback visuel :
 *   LD1 Vert  (PB0)  = connecte
 *   LD2 Bleu  (PB7)  = sudo
 *   LD3 Rouge (PB14) = alerte / erreur
 *
 * Les LEDs sont initialisees par CubeMX (MX_GPIO_Init dans main.c).
 * Ce module se contente de les allumer/eteindre selon le contexte.
 *
 * Dependances :
 *   - main.h    : defines LD1_Pin, LD2_Pin, LD3_Pin
 *   - bb_auth.h : auth_est_connecte(), auth_est_sudo()
 *   - HAL_GPIO  : HAL_GPIO_WritePin(), HAL_Delay()
 */

#include "bb_leds.h"
#include "bb_auth.h"

/* ── Fonctions privees ──────────────────────────────────────── */

static void led_set(uint16_t pin, int on)
{
    HAL_GPIO_WritePin(GPIOB, pin, on ? GPIO_PIN_SET : GPIO_PIN_RESET);
}

/* ── Fonctions publiques ────────────────────────────────────── */

void leds_init(void)
{
    /* Tout eteindre au demarrage */
    led_set(LD1_Pin, 0);   /* Vert OFF  */
    led_set(LD2_Pin, 0);   /* Bleu OFF  */
    led_set(LD3_Pin, 0);   /* Rouge OFF */
}

void leds_maj_etat(void)
{
    int connecte = auth_est_connecte();
    int sudo     = auth_est_sudo();

    led_set(LD1_Pin, connecte);   /* Vert  = connecte  */
    led_set(LD2_Pin, sudo);       /* Bleu  = sudo      */
    /* Rouge geree separement par leds_alerte() */
}

void leds_alerte(int n)
{
    for (int i = 0; i < n; i++) {
        led_set(LD3_Pin, 1);     /* Rouge ON  */
        HAL_Delay(100);
        led_set(LD3_Pin, 0);     /* Rouge OFF */
        HAL_Delay(100);
    }
}

void leds_boot_flash(void)
{
    /* Allumer les 3 LEDs : confirmation visuelle que le firmware tourne */
    led_set(LD1_Pin, 1);
    led_set(LD2_Pin, 1);
    led_set(LD3_Pin, 1);
    HAL_Delay(500);

    /* Tout eteindre */
    led_set(LD1_Pin, 0);
    led_set(LD2_Pin, 0);
    led_set(LD3_Pin, 0);
}
