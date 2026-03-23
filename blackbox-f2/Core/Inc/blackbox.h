/*
 * blackbox.h — Point d'entree public du firmware BlackBox
 * Version F2 : STM32F207ZGTx (Nucleo-144 F2)
 *
 * Un seul appel suffit depuis main.c :
 *   blackbox_run(&huart3);
 *
 * Cette fonction ne retourne jamais (boucle infinie interne).
 */

#ifndef BLACKBOX_H
#define BLACKBOX_H

#include "stm32f2xx_hal.h"

/* Lance le firmware BlackBox.
 * huart : handle UART connecte au ST-Link VCP (USART3 sur Nucleo-144). */
void blackbox_run(UART_HandleTypeDef *huart);

#endif /* BLACKBOX_H */
