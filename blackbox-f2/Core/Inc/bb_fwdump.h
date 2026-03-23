/*
 * bb_fwdump.h — Interface d'export des logs (FWDUMP)
 *
 * Ce module exporte les logs vers un dispositif externe.
 * Cible finale : bus SPI1 avec chiffrement XOR.
 *
 * Format de trame SPI (a implementer en C7) :
 *   [0xBB][0xAA]          marqueur de debut
 *   [nb_logs]             1 octet : nombre de logs
 *   Pour chaque log :
 *     [longueur]          1 octet : longueur du message
 *     [data...]           n octets : message (chiffre en C8)
 *   [0xEE][0xFF]          marqueur de fin
 *
 * VULNERABILITE V7 : l'export se fait en clair (pas de XOR).
 * Correction C7 : utiliser HAL_SPI_Transmit a la place de l'UART.
 * Correction C8 : XOR chaque octet de data avec XOR_KEY.
 */

#ifndef BB_FWDUMP_H
#define BB_FWDUMP_H

/* Lance l'export des logs.
 * Verifie auth_est_connecte() — erreur si non connecte.
 * TODO C7 : remplacer l'envoi UART par SPI. */
void fwdump_cmd_executer(void);

#endif /* BB_FWDUMP_H */
