/*
 * bb_sha256.h — SHA-256 software (F2 : pas de peripherique HASH hardware)
 *
 * Sur STM32F7, la correction C9 utilise HAL_HASH_SHA256_Start().
 * Sur STM32F2 (F207ZG), le peripherique HASH n'existe pas.
 * Cette implementation software remplace le hardware pour C9.
 *
 * Interface identique a l'usage enseigne :
 *   uint8_t digest[32];
 *   bb_sha256((uint8_t *)pin, strlen(pin), digest);
 *   if (memcmp(digest, PIN_HASH, 32) == 0) { ... }
 *
 * Source : implementation de domaine public (Brad Conte, 2011).
 */

#ifndef BB_SHA256_H
#define BB_SHA256_H

#include <stdint.h>
#include <stddef.h>

/* Calcule le hash SHA-256 de `data` (longueur `len`).
 * Ecrit 32 octets dans `digest`. */
void bb_sha256(const uint8_t *data, size_t len, uint8_t digest[32]);

#endif /* BB_SHA256_H */
