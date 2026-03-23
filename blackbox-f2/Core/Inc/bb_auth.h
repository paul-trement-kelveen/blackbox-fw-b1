/*
 * bb_auth.h — Interface d'authentification
 * Version F2 : STM32F207ZGTx (Nucleo-144 F2)
 *
 * Identique a la version F7.
 * Difference en Phase 2 : C9 utilise bb_sha256() (software)
 * au lieu de HAL_HASH_SHA256_Start() (hardware absent sur F207).
 */

#ifndef BB_AUTH_H
#define BB_AUTH_H

void auth_init(void);
int  auth_est_connecte(void);
int  auth_est_sudo(void);
void auth_cmd_login(const char *pin);
void auth_cmd_logout(void);
void auth_cmd_su(const char *pin);

/* Session timeout (V8/C12) */
void auth_touch_session(void);
void auth_verifier_timeout(void);

#endif /* BB_AUTH_H */
