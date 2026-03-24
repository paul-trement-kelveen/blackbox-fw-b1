/*
 * bb_config.h — Configuration centrale du firmware BlackBox
 *
 * C'est ICI que toutes les constantes sont definies.
 * En Phase 2, vous modifierez principalement ce fichier.
 *
 * Philosophie :
 *   Un fichier de config centralise = une seule source de verite.
 *   Changer une valeur ici la change partout dans le code.
 */

#ifndef BB_CONFIG_H
#define BB_CONFIG_H

/* ================================================================
 * AUTHENTIFICATION
 *
 * VULNERABILITE V1 : le PIN est en clair dans le code source.
 * Correction C1  : changer la valeur.
 * Correction C9  : hasher avec SHA-256 (voir bb_auth.c).
 * ================================================================ */
#define PIN_SECRET    "0000"    /* PIN crew par defaut              */
#define PIN_SUDO      "9999"    /* PIN sudo — a implementer en C11  */
                                /* Note : comme PIN_SECRET, ce PIN  */
                                /* est visible dans le binaire ELF  */
                                /* (strings). A hasher si C9 fait.  */

/* ================================================================
 * CHIFFREMENT
 *
 * VULNERABILITE V6/V7 : cle fixe, connue de tous.
 * Correction C6  : utiliser XOR_KEY dans bb_logs.c.
 * Correction C8  : utiliser XOR_KEY dans bb_fwdump.c.
 * Correction C10 : remplacer par une cle generee par HAL_RNG.
 * ================================================================ */
#define XOR_KEY       0xAB      /* 0xAB = 171 en decimal = 10101011 en binaire */

/* ================================================================
 * LIMITES MEMOIRE
 * ================================================================ */
#define MAX_LOGS      10        /* logs maximum en RAM              */
#define LOG_SIZE      80        /* taille max d'un message (octets) */
#define MAX_HISTORY   8         /* commandes gardees en memoire     */
#define CMD_SIZE      80        /* taille max d'une commande        */

/* ================================================================
 * ANTI-BRUTE FORCE
 *
 * VULNERABILITE V3 : MAX_ECHECS n'est pas utilise — pas de lockout.
 * Correction C2 : utiliser ces valeurs dans bb_auth.c.
 * ================================================================ */
#define MAX_ECHECS         5        /* tentatives avant blocage         */
#define DELAI_LOCKOUT_1_MS 60000UL  /* 1 minute  (UL = unsigned long, car > 65535) */
#define DELAI_LOCKOUT_2_MS 180000UL /* 3 minutes (UL evite un depassement en int) */
#define DELAI_LOCKOUT_3_MS 300000UL /* 5 minutes                                  */

/* ================================================================
 * TIMING ANTI-FUZZING
 *
 * Delai ajoute dans comparer_pin() apres chaque caractere valide.
 * Semble etre une protection — en realite facilite le timing attack.
 * Correction C_timing : remplacer par comparaison temps-constant.
 * ================================================================ */
#define DELAI_PAR_CHAR_MS  10       /* ms par caractere correct        */

/* ================================================================
 * SESSION
 *
 * VULNERABILITE V8 : le timeout existe mais n'est PAS utilise.
 * auth_verifier_timeout() n'est jamais appelee dans la boucle.
 * Correction C12 : activer la verification dans blackbox.c.
 * ================================================================ */
#define SESSION_TIMEOUT_MS 120000UL /* 2 minutes d'inactivite          */

/* ================================================================
 * IDENTITE DU SYSTEME FDR
 *
 * Ces chaines sont stockees en Flash et visibles via "strings".
 * Un analyste forensique peut identifier le systeme avant meme
 * d'avoir acces au shell (retro-conception Phase 1A).
 * ================================================================ */
#define FDR_SERIAL_NO   "BB-F7-001"         /* Numero de serie unite FDR    */
#define FDR_FLIGHT_ID   "AF-7721"           /* Identifiant du vol enregistre */
#define FDR_STD_REF     "ARINC717/ED-112A"  /* Standard de certification    */
#define FDR_OPERATOR    "GRD Airlines"      /* Compagnie operatrice          */

#endif /* BB_CONFIG_H */
