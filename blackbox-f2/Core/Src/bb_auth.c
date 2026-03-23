/*
 * bb_auth.c — Authentification (login, logout, su)
 * Version F2 : STM32F207ZGTx (Nucleo-144 F2)
 *
 * Differences avec la version F7 :
 *   - Pas de HAL_HASH (peripherique absent sur F207ZG)
 *   - C9 : utilise bb_sha256() (software) au lieu de HAL_HASH_SHA256_Start()
 *   - RNG disponible sur F207ZG — extern hrng conserve pour C10
 *   - Tout le reste est identique (timing attack, lockout, su)
 *
 * Vulnerabilites presentes :
 *   V1      — PIN_SECRET en clair dans bb_config.h
 *   V3      — pas de compteur de tentatives (a implementer C2)
 *   V8      — session sans expiration (pas de timeout d'inactivite)
 *   VH1     — comparer_pin() vulnerable au timing attack
 *   VH4     — su accessible sans login (dans le dispatcher blackbox.c)
 *
 * ┌───────────────────────────────────────────────────────────────────┐
 * │ VULNERABILITE V8 — Session sans expiration (CWE-613)             │
 * │                                                                   │
 * │ Incident reel : le botnet Mirai (2016) exploitait des sessions   │
 * │ IoT qui ne se fermaient jamais apres inactivite. Un attaquant   │
 * │ pouvait se connecter une fois et garder l'acces indefiniment.    │
 * │ Ici, apres "login", la session reste active TANT que l'on ne    │
 * │ tape pas "logout". Si un operateur quitte le terminal sans se   │
 * │ deconnecter, n'importe qui peut utiliser sa session.            │
 * │                                                                   │
 * │ Correction C12 : ajouter un timer d'inactivite.                  │
 * │   - Sauvegarder HAL_GetTick() apres chaque commande             │
 * │   - Avant chaque commande, verifier si le delai est depasse     │
 * │   - Si oui, forcer auth_cmd_logout()                            │
 * └───────────────────────────────────────────────────────────────────┘
 */

#include "bb_auth.h"
#include "bb_shell.h"
#include "bb_config.h"
#include "bb_sha256.h"   /* SHA-256 software — remplace HAL_HASH sur F2 */
#include <string.h>

/*
 * Note F2 : le peripherique HASH hardware n'existe pas sur STM32F207.
 * La ligne suivante (presente dans la version F7) est SUPPRIMEE :
 *   extern HASH_HandleTypeDef hhash;
 *
 * A la place, bb_sha256() (implementation software) est utilisee en C9.
 * Interface identique du point de vue de l'etudiant :
 *   F7 : HAL_HASH_SHA256_Start(&hhash, data, len, digest, HAL_MAX_DELAY);
 *   F2 : bb_sha256(data, len, digest);
 */

/* Le RNG est disponible sur F207ZG */
extern RNG_HandleTypeDef hrng;

/* ── Etat interne ───────────────────────────────────────────── */

static int connecte = 0;    /* 1 = session crew active   */
static int sudo     = 0;    /* 1 = mode sudo actif       */

/* VULNERABILITE V8 : pas de timeout d'inactivite.
 *
 * La variable ci-dessous est prevue pour C12, mais N'EST PAS UTILISEE :
 * la boucle principale (blackbox.c) ne verifie jamais l'expiration.
 *
 * TODO C12 : dans blackbox.c, avant chaque commande, appeler
 *   auth_verifier_timeout() pour deconnecter automatiquement
 *   apres SESSION_TIMEOUT_MS millisecondes d'inactivite.
 */
static uint32_t derniere_activite = 0;

/* TODO C2 — anti-brute force (a ajouter par les etudiants) :
 *   static int     nb_echecs      = 0;
 *   static int     bloque         = 0;
 *   static uint32_t deblocage_ms  = 0;
 */

/* ── Comparaison du PIN ─────────────────────────────────────── */

/*
 * comparer_pin — compare pin_saisi avec pin_attendu.
 *
 * Cette fonction ajoute un delai "anti-fuzzing" de DELAI_PAR_CHAR_MS
 * apres chaque caractere CORRECT, pour ralentir les tentatives rapides.
 *
 * Retourne 1 si les PINs sont identiques, 0 sinon.
 *
 * ┌─────────────────────────────────────────────────────────────┐
 * │ EXERCICE DEBUGGER (Phase 1 — section 3b)                    │
 * │ Placez un point d'arret sur la ligne "HAL_Delay" ci-dessous.│
 * │ Tapez "login 0050" dans PuTTY.                              │
 * │ Observez : combien de fois le debugger s'arrete-t-il ?      │
 * │ Recommencez avec "login 0500". Difference ?                 │
 * └─────────────────────────────────────────────────────────────┘
 */
static int comparer_pin(const char *pin_saisi, const char *pin_attendu)
{
    int i = 0;

    while (pin_saisi[i] != '\0' && pin_attendu[i] != '\0') {

        if (pin_saisi[i] != pin_attendu[i])
            return 0;   /* retour immediat = timing mesurable ! */

        HAL_Delay(DELAI_PAR_CHAR_MS);   /* <── POINT D'ARRET ICI */
        i++;
    }

    /* Les deux chaines doivent se terminer en meme temps */
    return (pin_saisi[i] == '\0' && pin_attendu[i] == '\0');
}

/* ── Fonctions publiques ────────────────────────────────────── */

void auth_init(void)
{
    connecte = 0;
    sudo     = 0;
}

int auth_est_connecte(void) { return connecte; }
int auth_est_sudo(void)     { return sudo;     }

void auth_touch_session(void)
{
    /* Met a jour le timestamp de derniere activite.
     * A appeler apres chaque commande dans blackbox.c (correction C12). */
    derniere_activite = HAL_GetTick();
}

void auth_verifier_timeout(void)
{
    /* Verifie si la session a expire par inactivite.
     *
     * VULNERABILITE V8 : cette fonction existe mais n'est JAMAIS APPELEE
     * dans la boucle principale. La session ne s'expire donc jamais.
     *
     * Correction C12 : appeler cette fonction dans blackbox.c,
     * juste avant afficher_prompt(), dans le while(1). */
    if (connecte && (HAL_GetTick() - derniere_activite > SESSION_TIMEOUT_MS)) {
        connecte = 0;
        sudo     = 0;
        shell_envoyer("\r\n[!] Session expiree (inactivite).\r\n");
    }
}

void auth_cmd_login(const char *pin)
{
    /*
     * VULNERABILITE V3 : aucun compteur de tentatives.
     * TODO C2 : ajouter avant la comparaison :
     *   if (bloque && HAL_GetTick() < deblocage_ms) { erreur; return; }
     *   ...et apres echec : nb_echecs++; if (nb_echecs >= MAX_ECHECS) { bloque; }
     */
    if (comparer_pin(pin, PIN_SECRET)) {
        connecte = 1;
        derniere_activite = HAL_GetTick();   /* initialise le timer V8 */
        shell_envoyer("Connexion reussie.\r\n");
    } else {
        shell_envoyer("PIN incorrect.\r\n");
    }
}

void auth_cmd_logout(void)
{
    connecte = 0;
    sudo     = 0;
    shell_envoyer("Deconnecte.\r\n");
}

void auth_cmd_su(const char *pin)
{
    /*
     * TODO C11 : implementer le mode sudo.
     *
     * Note F2 vs F7 :
     *   Pour hasher le PIN sudo (si C9 fait), utiliser bb_sha256()
     *   au lieu de HAL_HASH_SHA256_Start().
     *
     *   Exemple (C11 + C9 sur F2) :
     *     uint8_t digest[32];
     *     bb_sha256((uint8_t *)pin, strlen(pin), digest);
     *     if (memcmp(digest, PIN_SUDO_HASH, 32) == 0) { sudo = 1; }
     *
     * Structure a ajouter dans l'etat interne :
     *   static int     nb_echecs_su    = 0;
     *   static int     niveau_blocage  = 0;   // 0,1,2,3
     *   static uint32_t deblocage_su   = 0;
     *
     * Logique :
     *   1. Verifier bloquage : if (HAL_GetTick() < deblocage_su) => refuser
     *   2. Comparer pin avec PIN_SUDO (ou son hash si C9 fait)
     *   3. Succes : sudo = 1
     *   4. Echec  : nb_echecs_su++
     *              si nb_echecs_su >= MAX_ECHECS : incrementer niveau_blocage
     *              et fixer deblocage_su = HAL_GetTick() + delai[niveau_blocage]
     *
     * Tableau des delais :
     *   niveau 0 -> DELAI_LOCKOUT_1_MS (1 min)
     *   niveau 1 -> DELAI_LOCKOUT_2_MS (3 min)
     *   niveau 2 -> DELAI_LOCKOUT_3_MS (5 min)
     *   niveau 3 -> bloque indefiniment
     */
    (void)pin;  /* Dit au compilateur : "oui, on sait que pin n'est pas
                 *  utilise pour l'instant — pas de warning svp."
                 *  Ce parametre sera utilise dans C11. */
    shell_envoyer("Mode sudo : non implemente (TODO C11).\r\n");
}
