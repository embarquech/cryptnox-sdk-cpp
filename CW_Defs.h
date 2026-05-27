#ifndef CW_DEFS_H
#define CW_DEFS_H

/******************************************************************
 * 1. Included files
 ******************************************************************/

#include "platform_compat.h"

/******************************************************************
 * 2. Constants / define declarations
 ******************************************************************/

/* Session key sizes */
#define CW_AESKEY_SIZE    (32U)  /**< AES-256 session encryption key size in bytes */
#define CW_MACKEY_SIZE    (32U)  /**< AES-256 session MAC key size in bytes */
#define CW_IV_SIZE        (16U)  /**< AES-CBC IV size in bytes */

/* Generic error codes */
#define CW_OK                         (0x00U)  /**< OK */
#define CW_NOK                        (0x01U)  /**< NOK */
#define CW_INVALID_SESSION            (0x02U)  /**< Invalid session */

/* Key / path types for SIGN command (keyType) */
#define CW_SIGN_CURR_K1               (0x00U)  /**< Current key (k1) */
#define CW_SIGN_CURR_R1               (0x10U)  /**< Current key (r1) */
#define CW_SIGN_DERIVE_K1             (0x01U)  /**< Derive with k1 curve */
#define CW_SIGN_DERIVE_R1             (0x11U)  /**< Derive with r1 curve */
#define CW_SIGN_PINLESS_K1            (0x03U)  /**< PIN-less path (k1 only) */

/* PIN mode for SIGN command */
#define CW_SIGN_WITH_PIN              (false)  /**< PIN path */
#define CW_SIGN_PINLESS               (true)   /**< PIN-less path */

/* Signature types for SIGN command */
#define CW_SIGN_SIG_ECDSA_LOW_S       (0x00U)  /**< ECDSA with canonical low S */
#define CW_SIGN_SIG_ECDSA_EOSIO       (0x01U)  /**< ECDSA EOSIO format */
#define CW_SIGN_SIG_SCHNORR_BIP340    (0x02U)  /**< Schnorr BIP340 */

/* SIGN-specific error codes */
#define CW_SIGN_KEY_TOO_SHORT                  (0x80U)
#define CW_SIGN_NO_KEY_LOADED                  (0x81U)
#define CW_SIGN_PIN_INCORRECT                  (0x82U)
#define CW_SIGN_KEY_TOO_SHORT_WITH_PINLESS_MODE (0x83U)

/* Size constants */
#define CW_RAW_SIGNATURE_SIZE         (64U)    /**< Raw signature (r[32] + s[32]) */
#define CW_HASH_SIZE                  (32U)    /**< Standard hash size */
#define CW_MAX_DERIVE_PATH_LENGTH     (20U)    /**< Max BIP32 path bytes */
#define CW_MIN_PIN_LENGTH              (4U)    /**< Minimum PIN length */
#define CW_MAX_PIN_LENGTH              (9U)    /**< Maximum PIN length */
#define CW_USER_DATA_PAGE_SIZE        (208U)   /**< Max plaintext bytes per write user data page */
#define CW_CONNECT_MAX_ATTEMPTS        (5U)    /**< Max NFC connection retry attempts */

/* Byte offsets within a raw 64-byte signature (r[32] || s[32]) */
#define CW_SIG_R_OFFSET               (0U)   /**< Byte offset of the r component */
#define CW_SIG_S_OFFSET               (32U)  /**< Byte offset of the s component */

/* DER encoding tags (ASN.1) */
#define CW_DER_TAG_SEQUENCE           (0x30U)
#define CW_DER_TAG_INTEGER            (0x02U)

/* Certificate verification constants */
#define CW_CERT_NONCE_SIZE            (8U)     /**< Challenge nonce length in bytes */

/* Certificate verification result codes */
#define CW_CERT_OK                    (0x00U)  /**< Certificate chain verified */
#define CW_CERT_FORMAT_ERROR          (0x10U)  /**< Malformed certificate data */
#define CW_CERT_NONCE_MISMATCH        (0x11U)  /**< Challenge nonce not echoed */
#define CW_CERT_CARD_SIG_INVALID      (0x12U)  /**< Card cert ECDSA sig failed */
#define CW_CERT_MANUF_SIG_INVALID     (0x13U)  /**< Manufacturer cert ECDSA sig failed */
#define CW_CERT_KEY_NOT_FOUND         (0x14U)  /**< Device public key OID not found */

/* Manufacturer certificate maximum buffer size (bytes).
 * Actual Cryptnox Basic G1 manufacturer certificate is 411 bytes (0x019B). */
#define CW_MANUF_CERT_MAX_BYTES       (420U)

/******************************************************************
 * 3. CW_Curve enum
 ******************************************************************/

/**
 * @enum CW_Curve
 * @brief Portable curve identifier used throughout the SDK.
 *
 * Replaces direct references to uECC_Curve_t at every API boundary so the
 * abstract interfaces (CW_CryptoProvider, CW_SecureChannel) remain decoupled
 * from any specific ECC back-end.
 */
enum CW_Curve {
    CW_CURVE_SECP256R1 = 0,  /**< NIST P-256 / secp256r1 */
    CW_CURVE_SECP256K1 = 1   /**< Koblitz secp256k1 */
};

/******************************************************************
 * 4. CW_SecureSession struct
 ******************************************************************/

/**
 * @struct CW_SecureSession
 * @brief Holds cryptographic session state for reentrant secure channel operations.
 *
 * Encapsulates all session-specific cryptographic material (Kenc, Kmac, rolling IV),
 * allowing functions to be reentrant by passing session state as a parameter.
 */
struct CW_SecureSession {
    uint8_t aesKey[CW_AESKEY_SIZE];  /**< AES-256 session encryption key (Kenc) */
    uint8_t macKey[CW_MACKEY_SIZE];  /**< AES-256 session MAC key (Kmac) */
    uint8_t iv[CW_IV_SIZE];          /**< Current AES-CBC IV (rolling IV) */

    /** @brief Zero-initialise all session keys and IV. */
    CW_SecureSession() {
        memset(aesKey, 0U, sizeof(aesKey));
        memset(macKey, 0U, sizeof(macKey));
        memset(iv, 0U, sizeof(iv));
    }

    /** @brief Securely clear all session keys and IV (H-02: volatile barrier prevents dead-store elimination). */
    void clear() {
        volatile uint8_t* p = aesKey;
        for (uint8_t i = 0U; i < CW_AESKEY_SIZE; i++) { p[i] = 0U; }
        p = macKey;
        for (uint8_t i = 0U; i < CW_MACKEY_SIZE; i++) { p[i] = 0U; }
        p = iv;
        for (uint8_t i = 0U; i < CW_IV_SIZE; i++) { p[i] = 0U; }
    }
};

/******************************************************************
 * 5. Compile-time feature flags
 ******************************************************************/

/** Certificate chain verification is always enabled (SEC-004 / H-07).
 * Building with -DCW_VERIFY_CERT=0 is a hard error — it disables the card
 * authenticity gate and allows any forged key to be accepted. */
#ifndef CW_VERIFY_CERT
#define CW_VERIFY_CERT 1
#endif
#if CW_VERIFY_CERT == 0
#  error "CW_VERIFY_CERT=0 disables certificate chain verification (CRIT-02/H-07). " \
         "Remove -DCW_VERIFY_CERT=0 from your build flags — this gate must never be disabled."
#endif

/**
 * Set to 1 to enable library-internal debug logging via CW_Logger.
 * Disabled by default to preserve Flash on resource-constrained boards.
 * Must never be enabled in release/optimised builds — doing so leaks
 * session state over UART (SEC-012).
 */
#ifndef CW_DEBUG_LOGGING
#  define CW_DEBUG_LOGGING 0
#endif

#if CW_DEBUG_LOGGING && defined(NDEBUG)
#  error "CW_DEBUG_LOGGING=1 is set but NDEBUG is defined (release/optimised build). " \
         "Debug logging must not ship in production firmware — it leaks session state " \
         "over UART.  Remove -DCW_DEBUG_LOGGING=1 from your release build flags (SEC-012)."
#endif

#endif // CW_DEFS_H
