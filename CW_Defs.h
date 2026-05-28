/*
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Cryptnox SA
 */

/**
 * @file CW_Defs.h
 * @brief Shared constants, error codes, and session state for the SDK.
 *
 * Defines:
 *  - AES session key / IV sizes
 *  - Generic and SIGN-specific error codes (@c CW_OK, @c CW_NOK, @c CW_SIGN_*)
 *  - SIGN APDU parameter values (key types, signature types, PIN/PIN-less)
 *  - Buffer and protocol size limits
 *  - Certificate verification result codes (@c CW_CERT_*)
 *  - @ref CW_Curve enum (portable curve identifier)
 *  - @ref CW_SecureSession (encryption + MAC keys + rolling IV)
 *  - Compile-time security gates: @c CW_VERIFY_CERT, @c CW_DEBUG_LOGGING
 */

#ifndef CW_DEFS_H
#define CW_DEFS_H

/******************************************************************
 * 0. Doxygen module groups (used by @ingroup throughout the SDK)
 ******************************************************************/

/**
 * @defgroup api Public API
 * @brief Types and classes application code interacts with directly.
 *
 * Includes @ref CryptnoxWallet (the main entry point), the sign request /
 * result structs, @ref CW_CardInfo, and @ref CW_SecureSession.
 */

/**
 * @defgroup protocol Secure channel protocol
 * @brief Low-level secure messaging implementation.
 *
 * @ref CW_SecureChannel is composed inside @ref CryptnoxWallet and is not
 * normally used directly. Documented here for callers that need to drive
 * the activation sequence manually (e.g. custom retry policies, fuzzing).
 */

/**
 * @defgroup adapters Adapter interfaces
 * @brief Abstract contracts a host integration must implement.
 *
 * Provide concrete implementations of @ref CW_NfcTransport,
 * @ref CW_CryptoProvider, @ref CW_Logger, and @ref CW_Platform when porting
 * the SDK to a new MCU or operating system.
 */

/**
 * @defgroup util Utilities & shared definitions
 * @brief Platform-independent helpers and shared constants.
 *
 * Includes @ref CW_Utils (constant-time compare, secure wipe, safe memcpy,
 * RNG), the @c CW_CERT_* / @c CW_SIGN_* error codes, and the trusted-CA
 * key table (@ref CW_TrustedKeys.h).
 */

/******************************************************************
 * 1. Included files
 ******************************************************************/

#include "platform_compat.h"
#include "CW_Utils.h"

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
 * @ingroup util
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
 * @ingroup api
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

    /** @brief Securely clear all session keys and IV. */
    void clear() {
        CW_Utils::secure_wipe(aesKey, sizeof(aesKey));
        CW_Utils::secure_wipe(macKey, sizeof(macKey));
        CW_Utils::secure_wipe(iv,     sizeof(iv));
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
 *
 * Off by default. Enabling it kills flash optimisation — measured on
 * Arduino UNO R4 (Renesas RA4M1): +149 KB flash, +6 KB SRAM (31 % → 88 %
 * of a 256 KB image on the Sign example). Same order of magnitude on
 * every constrained MCU.
 *
 * Also leaks session state over UART (SEC-012). Bring-up only, never in
 * release builds.
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
