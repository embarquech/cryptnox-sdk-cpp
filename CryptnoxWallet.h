/*
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Cryptnox SA
 */

/**
 * @file CryptnoxWallet.h
 * @brief High-level API for interacting with a Cryptnox Hardware Wallet over NFC.
 *
 * Declares @ref CryptnoxWallet, the main entry point for application code.
 * The class wires together the four abstract adapters supplied by the host
 * integration (NFC transport, crypto provider, logger, platform) and exposes
 * the wallet operations: card connection, secure channel establishment,
 * card info retrieval, PIN verification, transaction signing, and user-data
 * writing.
 *
 * @see CW_NfcTransport
 * @see CW_CryptoProvider
 * @see CW_Logger
 * @see CW_Platform
 */

#ifndef CRYPTNOXWALLET_H
#define CRYPTNOXWALLET_H

/******************************************************************
 * 1. Included files
 ******************************************************************/

#include "platform_compat.h"
#include "CW_Defs.h"
#include "CW_Logger.h"
#include "CW_Platform.h"
#include "CW_SecureChannel.h"
#include "CW_Utils.h"

/******************************************************************
 * 2. Typedefs / structs (sign API)
 ******************************************************************/

/** @brief Max name length stored on a Cryptnox card (per card spec). */
#define CW_CARD_NAME_MAX_LEN  (20U)

/** @brief Max email length stored on a Cryptnox card (per card spec). */
#define CW_CARD_EMAIL_MAX_LEN (60U)

/**
 * @struct CW_CardInfo
 * @ingroup api
 * @brief Subset of the Cryptnox card info returned by APDU 0x80FA0000.
 *
 * Mirrors the fields the Python SDK exposes as @c card._owner: ASCII name
 * and email programmed when the card was initialised. NUL-terminated.
 */
struct CW_CardInfo {
    char name[CW_CARD_NAME_MAX_LEN + 1U];    /**< NUL-terminated ASCII name. */
    char email[CW_CARD_EMAIL_MAX_LEN + 1U];  /**< NUL-terminated ASCII email. */

    CW_CardInfo() {
        name[0]  = '\0';
        email[0] = '\0';
    }
};

/**
 * @struct CW_SignRequest
 * @ingroup api
 * @brief Request parameters for @ref CryptnoxWallet::sign.
 *
 * Owns the PIN buffer for the lifetime of the request — the destructor
 * securely wipes it (@ref CW_Utils::secure_wipe), so allocating the request
 * on the stack inside a tight scope is the recommended pattern.
 */
struct CW_SignRequest {
    CW_SecureSession& session;       /**< Reference to an open secure session. */
    uint8_t keyType;                 /**< Key / path type — one of the @c CW_SIGN_CURR_*, @c CW_SIGN_DERIVE_*, @c CW_SIGN_PINLESS_K1 constants. */
    uint8_t signatureType;           /**< Signature format — one of @c CW_SIGN_SIG_ECDSA_LOW_S, @c CW_SIGN_SIG_ECDSA_EOSIO, @c CW_SIGN_SIG_SCHNORR_BIP340. */
    uint8_t pin[CW_MAX_PIN_LENGTH];  /**< PIN bytes (4–9 ASCII digits). Zero-padded; cleared in the destructor. */
    bool pinLessMode;                /**< false = PIN path, true = PIN-less path (requires @c keyType == @ref CW_SIGN_PINLESS_K1). */
    const uint8_t* hash;             /**< Pointer to the hash to sign (typically 32 bytes — SHA-256 of the transaction). */
    uint8_t hashLength;              /**< Length of @c hash in bytes (must be ≤ @ref CW_HASH_SIZE). */
    const uint8_t* derivePath;       /**< BIP32 path bytes for DERIVE modes; @c NULL for CURR / PINLESS modes. */
    uint8_t derivePathLength;        /**< Length of @c derivePath in bytes (must be a multiple of 4). */

    /**
     * @brief Construct a sign request with sensible defaults.
     * @param[in] sess    Open secure session.
     * @param[in] kType   Key type. Defaults to @ref CW_SIGN_CURR_K1.
     * @param[in] sigType Signature type. Defaults to @ref CW_SIGN_SIG_ECDSA_LOW_S.
     * @param[in] pinless PIN mode. Defaults to PIN required (@ref CW_SIGN_WITH_PIN).
     */
    explicit CW_SignRequest(CW_SecureSession& sess,
                            uint8_t kType   = CW_SIGN_CURR_K1,
                            uint8_t sigType = CW_SIGN_SIG_ECDSA_LOW_S,
                            bool pinless    = CW_SIGN_WITH_PIN)
        : session(sess), keyType(kType), signatureType(sigType),
          pinLessMode(pinless), hash(NULL), hashLength(0U),
          derivePath(NULL), derivePathLength(0U) {
        memset(pin, 0U, sizeof(pin));
    }

    /** @brief Securely wipes the PIN buffer. */
    ~CW_SignRequest() {
        CW_Utils::secure_wipe(pin, sizeof(pin));
    }
};

/**
 * @struct CW_SignResult
 * @brief Result of @ref CryptnoxWallet::sign.
 *
 * The error code is checked first: when it is @ref CW_OK the signature is
 * valid raw (r || s) on secp256k1 / secp256r1 (depending on the
 * @c keyType used). On any other code @c signature is left zero.
 */
struct CW_SignResult {
    uint8_t signature[CW_RAW_SIGNATURE_SIZE]; /**< Raw 64-byte signature: r[32] || s[32]. Zero on failure. */
    uint8_t errorCode;                        /**< @ref CW_OK on success, otherwise a @c CW_SIGN_* / @c CW_INVALID_SESSION code. */

    /** @brief Construct a default-failure result. */
    CW_SignResult() : errorCode(CW_NOK) {
        memset(signature, 0U, sizeof(signature));
    }
};

/******************************************************************
 * 3. CryptnoxWallet class
 ******************************************************************/

/**
 * @class CryptnoxWallet
 * @ingroup api
 * @brief High-level interface for interacting with a Cryptnox Hardware Wallet over NFC.
 *
 * Manages card connection, secure channel establishment (delegated to
 * @ref CW_SecureChannel), PIN verification, transaction signing, user-data
 * writing, and card-info retrieval.
 *
 * Dependencies are injected by the caller via the constructor. The class
 * itself only talks to the four abstract adapters, keeping the
 * implementation platform-independent.
 *
 * @par Typical lifecycle
 * @code
 * CryptnoxWallet wallet(transport, logger, crypto, platform);
 * wallet.begin();
 *
 * CW_SecureSession session;
 * if (wallet.connect(session)) {
 *     wallet.verifyPin(session, pin, pinLen);
 *     wallet.sign(req);
 * }
 * wallet.disconnect(session);   // mandatory — even on connect() failure
 * @endcode
 *
 * @note Single-shot use — the class is non-copyable. Reuse the same
 *       @ref CryptnoxWallet instance across multiple card sessions; do not
 *       construct one per APDU.
 */
class CryptnoxWallet {
public:
    /**
     * @brief Construct a CryptnoxWallet.
     *
     * @param driver   Reference to the NFC transport implementation.
     * @param logger   Reference to the logging implementation.
     * @param crypto   Reference to the crypto provider implementation.
     * @param platform Reference to the platform abstraction (for sleep_ms).
     */
    CryptnoxWallet(CW_NfcTransport& driver, CW_Logger& logger,
                   CW_CryptoProvider& crypto, CW_Platform& platform);

    CryptnoxWallet(const CryptnoxWallet&) = delete;
    CryptnoxWallet& operator=(const CryptnoxWallet&) = delete;

    /**
     * @brief Initialize the NFC module via the underlying transport driver.
     * @return true if the module was successfully initialised, false otherwise.
     */
    bool begin();

    /**
     * @brief Connect to the Cryptnox card and establish a secure channel.
     *
     * Retries the full card activation sequence up to @c CW_CONNECT_MAX_ATTEMPTS
     * times. On any failure (including transient transport errors) the session
     * is securely wiped before the next attempt so no partial key material
     * can survive a retry (CRIT-04).
     *
     * @param[out] session Secure session to populate with derived keys and IV
     *                     on success; left zero-wiped on failure.
     * @return true if the secure channel was established and @p session is
     *         ready for use, false otherwise.
     *
     * @post On true: @p session holds valid Kenc / Kmac / IV.
     * @post On false: @p session is zero-wiped.
     * @warning Always call @ref disconnect() after this — even on failure — to
     *          release the reader for the next card cycle.
     */
    bool connect(CW_SecureSession& session);

    /**
     * @brief Establish a secure channel (SELECT → certificate → ECDH → mutual auth).
     *
     * Lower-level than @ref connect(): runs the full activation sequence once,
     * without the retry loop. Used internally by @ref connect(); exposed for
     * advanced callers that handle retry policy themselves.
     *
     * @param[out] session Secure session to populate.
     * @return true if mutual authentication succeeded, false if any step of
     *         the activation sequence (SELECT, certificate chain verification,
     *         ECDH, MAC check) failed.
     *
     * @warning All sensitive ephemeral key material is wiped from the stack
     *          on every exit path (H-01, M-02).
     */
    bool establishSecureChannel(CW_SecureSession& session);

    /**
     * @brief Disconnect and securely clear the session.
     *
     * Wipes any session keys and resets the NFC reader so the next card
     * detection cycle starts from a clean state.
     *
     * @param[in,out] session Session to clear. Safe to pass a never-connected
     *                        or partially-connected session.
     *
     * @pre Must be called at the end of every card-processing iteration —
     *      including iterations where @ref connect() failed — otherwise the
     *      NFC reader may remain in an unresponsive state.
     */
    void disconnect(CW_SecureSession& session);

    /**
     * @brief Send a secured GET CARD INFO APDU (0x80FA0000) and optionally
     *        decode the owner name/email from the response.
     *
     * @param[in,out] session  Valid secure session.
     * @param[out]    info     Optional output. When non-NULL and the call
     *                         succeeds, populated with the card's owner
     *                         name and email (ASCII, NUL-terminated).
     * @return true if the secure exchange completed and (when @c info is
     *         non-NULL) parsing the name/email fields succeeded.
     */
    bool getCardInfo(CW_SecureSession& session, CW_CardInfo* info = NULL);

    /**
     * @brief Verify the PIN code on the card.
     *
     * Sends an encrypted VERIFY PIN APDU. The card maintains a try counter:
     * every wrong attempt decrements it, and reaching zero locks the PIN
     * permanently until a successful PUK / re-initialisation flow.
     *
     * @param[in,out] session   Valid secure session.
     * @param[in]     pin       PIN bytes (ASCII digits, 4–9 characters).
     * @param[in]     pinLength Length of the PIN (must be in
     *                          [@ref CW_MIN_PIN_LENGTH, @ref CW_MAX_PIN_LENGTH]).
     * @return true if the card accepted the PIN, false on wrong PIN, closed
     *         or invalid session, length out of range, or transport / MAC
     *         failure.
     *
     * @warning Each failed attempt decrements the card's PIN counter. Treat
     *          a false return as "wrong PIN" only after confirming session
     *          validity — a transport glitch should not be retried with a
     *          new PIN.
     */
    bool verifyPin(CW_SecureSession& session, const uint8_t* pin, uint8_t pinLength);

    /**
     * @brief Sign a 32-byte digest using a card-resident key.
     *
     * Builds the SIGN payload (hash || optional BIP32 path || optional PIN),
     * sends it through the secure channel, parses the DER signature returned
     * by the card, and unpacks it into the canonical 64-byte raw form
     * (r[32] || s[32]).
     *
     * @param[in] request Sign parameters — must reference a valid secure
     *                    session, a 32-byte hash, the desired key/signature
     *                    type, and the PIN (unless @c pinLessMode is set).
     * @return @ref CW_SignResult. On success @c errorCode is @ref CW_OK and
     *         @c signature holds the 64-byte raw signature. On failure the
     *         signature is zeroed and @c errorCode indicates the cause:
     *
     * @retval CW_OK                                  Signature valid.
     * @retval CW_INVALID_SESSION                     Secure channel not open.
     * @retval CW_SIGN_KEY_TOO_SHORT                  Bad hash buffer / length.
     * @retval CW_SIGN_NO_KEY_LOADED                  Card rejected the SIGN APDU.
     * @retval CW_SIGN_PIN_INCORRECT                  PIN length out of range.
     * @retval CW_SIGN_KEY_TOO_SHORT_WITH_PINLESS_MODE
     *                                                PIN-less mode requested but
     *                                                @c keyType is not
     *                                                @ref CW_SIGN_PINLESS_K1.
     *
     * @warning When @c pinLessMode is false the @c request.pin field must be
     *          populated. The destructor of @ref CW_SignRequest securely
     *          wipes the PIN, but the caller must zero any other copy.
     */
    CW_SignResult sign(CW_SignRequest& request);

    /**
     * @brief Write data to a user memory slot, paginating in CW_USER_DATA_PAGE_SIZE chunks.
     *
     * @param[in,out] session    Valid secure session.
     * @param[in]     slot       User data slot index.
     * @param[in]     data       Data to write.
     * @param[in]     dataLength Total bytes to write.
     * @return true if all pages written successfully, false otherwise.
     */
    bool writeUserData(CW_SecureSession& session, uint8_t slot,
                       const uint8_t* data, uint16_t dataLength);

    /**
     * @brief Parse a DER-encoded ECDSA signature to extract raw r and s values.
     *
     * @param[in]  der       DER-encoded signature bytes.
     * @param[in]  derLength DER length.
     * @param[out] r         Buffer for r (at least 33 bytes).
     * @param[out] rLength   Actual r length written.
     * @param[out] s         Buffer for s (at least 33 bytes).
     * @param[out] sLength   Actual s length written.
     * @return true on success, false on malformed DER.
     */
    static bool parseDerSignature(const uint8_t* der, uint8_t derLength,
                                  uint8_t* r, uint8_t& rLength,
                                  uint8_t* s, uint8_t& sLength);

private:
    CW_Logger&       _logger;   ///< Logging interface.
    CW_Platform&     _platform; ///< Platform abstraction (sleep_ms).
    CW_SecureChannel _secure;   ///< Owned secure channel.

    bool isSecureChannelOpen(const CW_SecureSession& session) const;
    bool printPN532FirmwareVersion();

    /* Sign helper methods */
    bool validateSignRequest(const CW_SignRequest& request, CW_SignResult& result);
    void buildSignPayload(const CW_SignRequest& request, uint8_t* data, uint16_t& dataLength);
    bool sendSignApdu(CW_SignRequest& request, const uint8_t* data, uint16_t dataLength,
                      uint8_t* derResponse, uint16_t& derLength, CW_SignResult& result);
    bool extractRawSignature(const uint8_t* derResponse, uint16_t derLength, CW_SignResult& result);
    void debugPrintSignature(const uint8_t* signature);
};

#endif // CRYPTNOXWALLET_H
