/*
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Cryptnox SA
 */

/**
 * @file CW_SecureChannel.h
 * @brief Cryptnox secure channel protocol over NFC.
 *
 * Declares @ref CW_SecureChannel, responsible for every low-level APDU
 * exchange required to establish and use an authenticated, encrypted
 * session with a Cryptnox Hardware Wallet:
 *  - SELECT AID
 *  - Manufacturer + card certificate retrieval and chain verification
 *  - Ephemeral key extraction and ECDH session key derivation
 *  - MUTUALLY AUTHENTICATE
 *  - AES-CBC + MAC secure messaging (encrypt / decrypt / SW check)
 *
 * The class is composed inside @ref CryptnoxWallet and is not normally used
 * directly by application code.
 */

#ifndef CW_SECURECHANNEL_H
#define CW_SECURECHANNEL_H

/******************************************************************
 * 1. Public constants
 ******************************************************************/

#define CW_PAIRING_DATA       "Cryptnox Basic CommonPairingData"
#define CW_PAIRING_DATA_BYTES (sizeof(CW_PAIRING_DATA) - 1U)

/******************************************************************
 * 2. Included files
 ******************************************************************/

#include "platform_compat.h"
#include "CW_NfcTransport.h"
#include "CW_Logger.h"
#include "CW_CryptoProvider.h"
#include "CW_Platform.h"
#include "CW_Defs.h"          /* for CW_SecureSession, CW_Curve, and constants */

/******************************************************************
 * 2. Class declaration
 ******************************************************************/

/**
 * @class CW_SecureChannel
 * @ingroup protocol
 * @brief Implements the Cryptnox secure channel protocol over NFC.
 *
 * Handles all low-level APDU exchanges required to establish and use
 * a secure session with the Cryptnox smart card:
 *  - Application selection (SELECT APDU)
 *  - Card certificate retrieval and ephemeral key extraction
 *  - ECDH-based session key derivation (OPEN SECURE CHANNEL + MUTUALLY AUTHENTICATE)
 *  - AES-CBC-MAC secure messaging (encrypt / decrypt / MAC verify)
 *  - Status word checking
 *
 * CW_SecureChannel is composed inside CryptnoxWallet and is not
 * intended to be used directly by application code.
 */
class CW_SecureChannel {
public:
    /**
     * @brief Construct a CW_SecureChannel.
     *
     * @param driver   Reference to the NFC transport.
     * @param logger   Reference to the logging interface.
     * @param crypto   Reference to the crypto provider.
     * @param platform Reference to the platform abstraction (for sleep_ms).
     */
    CW_SecureChannel(CW_NfcTransport& driver, CW_Logger& logger,
                     CW_CryptoProvider& crypto, CW_Platform& platform);

    CW_SecureChannel(const CW_SecureChannel&) = delete;
    CW_SecureChannel& operator=(const CW_SecureChannel&) = delete;

    /**
     * @brief Initialize the NFC transport module.
     * @return true if the module was successfully initialised, false otherwise.
     */
    bool begin();

    /**
     * @brief Detect a passive NFC target (ISO-DEP card).
     * @return true if a card was found, false otherwise.
     */
    bool inListPassiveTarget();

    /**
     * @brief Reset the NFC reader hardware.
     */
    void resetReader();

    /**
     * @brief Print the NFC reader firmware version to the logger.
     * @return true on success, false otherwise.
     */
    bool printFirmwareVersion();

    /**
     * @brief Send the SELECT APDU to activate the Cryptnox application.
     * @return true on success, false otherwise.
     */
    bool selectApdu();

    /**
     * @brief Retrieve the card's ephemeral public key via GET CARD CERTIFICATE.
     *
     * Sends a random challenge nonce to the card and stores it internally.
     * The nonce echo check is performed inside verifyCertificateChain() to
     * ensure replay protection is coupled with signature verification.
     *
     * @param[out] cardCertificate       Buffer to receive the raw certificate bytes.
     * @param[out] cardCertificateLength Actual certificate length (bytes).
     * @return true on success, false otherwise.
     */
    bool getCardCertificate(uint8_t* cardCertificate, uint8_t& cardCertificateLength);

    /**
     * @brief Extract the card's ephemeral EC P-256 public key from a certificate.
     *
     * @param[in]  cardCertificate      Raw certificate bytes.
     * @param[out] cardEphemeralPubKey  64-byte key (X||Y, no 0x04 prefix) for ECDH.
     * @param[out] fullEphemeralPubKey65 Optional 65-byte key including 0x04 prefix.
     * @return true on success, false otherwise.
     */
    bool extractCardEphemeralKey(const uint8_t* cardCertificate,
                                 uint8_t* cardEphemeralPubKey,
                                 uint8_t* fullEphemeralPubKey65 = NULL);

    /**
     * @brief Send OPEN SECURE CHANNEL and retrieve the session salt.
     *
     * Generates a client EC key pair via the crypto provider and sends the
     * public key to the card; the card responds with a 32-byte salt that
     * later feeds into Kenc / Kmac derivation in @ref mutuallyAuthenticate.
     *
     * @param[out] salt             32-byte session salt returned by the card.
     * @param[out] clientPublicKey  64-byte freshly generated client public key.
     * @param[out] clientPrivateKey 32-byte freshly generated client private key.
     * @param[in]  sessionCurve     ECC curve for key generation (secp256r1).
     * @return true on success, false otherwise.
     *
     * @pre @ref selectApdu must have been called successfully.
     * @warning @p clientPrivateKey is sensitive — the caller MUST wipe it
     *          via @ref CW_Utils::secure_wipe on every exit path.
     */
    bool openSecureChannel(uint8_t* salt,
                           uint8_t* clientPublicKey,
                           uint8_t* clientPrivateKey,
                           CW_Curve sessionCurve);

    /**
     * @brief Perform ECDH derivation and MUTUALLY AUTHENTICATE with the card.
     *
     * Final step of the secure channel handshake:
     *  1. ECDH shared secret = clientPrivateKey · cardEphemeralPubKey
     *  2. (Kenc || Kmac || IV) ← SHA-512(salt || pairingKey || sharedSecret)
     *  3. Encrypts a 16-byte random challenge with the new Kenc and sends
     *     it inside the MUTUALLY AUTHENTICATE APDU
     *  4. Verifies the card returns the same plaintext when re-encrypting
     *     its own counter — this proves the card knows Kenc
     *
     * @param[out] session             Secure session populated with derived keys + initial IV.
     * @param[in]  salt                32-byte salt from @ref openSecureChannel.
     * @param[in]  clientPublicKey     64-byte client public key.
     * @param[in]  clientPrivateKey    32-byte client private key.
     * @param[in]  sessionCurve        ECC curve.
     * @param[in]  cardEphemeralPubKey 64-byte card ephemeral public key.
     * @return true on success, false if ECDH failed, the card's challenge
     *         response did not match, or any APDU exchange failed.
     *
     * @pre @ref openSecureChannel must have been called and returned true.
     * @post On true: @p session has Kenc, Kmac, and rolling IV ready for
     *       @ref aesCbcEncrypt. On false: @p session is left untouched and
     *       must not be used.
     * @warning All ephemeral key material in the caller's stack
     *          (@p clientPrivateKey, @p salt) must be wiped after this call.
     */
    bool mutuallyAuthenticate(CW_SecureSession& session,
                              const uint8_t* salt,
                              uint8_t* clientPublicKey,
                              const uint8_t* clientPrivateKey,
                              CW_Curve sessionCurve,
                              const uint8_t* cardEphemeralPubKey);

    /**
     * @brief Retrieve the manufacturer certificate stored in card flash.
     *
     * @param[out] cert    Buffer to receive the raw DER certificate bytes.
     * @param[out] certLen Actual certificate length written.
     * @return true on success, false if APDU fails or buffer too small.
     */
    bool getManufacturerCertificate(uint8_t* cert, uint16_t& certLen);

    /**
     * @brief Fetch and cache the manufacturer certificate before getCardCertificate().
     *
     * The Cryptnox card state machine advances after GET_CARD_CERTIFICATE (INS=F8)
     * and will not respond to GET_MANUFACTURER_CERTIFICATE (INS=F7) after that point.
     * Call this method immediately after selectApdu() and before getCardCertificate()
     * so that verifyCertificateChain() can use the cached copy without an APDU.
     *
     * @return true if the certificate was fetched and cached, false otherwise.
     */
    bool preFetchManufacturerCert();

    /**
     * @brief Verify the full card certificate chain against the trusted CA.
     *
     * Walks the cached manufacturer certificate (fetched earlier by
     * @ref preFetchManufacturerCert), verifies its ECDSA signature against
     * each entry in @ref CW_TRUSTED_CA_KEYS, then verifies the card's
     * ephemeral certificate against the manufacturer public key. Also
     * checks that the challenge nonce sent in @ref getCardCertificate was
     * echoed back inside the card certificate.
     *
     * @param[in] cardCert    Raw card certificate bytes (typically 146 bytes).
     * @param[in] cardCertLen Length of @p cardCert.
     * @return One of the @c CW_CERT_* result codes:
     *
     * @retval CW_CERT_OK                 Chain verified end-to-end.
     * @retval CW_CERT_FORMAT_ERROR       Malformed certificate / unexpected TLV.
     * @retval CW_CERT_NONCE_MISMATCH     Card did not echo the challenge nonce.
     * @retval CW_CERT_CARD_SIG_INVALID   Card cert ECDSA signature failed verification.
     * @retval CW_CERT_MANUF_SIG_INVALID  Manufacturer cert signature does not match any trusted CA key.
     * @retval CW_CERT_KEY_NOT_FOUND      Device public-key OID not found in the certificate.
     *
     * @pre @ref preFetchManufacturerCert must have been called and returned
     *      true (the manufacturer certificate is cached internally and not
     *      re-fetchable after @ref getCardCertificate).
     * @pre @ref getCardCertificate must have been called so the challenge
     *      nonce is recorded internally.
     */
    uint8_t verifyCertificateChain(const uint8_t* cardCert, uint8_t cardCertLen);

    /**
     * @brief AES-CBC encrypt + MAC, send APDU, and decrypt response.
     *
     * Performs one secure messaging round-trip: pads and encrypts @p data
     * with Kenc using the current IV; computes a CMAC over (header || cipher)
     * with Kmac; sends the wrapped APDU; on the response, verifies the MAC
     * and decrypts the payload. The new IV for the next call is taken from
     * the last cipher block (rolling IV).
     *
     * @param[in,out] session               Secure session (Kenc / Kmac / IV).
     * @param[in]     apdu                  APDU header (CLA, INS, P1, P2).
     * @param[in]     apduLength            Header length (must be 4).
     * @param[in]     data                  Plaintext payload.
     * @param[in]     dataLength            Plaintext length (≤ @ref CW_USER_DATA_PAGE_SIZE).
     * @param[out]    decryptedOutput       Optional buffer for the decrypted response payload.
     * @param[out]    decryptedOutputLength Optional pointer to receive the decrypted payload length.
     * @return true if the APDU was sent and the response MAC verified +
     *         decrypted successfully; false on bad parameters, transport
     *         failure, MAC mismatch, or unexpected status word.
     *
     * @pre @p session must be the output of a successful
     *      @ref mutuallyAuthenticate call.
     * @warning Mutates @c session.iv. On any failure the IV may be left in
     *          an undefined state — treat the session as broken and tear it
     *          down with @ref CW_SecureSession::clear.
     * @warning Reuses module-private static buffers (@c s_apduBuf, @c s_macBuf,
     *          @c s_dataBuf). Not safe to call concurrently from multiple
     *          tasks; serialise at the application level.
     */
    bool aesCbcEncrypt(CW_SecureSession& session,
                       const uint8_t apdu[], uint16_t apduLength,
                       const uint8_t data[], uint16_t dataLength,
                       uint8_t* decryptedOutput = NULL,
                       uint16_t* decryptedOutputLength = NULL);

    /**
     * @brief Verify MAC and decrypt an encrypted APDU response.
     *
     * Internal helper called from @ref aesCbcEncrypt — exposed for the fuzz
     * harness. Verifies the response MAC against Kmac, then decrypts the
     * payload with Kenc using the supplied IV (which is the MAC of the
     * sent request, by protocol).
     *
     * @param[in,out] session               Secure session.
     * @param[in]     response              Encrypted response buffer (MAC || cipher || SW).
     * @param[in]     responseLen           Response length.
     * @param[in]     macValue              MAC of the request — used as decrypt IV.
     * @param[out]    decryptedOutput       Optional plaintext output buffer.
     * @param[out]    decryptedOutputLength Optional plaintext output length.
     * @return true if MAC matched and decryption succeeded, false otherwise.
     *
     * @warning A false return indicates either tampering or a corrupted
     *          channel — the session must not be reused without renegotiation.
     */
    bool aesCbcDecrypt(const CW_SecureSession& session,
                       uint8_t* response, size_t responseLen,
                       uint8_t* macValue,
                       uint8_t* decryptedOutput = NULL,
                       uint16_t* decryptedOutputLength = NULL);

    /**
     * @brief Verify the SW1/SW2 status word at the end of an APDU response.
     *
     * @param response       APDU response buffer.
     * @param responseLength Response length.
     * @param sw1Expected    Expected SW1 byte.
     * @param sw2Expected    Expected SW2 byte.
     * @return true if last two bytes match expectations, false otherwise.
     */
    bool checkStatusWord(const uint8_t* response, uint16_t responseLength,
                         uint8_t sw1Expected, uint8_t sw2Expected);

private:
    CW_NfcTransport&   _driver;   ///< NFC transport for APDU exchange.
    CW_Logger&         _logger;   ///< Logging interface.
    CW_CryptoProvider& _crypto;   ///< Crypto operations (AES, SHA, ECDH, RNG).
    CW_Platform&       _platform; ///< Platform abstraction (sleep_ms).

    /** @brief Nonce sent in the last getCardCertificate() call; checked in verifyCertificateChain(). */
    uint8_t _lastNonce[CW_CERT_NONCE_SIZE];

    /** @brief Non-zero when s_mfCertBuf holds a valid pre-fetched manufacturer certificate. */
    uint16_t _cachedMfCertLen;

    static bool parseDerSigToRaw(const uint8_t* der, uint8_t derLen,
                                 uint8_t* raw64);

    bool verifyEcdsaSha256(const uint8_t* pubKey64,
                           const uint8_t* message, uint16_t msgLen,
                           const uint8_t* derSig, uint8_t derSigLen);

#ifdef CW_FUZZ_BUILD
    friend struct DerFuzzTarget;
#endif
};

#endif // CW_SECURECHANNEL_H
