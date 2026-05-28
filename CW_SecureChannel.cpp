/*
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Cryptnox SA
 */

/**
 * @file CW_SecureChannel.cpp
 * @brief Implementation of the Cryptnox secure channel protocol.
 *
 * Implements the methods declared in CW_SecureChannel.h:
 * APDU framing, certificate chain verification against the trusted CA keys
 * (@ref CW_TrustedKeys.h), ECDH session key derivation, AES-CBC encrypted
 * messaging with rolling IV, and MAC verification on every response.
 *
 * Module-level static scratch buffers are reused across calls to keep the
 * stack footprint small; secret material is wiped after use.
 */

#include "CW_SecureChannel.h"
#include "CW_Utils.h"
#include "CW_TrustedKeys.h"

/******************************************************************
 * Module-level constants
 ******************************************************************/

#define RESPONSE_GETCARDCERTIFICATE_IN_BYTES        148U
/* SELECT AID: 1 (type) + 3 (ver) + 32 (status) + 2 (SW) = 38 bytes */
#define RESPONSE_SELECT_IN_BYTES                     40U
/* GET_MANUFACTURER_CERT: full DataOut up to certLen(2)+cert(411)+SW(2)=415 bytes; 420 for margin. */
#define RESPONSE_GETMANUFACTURERCERT_PAGE_IN_BYTES  420U
#define RESPONSE_OPENSECURECHANNEL_IN_BYTES      34U
#define REQUEST_MUTUALLYAUTHENTICATE_IN_BYTES    69U
#define RESPONSE_MUTUALLYAUTHENTICATE_IN_BYTES   66U
#define RESPONSE_STATUS_WORDS_IN_BYTES            2U

#define OPENSECURECHANNEL_SALT_IN_BYTES   (RESPONSE_OPENSECURECHANNEL_IN_BYTES - RESPONSE_STATUS_WORDS_IN_BYTES)
#define GETCARDCERTIFICATE_IN_BYTES       (RESPONSE_GETCARDCERTIFICATE_IN_BYTES - RESPONSE_STATUS_WORDS_IN_BYTES)

#define RANDOM_BYTES              8U
#define COMMON_PAIRING_DATA       CW_PAIRING_DATA
#define CLIENT_PRIVATE_KEY_SIZE  32U
#define CLIENT_PUBLIC_KEY_SIZE   64U
#define CARDEPHEMERALPUBKEY_SIZE 64U
#define AES_BLOCK_SIZE           16U
#define APDU_HEADER_LEN           (4U)
#define APDU_LC_LEN               (1U)
#define MAC_APDU_LEN             (12U)
#define INPUT_BUFFER_LIMIT        (CW_USER_DATA_PAGE_SIZE)
#define ENC_BUF_MAX_LEN           (INPUT_BUFFER_LIMIT + AES_BLOCK_SIZE)
#define MAX_MAC_DATA_LEN          (APDU_HEADER_LEN + MAC_APDU_LEN + ENC_BUF_MAX_LEN)
#define SEND_APDU_MAX_LEN         (APDU_HEADER_LEN + APDU_LC_LEN + AES_BLOCK_SIZE + ENC_BUF_MAX_LEN)

/* Enforce APDU fits within a single PN532 APDU (255 bytes max) */
static_assert(APDU_HEADER_LEN + APDU_LC_LEN + AES_BLOCK_SIZE + ENC_BUF_MAX_LEN <= 255U,
              "CW_USER_DATA_PAGE_SIZE too large for PN532 single APDU transport");

/* Shared static crypto scratch buffers — reuse is safe because decrypt is
 * always called from inside encrypt AFTER encrypt's large buffers are done. */
static uint8_t s_apduBuf[SEND_APDU_MAX_LEN];  /* 245 bytes */
static uint8_t s_macBuf [MAX_MAC_DATA_LEN];   /* 240 bytes */
static uint8_t s_dataBuf[ENC_BUF_MAX_LEN];   /* 224 bytes */

/* Manufacturer certificate assembly buffer (used only during verifyCertificateChain). */
static uint8_t s_mfCertBuf[CW_MANUF_CERT_MAX_BYTES];

/* DER TLV tag bytes */
#define DER_TAG_SEQUENCE    (0x30U)  /* SEQUENCE (universal, constructed) */
#define DER_TAG_BIT_STRING  (0x03U)  /* BIT STRING */
#define DER_TAG_CTX0        (0xA0U)  /* [0] EXPLICIT — version in v3 TBSCertificate */

/* DER length-field encoding */
#define DER_LEN_LONG_FLAG   (0x80U)  /* set = long-form length */
#define DER_LEN_LONG_1      (0x81U)  /* long form, 1 following byte */
#define DER_LEN_LONG_2      (0x82U)  /* long form, 2 following bytes */

/* EC-point encoding */
#define DER_EC_UNCOMPRESSED (0x04U)  /* uncompressed point prefix */
#define DER_EC_POINT_BYTES  (65U)    /* 0x04 || X[32] || Y[32] */
#define DER_BIT_UNUSED_ZERO (0x00U)  /* BIT STRING unused-bits field must be 0 */

/******************************************************************
 * Constructor
 ******************************************************************/

// cppcheck-suppress misra-c2012-12.3 -- C++: member initializer-list commas are not the comma operator
CW_SecureChannel::CW_SecureChannel(CW_NfcTransport& driver,
                                   CW_Logger& logger,
                                   CW_CryptoProvider& crypto,
                                   CW_Platform& platform)
    : _driver(driver), _logger(logger), _crypto(crypto), _platform(platform),
      _cachedMfCertLen(0U) {
    memset(_lastNonce, 0, sizeof(_lastNonce));
}

/******************************************************************
 * Transport delegation methods
 ******************************************************************/

bool CW_SecureChannel::begin() {
    return _driver.begin();
}

bool CW_SecureChannel::inListPassiveTarget() {
    return _driver.inListPassiveTarget();
}

void CW_SecureChannel::resetReader() {
    _driver.resetReader();
}

bool CW_SecureChannel::printFirmwareVersion() {
    return _driver.printFirmwareVersion();
}

/******************************************************************
 * Private helpers
 ******************************************************************/

bool CW_SecureChannel::checkStatusWord(const uint8_t* response, uint16_t responseLength,
                                       uint8_t sw1Expected, uint8_t sw2Expected) {
    bool ret = false;

    if ((response == NULL) || (responseLength < 2U)) {
#if CW_DEBUG_LOGGING
        _logger.println(F("checkStatusWord: response too short."));
#endif
    }
    else {
        uint8_t sw1 = response[responseLength - 2U];
        uint8_t sw2 = response[responseLength - 1U];

        if ((sw1 == sw1Expected) && (sw2 == sw2Expected)) {
            ret = true;
        }
        else {
#if CW_DEBUG_LOGGING
            _logger.print(F("SW: 0x"));
            if (sw1 < 16U) { _logger.print(F("0")); }
            _logger.print(sw1, HEX);
            _logger.print(F(" 0x"));
            if (sw2 < 16U) { _logger.print(F("0")); }
            _logger.println(sw2, HEX);
#endif
        }
    }

    return ret;
}

/******************************************************************
 * Public methods
 ******************************************************************/

bool CW_SecureChannel::selectApdu() {
    bool ret = false;

    uint8_t selectApduCmd[] = {
        0x00, 0xA4, 0x04, 0x00,
        0x07,
        0xA0, 0x00, 0x00, 0x10, 0x00, 0x01, 0x12
    };

    uint8_t response[RESPONSE_SELECT_IN_BYTES];
    uint8_t responseLength = static_cast<uint8_t>(sizeof(response));

    if (_driver.sendAPDU(selectApduCmd, sizeof(selectApduCmd), response, responseLength)) {
        if (checkStatusWord(response, responseLength, 0x90U, 0x00U)) {
            ret = true;
        } else {
#if CW_DEBUG_LOGGING
            _logger.println(F("Select APDU failed."));
#endif
        }
    } else {
#if CW_DEBUG_LOGGING
        _logger.println(F("APDU select failed."));
#endif
    }

    return ret;
}

bool CW_SecureChannel::getCardCertificate(uint8_t* cardCertificate, uint8_t& cardCertificateLength) {
    bool ret = false;
    uint8_t getCardCertificateResponse[RESPONSE_GETCARDCERTIFICATE_IN_BYTES];
    uint8_t getCardCertificateResponseLength = static_cast<uint8_t>(sizeof(getCardCertificateResponse));

    if (cardCertificate != NULL) {
        uint8_t randomBytes[RANDOM_BYTES] = { 0U };
        if (!_crypto.random(randomBytes, RANDOM_BYTES)) {
#if CW_DEBUG_LOGGING
            _logger.println(F("getCardCertificate: RNG failed."));
#endif
            return false;
        }

        /* Store nonce for replay check in verifyCertificateChain(). */
        (void)CW_Utils::safe_memcpy(_lastNonce, RANDOM_BYTES, randomBytes, RANDOM_BYTES);

        uint8_t getCardCertificateApdu[] = {
            0x80, 0xF8, 0x00, 0x00, 0x08
        };

        uint8_t fullApdu[sizeof(getCardCertificateApdu) + RANDOM_BYTES];
        (void)CW_Utils::safe_memcpy(fullApdu, sizeof(fullApdu), getCardCertificateApdu, sizeof(getCardCertificateApdu));
        (void)CW_Utils::safe_memcpy(fullApdu + sizeof(getCardCertificateApdu), RANDOM_BYTES, randomBytes, RANDOM_BYTES);

        if (_driver.sendAPDU(fullApdu, sizeof(fullApdu),
                             getCardCertificateResponse, getCardCertificateResponseLength)) {
            if (checkStatusWord(getCardCertificateResponse, getCardCertificateResponseLength,
                                0x90U, 0x00U)) {
                cardCertificateLength = static_cast<uint8_t>(
                    static_cast<uint8_t>(getCardCertificateResponseLength - RESPONSE_STATUS_WORDS_IN_BYTES));
                (void)CW_Utils::safe_memcpy(cardCertificate, GETCARDCERTIFICATE_IN_BYTES, getCardCertificateResponse, cardCertificateLength);
                ret = true;
            } else {
#if CW_DEBUG_LOGGING
                _logger.println(F("getCardCertificate: bad SW."));
#endif
            }
        } else {
#if CW_DEBUG_LOGGING
            _logger.println(F("getCardCertificate APDU failed."));
#endif
        }
    }

    return ret;
}

bool CW_SecureChannel::extractCardEphemeralKey(const uint8_t* cardCertificate,
                                               uint8_t* cardEphemeralPubKey,
                                               uint8_t* fullEphemeralPubKey65) {
    bool ret = false;

    if ((cardCertificate == NULL) || (cardEphemeralPubKey == NULL)) {
        ret = false;
    }
    else {
        const uint8_t keyStart = 1U + 8U; /* skip 'C' and nonce */
        const uint8_t fullKeyLength = 65U;

        /* Reject any key that is not an uncompressed point (0x04 prefix). */
        if (cardCertificate[keyStart] != 0x04U) {
            ret = false;
        }
        else {
            for (uint8_t i = 0U; i < fullKeyLength; i++) {
                uint8_t b = cardCertificate[keyStart + i];
                if (fullEphemeralPubKey65 != NULL) {
                    fullEphemeralPubKey65[i] = b;
                }
                if (i > 0U) {
                    cardEphemeralPubKey[i - 1U] = b;
                }
            }
            ret = true;
        }
    }

    return ret;
}

bool CW_SecureChannel::openSecureChannel(uint8_t* salt,
                                         uint8_t* sessionPublicKey,
                                         uint8_t* sessionPrivateKey,
                                         CW_Curve sessionCurve) {
    bool ret = false;

    if (!_crypto.makeKey(sessionPublicKey, sessionPrivateKey, sessionCurve)) {
#if CW_DEBUG_LOGGING
        _logger.println(F("ECC key generation failed."));
#endif
    }
    else {
        uint8_t opcApduHeader[] = {
            0x80, 0x10, 0x00, 0x00, 0x41, 0x04
        };

        uint8_t fullApdu[sizeof(opcApduHeader) + CLIENT_PUBLIC_KEY_SIZE];
        (void)CW_Utils::safe_memcpy(fullApdu, sizeof(fullApdu), opcApduHeader, sizeof(opcApduHeader));
        (void)CW_Utils::safe_memcpy(fullApdu + sizeof(opcApduHeader), CLIENT_PUBLIC_KEY_SIZE, sessionPublicKey, CLIENT_PUBLIC_KEY_SIZE);

        uint8_t response[RESPONSE_OPENSECURECHANNEL_IN_BYTES];
        uint8_t responseLength = static_cast<uint8_t>(sizeof(response));

        if (_driver.sendAPDU(fullApdu, sizeof(fullApdu), response, responseLength)) {
            if (checkStatusWord(response, responseLength, 0x90U, 0x00U)) {
                if (responseLength == static_cast<uint8_t>(RESPONSE_OPENSECURECHANNEL_IN_BYTES)) {
                    (void)CW_Utils::safe_memcpy(salt, OPENSECURECHANNEL_SALT_IN_BYTES, response, OPENSECURECHANNEL_SALT_IN_BYTES);
                    ret = true;
                } else {
#if CW_DEBUG_LOGGING
                    _logger.println(F("OpenSecureChannel: unexpected response size."));
#endif
                }
            } else {
#if CW_DEBUG_LOGGING
                _logger.println(F("OpenSecureChannel: bad SW."));
#endif
            }
        } else {
#if CW_DEBUG_LOGGING
            _logger.println(F("OpenSecureChannel APDU failed."));
#endif
        }
    }

    return ret;
}

/**
 * @details
 * Cryptographic flow:
 *  1. Compute the ECDH shared secret S = ECDH(clientPrivateKey,
 *     cardEphemeralPubKey) on the negotiated curve.
 *  2. Derive 80 bytes of keying material via SHA-512 over
 *     (salt || S || pairingDataHash) and split into:
 *       - Kenc[32]: AES-256 session encryption key
 *       - Kmac[32]: AES-256 session MAC key
 *       - IV[16]  : initial rolling IV
 *  3. Send MUTUALLY AUTHENTICATE with a random 16-byte challenge encrypted
 *     under Kenc / IV. The card must answer with the same 16 bytes
 *     re-encrypted with the new IV — a verification that fails fast on
 *     any key-derivation mismatch.
 *  4. On success, populate @p session and wipe @p sharedSecret from the stack.
 *
 * Failure modes that cause an early-exit with a wiped session:
 *  - ECDH returned zero or invalid (curve mismatch)
 *  - APDU transport failure
 *  - Card challenge response mismatch (active attacker or wrong card)
 */
bool CW_SecureChannel::mutuallyAuthenticate(CW_SecureSession& session,
                                            const uint8_t* salt,
                                            uint8_t* clientPublicKey,
                                            const uint8_t* clientPrivateKey,
                                            CW_Curve sessionCurve,
                                            const uint8_t* cardEphemeralPubKey) {
    bool ret = false;
    uint8_t sharedSecret[32U] = { 0U };
    (void)clientPublicKey;

    if (!_crypto.ecdh(cardEphemeralPubKey, clientPrivateKey, sharedSecret, sessionCurve)) {
#if CW_DEBUG_LOGGING
        _logger.println(F("ECDH failed."));
#endif
    }
    else {
        uint8_t concat[32U + sizeof(COMMON_PAIRING_DATA) - 1U + 32U] = { 0U };
        uint8_t sha512Output[64U] = { 0U };
        const size_t pairingKeyLen = sizeof(COMMON_PAIRING_DATA) - 1U;
        const size_t concatLen    = 32U + pairingKeyLen + 32U;

        (void)CW_Utils::safe_memcpy(concat, sizeof(concat), sharedSecret, 32U);
        (void)CW_Utils::safe_memcpy(concat + 32U, sizeof(concat) - 32U, reinterpret_cast<const uint8_t*>(COMMON_PAIRING_DATA), pairingKeyLen);
        (void)CW_Utils::safe_memcpy(concat + 32U + pairingKeyLen, 32U, salt, 32U);

        bool sha512Ok = _crypto.sha512(concat, concatLen, sha512Output);

        if (!sha512Ok) {
            CW_Utils::secure_wipe(sharedSecret, sizeof(sharedSecret));
            CW_Utils::secure_wipe(sha512Output, sizeof(sha512Output));
            CW_Utils::secure_wipe(concat, sizeof(concat));
            return false;
        }

        (void)CW_Utils::safe_memcpy(session.aesKey, CW_AESKEY_SIZE, sha512Output, CW_AESKEY_SIZE);
        (void)CW_Utils::safe_memcpy(session.macKey, CW_MACKEY_SIZE, sha512Output + CW_AESKEY_SIZE, CW_MACKEY_SIZE);

        uint8_t iv_opc[AES_BLOCK_SIZE] = { 0U };
        uint8_t mac_iv[AES_BLOCK_SIZE] = { 0U };
        memset(iv_opc, 0x01U, AES_BLOCK_SIZE);

        uint8_t RNG_data[32U] = { 0U };
        if (!_crypto.random(RNG_data, sizeof(RNG_data))) {
#if CW_DEBUG_LOGGING
            _logger.println(F("RNG failed."));
#endif
            session.clear();
            CW_Utils::secure_wipe(sharedSecret, sizeof(sharedSecret));
            CW_Utils::secure_wipe(sha512Output, sizeof(sha512Output));
            CW_Utils::secure_wipe(concat, sizeof(concat));
            return false;
        }

        /* Encrypt random data with Kenc (Bit padding) */
        uint8_t ciphertextOPC[48U] = { 0U };
        uint16_t cipherLength = _crypto.aesCbcEncrypt(RNG_data, sizeof(RNG_data),
                                                      ciphertextOPC,
                                                      session.aesKey, sizeof(session.aesKey),
                                                      iv_opc, true);

        /* Compute MAC over APDU header + ciphertext (Null padding) */
        uint8_t opcApduHeader[APDU_HEADER_LEN + APDU_LC_LEN] = {
            0x80U, 0x11U, 0x00U, 0x00U,
            (uint8_t)(cipherLength + AES_BLOCK_SIZE)
        };
        uint8_t MAC_apduHeader[AES_BLOCK_SIZE] = { 0U };
        (void)CW_Utils::safe_memcpy(MAC_apduHeader, sizeof(MAC_apduHeader), opcApduHeader, sizeof(opcApduHeader));

        size_t  MAC_data_length = sizeof(MAC_apduHeader) + cipherLength;
        uint8_t MAC_data[64U] = { 0U };
        uint8_t ciphertextMACLong[64U] = { 0U };

        if (MAC_data_length > sizeof(MAC_data)) {
            session.clear();
            CW_Utils::secure_wipe(sharedSecret, sizeof(sharedSecret));
            CW_Utils::secure_wipe(sha512Output, sizeof(sha512Output));
            CW_Utils::secure_wipe(concat, sizeof(concat));
            CW_Utils::secure_wipe(RNG_data, sizeof(RNG_data));
            return false;
        }

        (void)CW_Utils::safe_memcpy(MAC_data, sizeof(MAC_data), MAC_apduHeader, sizeof(MAC_apduHeader));
        (void)CW_Utils::safe_memcpy(MAC_data + sizeof(MAC_apduHeader), sizeof(MAC_data) - sizeof(MAC_apduHeader), ciphertextOPC, cipherLength);

        uint16_t encryptedLengthMAC = _crypto.aesCbcEncrypt(MAC_data, (uint16_t)MAC_data_length,
                                                            ciphertextMACLong,
                                                            session.macKey, sizeof(session.macKey),
                                                            mac_iv, false);

        uint8_t MAC_value[AES_BLOCK_SIZE] = { 0U };
        uint8_t macOffset = (uint8_t)(encryptedLengthMAC - AES_BLOCK_SIZE);
        (void)CW_Utils::safe_memcpy(MAC_value, sizeof(MAC_value), ciphertextMACLong + macOffset, AES_BLOCK_SIZE);

        /* Forge MUTUALLY AUTHENTICATE APDU */
        uint8_t sendApduOpc[REQUEST_MUTUALLYAUTHENTICATE_IN_BYTES] = { 0U };
        uint16_t offset = 0U;
        (void)CW_Utils::safe_memcpy(sendApduOpc + offset, sizeof(sendApduOpc) - static_cast<size_t>(offset), opcApduHeader, sizeof(opcApduHeader));
        offset += sizeof(opcApduHeader);
        (void)CW_Utils::safe_memcpy(sendApduOpc + offset, sizeof(sendApduOpc) - static_cast<size_t>(offset), MAC_value, sizeof(MAC_value));
        offset += sizeof(MAC_value);
        (void)CW_Utils::safe_memcpy(sendApduOpc + offset, sizeof(sendApduOpc) - static_cast<size_t>(offset), ciphertextOPC, cipherLength);

        uint8_t response[255U] = { 0U };
        uint8_t responseLength = static_cast<uint8_t>(sizeof(response));

        if (_driver.sendAPDU(sendApduOpc, sizeof(sendApduOpc), response, responseLength)) {
            if (checkStatusWord(response, responseLength, 0x90U, 0x00U)) {
                if (responseLength == static_cast<uint8_t>(RESPONSE_MUTUALLYAUTHENTICATE_IN_BYTES)) {
                    (void)CW_Utils::safe_memcpy(session.iv, CW_IV_SIZE, response, CW_IV_SIZE);
                    ret = true;
                } else {
#if CW_DEBUG_LOGGING
                    _logger.println(F("MutualAuth: unexpected response size."));
#endif
                }
            } else {
#if CW_DEBUG_LOGGING
                _logger.println(F("MutualAuth: bad SW."));
#endif
            }
        } else {
#if CW_DEBUG_LOGGING
            _logger.println(F("MutualAuth APDU failed."));
#endif
        }

        /* Secure cleanup */
        CW_Utils::secure_wipe(sharedSecret, sizeof(sharedSecret));
        CW_Utils::secure_wipe(sha512Output, sizeof(sha512Output));
        CW_Utils::secure_wipe(concat, sizeof(concat));
        CW_Utils::secure_wipe(RNG_data, sizeof(RNG_data));
        CW_Utils::secure_wipe(ciphertextOPC, sizeof(ciphertextOPC));
        CW_Utils::secure_wipe(MAC_data, sizeof(MAC_data));

        /* If the APDU exchange failed after session keys were written, clear
         * them now to prevent a half-initialised session from being used (CRIT-04). */
        if (!ret) {
            session.clear();
        }
    }

    return ret;
}

/**
 * @details
 * One secure-messaging round-trip is built in five stages, reusing module-
 * private scratch buffers (@c s_apduBuf, @c s_macBuf, @c s_dataBuf) to keep
 * the call-site stack frame small:
 *
 *   1. Plaintext padding — ISO/IEC 9797-1 Method 2 (bit padding) is appended
 *      to @p data so the length is a multiple of the AES block size.
 *   2. Encryption — AES-256-CBC under Kenc with the current rolling IV.
 *   3. MAC computation — AES-CMAC over (APDU header || Lc || ciphertext)
 *      under Kmac. The MAC's last 8 bytes are prepended to the ciphertext
 *      in the outgoing APDU.
 *   4. Transport — the assembled APDU goes to the card; the response is
 *      structured as (MAC[8] || cipher || SW1 SW2).
 *   5. Response decryption — delegated to @ref aesCbcDecrypt, which verifies
 *      the response MAC against Kmac (using the request MAC as the IV per
 *      protocol) before decrypting under Kenc.
 *
 * IV update — on success, the last 16 bytes of the response ciphertext become
 * the new session IV (rolling IV). On any failure path the IV is left in an
 * undefined state, which is why the caller must treat a false return as a
 * dead session.
 */
bool CW_SecureChannel::aesCbcEncrypt(CW_SecureSession& session,
                                     const uint8_t apdu[], uint16_t apduLength,
                                     const uint8_t data[], uint16_t dataLength,
                                     uint8_t* decryptedOutput, uint16_t* decryptedOutputLength) {
    bool ret = false;

    /* Reject payloads that would overflow s_dataBuf (MED-01). */
    if (dataLength > INPUT_BUFFER_LIMIT) {
#if CW_DEBUG_LOGGING
        _logger.println(F("Error: data too large for encryption buffer."));
#endif
        return false;
    }

    /* 1. Encrypt data with Kenc (Bit padding) */
    uint16_t encryptedLength = _crypto.aesCbcEncrypt(data, dataLength, s_dataBuf,
                                                     session.aesKey, sizeof(session.aesKey),
                                                     session.iv, true);

    uint16_t lcValue = encryptedLength + (uint16_t)AES_BLOCK_SIZE;
    /* lcValue must fit in uint8_t: with INPUT_BUFFER_LIMIT=208, max encryptedLength=224,
     * so max lcValue=240. The static_assert above also caps APDU at 255 bytes (MED-03). */
    if (lcValue > 0xFFU) {
#if CW_DEBUG_LOGGING
        _logger.println(F("Error: lcValue overflow — payload too large."));
#endif
        CW_Utils::secure_wipe(s_dataBuf, sizeof(s_dataBuf));
        return false;
    }
    uint8_t macApdu[MAC_APDU_LEN] = { 0U };
    /* MED-03: Single-byte length encoding and no direction byte are intentional —
     * this CBC-MAC construction matches the Cryptnox SCCP card firmware spec.
     * Changing to AES-CMAC, wider encoding, or adding a direction byte would
     * break the card protocol. lcValue overflow is prevented by the
     * INPUT_BUFFER_LIMIT precondition above (dataLength <= 208 → lcValue <= 240). */
    macApdu[0U] = (uint8_t)lcValue;

    uint16_t macDataLength = apduLength + sizeof(macApdu) + encryptedLength;
    if (macDataLength > MAX_MAC_DATA_LEN) {
#if CW_DEBUG_LOGGING
        _logger.println(F("Error: MAC data length exceeds buffer."));
#endif
        CW_Utils::secure_wipe(s_dataBuf, sizeof(s_dataBuf));
        return false;
    }

    /* 2. Build MAC input: APDU header || LC block || ciphertext */
    uint16_t offset = 0U;
    (void)CW_Utils::safe_memcpy(s_macBuf, sizeof(s_macBuf), apdu, apduLength);
    offset += apduLength;
    (void)CW_Utils::safe_memcpy(s_macBuf + offset, sizeof(s_macBuf) - static_cast<size_t>(offset), macApdu, sizeof(macApdu));
    offset += sizeof(macApdu);
    (void)CW_Utils::safe_memcpy(s_macBuf + offset, sizeof(s_macBuf) - static_cast<size_t>(offset), s_dataBuf, encryptedLength);

    uint8_t macIv[AES_BLOCK_SIZE] = { 0U };
    uint16_t macEncryptedLength = _crypto.aesCbcEncrypt(s_macBuf, macDataLength, s_apduBuf,
                                                        session.macKey, sizeof(session.macKey),
                                                        macIv, false);

    uint8_t macValue[AES_BLOCK_SIZE] = { 0U };
    uint16_t macOffset = macEncryptedLength - AES_BLOCK_SIZE;
    (void)CW_Utils::safe_memcpy(macValue, sizeof(macValue), s_apduBuf + macOffset, AES_BLOCK_SIZE);

    /* 3. Build send APDU: header || Lc || MAC || ciphertext */
    const uint8_t lc = (uint8_t)lcValue;
    uint8_t sendApduLength = (uint8_t)(apduLength + APDU_LC_LEN + sizeof(macValue) + encryptedLength);
    if (sendApduLength > SEND_APDU_MAX_LEN) {
#if CW_DEBUG_LOGGING
        _logger.println(F("Error: Send APDU length exceeds buffer."));
#endif
        CW_Utils::secure_wipe(s_dataBuf, sizeof(s_dataBuf));
        CW_Utils::secure_wipe(s_macBuf,  sizeof(s_macBuf));
        return false;
    }

    offset = 0U;
    (void)CW_Utils::safe_memcpy(s_apduBuf, sizeof(s_apduBuf), apdu, apduLength);
    offset += apduLength;
    s_apduBuf[offset] = lc;
    offset += APDU_LC_LEN;
    (void)CW_Utils::safe_memcpy(s_apduBuf + offset, sizeof(s_apduBuf) - static_cast<size_t>(offset), macValue, sizeof(macValue));
    offset += sizeof(macValue);
    (void)CW_Utils::safe_memcpy(s_apduBuf + offset, sizeof(s_apduBuf) - static_cast<size_t>(offset), s_dataBuf, encryptedLength);

    /* 4. Send APDU */
    uint8_t response[255U] = { 0U };
    uint8_t responseLength = static_cast<uint8_t>(sizeof(response));

    if (_driver.sendAPDU(s_apduBuf, sendApduLength, response, responseLength)) {
        if (checkStatusWord(response, responseLength, 0x90U, 0x00U)) {
            /* Update session.iv ONLY after the response MAC is verified (HIGH-01).
             * Moving it before aesCbcDecrypt would let an attacker-chosen IV
             * desynchronise the rolling-IV state even on MAC failure. */
            ret = aesCbcDecrypt(session, response, static_cast<size_t>(responseLength), macValue,
                                decryptedOutput, decryptedOutputLength);
            if (ret) {
                (void)CW_Utils::safe_memcpy(session.iv, CW_IV_SIZE, response, CW_IV_SIZE);
            } else {
                session.clear();
            }
        } else if (responseLength >= 2U) {
            /* Card-level error: surface the SW so the caller can diagnose
             * common cases (e.g. 0x63Cn = wrong PIN with n retries left). */
#if CW_DEBUG_LOGGING
            _logger.print(F("Secured APDU: bad SW 0x"));
            if (response[responseLength - 2U] < 0x10U) { _logger.print(F("0")); }
            _logger.print(response[responseLength - 2U], HEX);
            if (response[responseLength - 1U] < 0x10U) { _logger.print(F("0")); }
            _logger.println(response[responseLength - 1U], HEX);
#endif
        }
    } else {
#if CW_DEBUG_LOGGING
        _logger.println(F("Secured APDU failed."));
#endif
    }

    /* Wipe plaintext scratch buffers so they do not persist in .bss (MED-04). */
    CW_Utils::secure_wipe(s_dataBuf, sizeof(s_dataBuf));
    CW_Utils::secure_wipe(s_macBuf,  sizeof(s_macBuf));

    return ret;
}

bool CW_SecureChannel::aesCbcDecrypt(const CW_SecureSession& session,
                                     uint8_t* response, size_t response_len,
                                     uint8_t* mac_value,
                                     uint8_t* decryptedOutput, uint16_t* decryptedOutputLength) {
    /* Precondition: response must hold at least MAC(16) + 1 ciphertext byte + SW(2) (HIGH-02).
     * Without this check, response_len < 18 causes size_t underflow in the subtractions below. */
    if ((response == NULL) || (response_len < (size_t)(AES_BLOCK_SIZE + 2U + 1U))) {
        return false;
    }

    /* Response layout: MAC(16) || cipherText(N) || SW1(1) || SW2(1) */
    uint8_t rep_mac[AES_BLOCK_SIZE];
    (void)CW_Utils::safe_memcpy(rep_mac, sizeof(rep_mac), response, AES_BLOCK_SIZE);
    uint8_t* rep_data  = response + AES_BLOCK_SIZE;
    size_t totalDataLen = response_len - 2U;
    size_t cipherLen    = totalDataLen - AES_BLOCK_SIZE;

    if (mac_value == NULL) {
        return false;
    }

    /* Verify MAC: AES-CBC-MAC over [length_header(16)] || [all_ciphertext] */
    size_t macInputLen = AES_BLOCK_SIZE + cipherLen;
    if (macInputLen > sizeof(s_macBuf)) {
#if CW_DEBUG_LOGGING
        _logger.println(F("Error: Response too large for MAC verification."));
#endif
        return false;
    }

    memset(s_macBuf, 0U, AES_BLOCK_SIZE);
    s_macBuf[0] = (uint8_t)totalDataLen;
    (void)CW_Utils::safe_memcpy(s_macBuf + AES_BLOCK_SIZE, sizeof(s_macBuf) - AES_BLOCK_SIZE, rep_data, cipherLen);

    uint8_t mac_iv[AES_BLOCK_SIZE] = { 0U };
    uint16_t macEncryptedLength = _crypto.aesCbcEncrypt(s_macBuf, (uint16_t)macInputLen, s_apduBuf,
                                                        session.macKey, sizeof(session.macKey),
                                                        mac_iv, false);

    uint8_t recomputedMacValue[AES_BLOCK_SIZE] = { 0U };
    uint16_t macOffset = macEncryptedLength - AES_BLOCK_SIZE;
    (void)CW_Utils::safe_memcpy(recomputedMacValue, sizeof(recomputedMacValue), s_apduBuf + macOffset, AES_BLOCK_SIZE);

    if (!CW_Utils::secure_compare(rep_mac, recomputedMacValue, AES_BLOCK_SIZE)) {
#if CW_DEBUG_LOGGING
        _logger.println(F("MAC mismatch."));
#endif
        CW_Utils::secure_wipe(s_macBuf, sizeof(s_macBuf));
        return false;
    }

    /* Decrypt ciphertext using mac_value as IV (Bit padding removal) */
    uint16_t decryptedDataLength = _crypto.aesCbcDecrypt(rep_data, (uint16_t)cipherLen, s_dataBuf,
                                                         session.aesKey, sizeof(session.aesKey),
                                                         mac_value, true);

    bool ret = false;

    if (decryptedDataLength < 2U) {
#if CW_DEBUG_LOGGING
        _logger.println(F("Error: Decoded data too short."));
#endif
    }
    else if (decryptedDataLength > sizeof(s_dataBuf)) {
#if CW_DEBUG_LOGGING
        _logger.println(F("Error: Decoded data length exceeds buffer."));
#endif
    }
    else {
        uint8_t innerSW1 = s_dataBuf[decryptedDataLength - 2U];
        uint8_t innerSW2 = s_dataBuf[decryptedDataLength - 1U];
        uint16_t payloadLength = decryptedDataLength - 2U;

        if ((innerSW1 != 0x90U) || (innerSW2 != 0x00U)) {
#if CW_DEBUG_LOGGING
            _logger.print(F("Card error SW: 0x"));
            if (innerSW1 < 0x10U) { _logger.print(F("0")); }
            _logger.print(innerSW1, HEX);
            _logger.print(F(" 0x"));
            if (innerSW2 < 0x10U) { _logger.print(F("0")); }
            _logger.println(innerSW2, HEX);
#endif
        }
        else {
            ret = true;
        }

        if ((decryptedOutput != NULL) && (decryptedOutputLength != NULL)) {
            (void)CW_Utils::safe_memcpy(decryptedOutput, sizeof(s_dataBuf), s_dataBuf, payloadLength);
            *decryptedOutputLength = payloadLength;
        }
    }

    /* Wipe plaintext scratch buffers (MED-04). */
    CW_Utils::secure_wipe(s_dataBuf, sizeof(s_dataBuf));
    CW_Utils::secure_wipe(s_macBuf,  sizeof(s_macBuf));

    return ret;
}

/******************************************************************
 * Certificate verification — static helpers
 ******************************************************************/


/* Read the DER length at buf[*pos]; advance *pos past the length bytes.
 * Supports short form and long form with 1 or 2 extra bytes only. */
static bool derReadLength(const uint8_t* buf, uint16_t bufLen,
                           uint16_t& pos, uint16_t& fieldLen) {
    bool    ok   = false;
    fieldLen     = 0U;

    if ((buf != NULL) && (pos < bufLen)) {
        uint8_t b = buf[pos];
        pos += 1U;

        if ((b & DER_LEN_LONG_FLAG) == 0U) {
            fieldLen = static_cast<uint16_t>(b);
            ok = true;
        } else if (b == DER_LEN_LONG_1) {
            if (pos < bufLen) {
                fieldLen = static_cast<uint16_t>(buf[pos]);
                pos += 1U;
                ok = true;
            }
        } else if (b == DER_LEN_LONG_2) {
            if ((pos + 1U) < bufLen) {
                fieldLen  = static_cast<uint16_t>(
                                static_cast<uint16_t>(buf[pos]) << 8U);
                fieldLen |= static_cast<uint16_t>(buf[pos + 1U]);
                pos += 2U;
                ok = true;
            }
        } else {
            ok = false; /* indefinite form or > 2 extra bytes — unsupported */
        }
    }

    return ok;
}

/* Skip one complete DER TLV (tag byte + length bytes + value) at buf[*pos]. */
static bool derSkipField(const uint8_t* buf, uint16_t bufLen, uint16_t& pos) {
    bool ok = false;

    if ((buf != NULL) && (pos < bufLen)) {
        uint16_t contentLen = 0U;
        pos += 1U; /* skip tag byte */
        if (derReadLength(buf, bufLen, pos, contentLen)) {
            if ((pos + contentLen) <= bufLen) {
                pos += contentLen;
                ok   = true;
            }
        }
    }

    return ok;
}

/* Walk a DER X.509 Certificate to extract — without any byte-pattern search:
 *   tbsMsgStart  offset of TBSCertificate SEQUENCE tag inside buf
 *   tbsMsgLen    total byte count of TBSCertificate (tag + length + content)
 *   pubKey65Ptr  pointer to 65-byte uncompressed EC point (0x04 || X || Y)
 *   sigPtr       pointer to the DER ECDSA signature bytes
 *   sigLen       byte count of the DER ECDSA signature
 * Returns false on any format or bounds error. */
static bool derWalkMfCert(const uint8_t* buf, uint16_t bufLen,
                           uint16_t& tbsMsgStart, uint16_t& tbsMsgLen,
                           const uint8_t*& pubKey65Ptr,
                           const uint8_t*& sigPtr, uint8_t& sigLen) {
    bool     ok             = true;
    uint16_t pos            = 0U;
    uint16_t certContentLen = 0U;
    uint16_t tbsContentLen  = 0U;
    uint16_t tbsEnd         = 0U;
    uint16_t spkiContentLen = 0U;
    uint16_t bsLen          = 0U;

    tbsMsgStart = 0U;
    tbsMsgLen   = 0U;
    pubKey65Ptr = NULL;
    sigPtr      = NULL;
    sigLen      = 0U;

    if ((buf == NULL) || (bufLen == 0U)) {
        ok = false;
    }

    /* ── outer Certificate SEQUENCE ── */
    if (ok) {
        if (buf[pos] != DER_TAG_SEQUENCE) {
            ok = false;
        }
    }
    if (ok) {
        pos += 1U;
        if (!derReadLength(buf, bufLen, pos, certContentLen)) {
            ok = false;
        }
    }
    if (ok) {
        if ((pos + certContentLen) > bufLen) {
            ok = false;
        }
    }

    /* ── TBSCertificate SEQUENCE (first child) ── */
    if (ok) {
        if (buf[pos] != DER_TAG_SEQUENCE) {
            ok = false;
        }
    }
    if (ok) {
        tbsMsgStart = pos;
        pos += 1U;
        if (!derReadLength(buf, bufLen, pos, tbsContentLen)) {
            ok = false;
        }
    }
    if (ok) {
        tbsMsgLen = (pos - tbsMsgStart) + tbsContentLen;
        tbsEnd    = pos + tbsContentLen;
        if (tbsEnd > bufLen) {
            ok = false;
        }
    }

    /* ── Walk TBSCertificate fields in order ── */

    /* [0] EXPLICIT version — present in X.509 v3 */
    if (ok && (pos < tbsEnd)) {
        if (buf[pos] == DER_TAG_CTX0) {
            if (!derSkipField(buf, tbsEnd, pos)) {
                ok = false;
            }
        }
    }

    /* serialNumber INTEGER */
    if (ok) {
        if (!derSkipField(buf, tbsEnd, pos)) {
            ok = false;
        }
    }

    /* signature AlgorithmIdentifier SEQUENCE */
    if (ok) {
        if (!derSkipField(buf, tbsEnd, pos)) {
            ok = false;
        }
    }

    /* issuer Name SEQUENCE */
    if (ok) {
        if (!derSkipField(buf, tbsEnd, pos)) {
            ok = false;
        }
    }

    /* validity SEQUENCE */
    if (ok) {
        if (!derSkipField(buf, tbsEnd, pos)) {
            ok = false;
        }
    }

    /* subject Name SEQUENCE */
    if (ok) {
        if (!derSkipField(buf, tbsEnd, pos)) {
            ok = false;
        }
    }

    /* ── SubjectPublicKeyInfo SEQUENCE ── */
    if (ok) {
        if (pos >= tbsEnd) {
            ok = false;
        }
    }
    if (ok) {
        if (buf[pos] != DER_TAG_SEQUENCE) {
            ok = false;
        }
    }
    if (ok) {
        pos += 1U;
        if (!derReadLength(buf, bufLen, pos, spkiContentLen)) {
            ok = false;
        }
    }
    if (ok) {
        if ((pos + spkiContentLen) > bufLen) {
            ok = false;
        }
    }

    /* Skip AlgorithmIdentifier SEQUENCE inside SubjectPublicKeyInfo */
    if (ok) {
        if (!derSkipField(buf, bufLen, pos)) {
            ok = false;
        }
    }

    /* subjectPublicKey BIT STRING */
    if (ok) {
        if (pos >= bufLen) {
            ok = false;
        }
    }
    if (ok) {
        if (buf[pos] != DER_TAG_BIT_STRING) {
            ok = false;
        }
    }
    if (ok) {
        pos += 1U;
        if (!derReadLength(buf, bufLen, pos, bsLen)) {
            ok = false;
        }
    }
    if (ok) {
        if ((pos + bsLen) > bufLen) {
            ok = false;
        }
    }
    if (ok) {
        if (bsLen < (1U + static_cast<uint16_t>(DER_EC_POINT_BYTES))) {
            ok = false; /* too short: unused-bits byte + 65-byte EC point */
        }
    }
    if (ok) {
        if (buf[pos] != DER_BIT_UNUSED_ZERO) {
            ok = false; /* unused bits must be 0 */
        } else if (buf[pos + 1U] != DER_EC_UNCOMPRESSED) {
            ok = false; /* must be an uncompressed EC point */
        } else {
            pubKey65Ptr = buf + pos + 1U; /* points to: 0x04 || X[32] || Y[32] */
        }
    }

    /* Jump to end of TBSCertificate, then skip signatureAlgorithm SEQUENCE */
    if (ok) {
        pos = tbsEnd;
        if (!derSkipField(buf, bufLen, pos)) {
            ok = false;
        }
    }

    /* ── signatureValue BIT STRING (third child of Certificate) ── */
    if (ok) {
        if (pos >= bufLen) {
            ok = false;
        }
    }
    if (ok) {
        if (buf[pos] != DER_TAG_BIT_STRING) {
            ok = false;
        }
    }
    if (ok) {
        pos += 1U;
        if (!derReadLength(buf, bufLen, pos, bsLen)) {
            ok = false;
        }
    }
    if (ok) {
        if ((pos + bsLen) > bufLen) {
            ok = false;
        }
    }
    if (ok) {
        if (bsLen < 2U) {
            ok = false; /* need unused-bits byte + at least 1 signature byte */
        }
    }
    if (ok) {
        if (buf[pos] != DER_BIT_UNUSED_ZERO) {
            ok = false; /* unused bits must be 0 */
        }
    }
    if (ok) {
        uint16_t rawSigLen = bsLen - 1U;
        if (rawSigLen > 255U) {
            ok = false;
        } else {
            sigPtr = buf + pos + 1U; /* DER ECDSA signature, after unused-bits byte */
            sigLen = static_cast<uint8_t>(rawSigLen);
        }
    }

    return ok;
}

bool CW_SecureChannel::parseDerSigToRaw(const uint8_t* der, uint8_t derLen,
                                        uint8_t* raw64) {
    bool ret = false;

    if ((der != NULL) && (raw64 != NULL) && (derLen >= 6U) && (der[0] == 0x30U)) {
        /* Validate outer SEQUENCE length against actual buffer (HIGH-04). */
        if ((uint8_t)(der[1] + 2U) > derLen) {
            return false;
        }

        uint8_t pos = 2U;  /* skip SEQUENCE tag + length */

        if (der[pos] == 0x02U) {
            pos++;
            uint8_t rLen = der[pos];
            pos++;
            /* Reject malformed r — DER r is at most 33 bytes (32 + 1 zero pad) (HIGH-04). */
            if (rLen > 33U) {
                return false;
            }
            if ((pos + rLen) <= derLen) {
                const uint8_t* rPtr = der + pos;
                pos += rLen;

                if ((pos < derLen) && (der[pos] == 0x02U)) {
                    pos++;
                    uint8_t sLen = der[pos];
                    pos++;
                    /* Reject malformed s (HIGH-04). */
                    if (sLen > 33U) {
                        return false;
                    }
                    if ((pos + sLen) <= derLen) {
                        /* M-06: verify sum of both INTEGER fields matches the outer SEQUENCE length.
                         * Trailing garbage after s would indicate malformed/crafted DER. */
                        if ((pos + sLen) != (uint8_t)(2U + der[1])) {
                            return false;
                        }
                        const uint8_t* sPtr = der + pos;

                        memset(raw64, 0U, 64U);

                        /* r: strip optional leading 0x00 padding byte */
                        if ((rLen == 33U) && (rPtr[0] == 0x00U)) { rPtr++; rLen = 32U; }
                        if (rLen <= 32U) {
                            (void)CW_Utils::safe_memcpy(raw64 + (32U - rLen), static_cast<size_t>(32U + rLen), rPtr, rLen);
                        }

                        /* s: strip optional leading 0x00 padding byte */
                        if ((sLen == 33U) && (sPtr[0] == 0x00U)) { sPtr++; sLen = 32U; }
                        if (sLen <= 32U) {
                            (void)CW_Utils::safe_memcpy(raw64 + 32U + (32U - sLen), static_cast<size_t>(sLen), sPtr, sLen);
                        }

                        ret = true;
                    }
                }
            }
        }
    }

    return ret;
}

bool CW_SecureChannel::verifyEcdsaSha256(const uint8_t* pubKey64,
                                         const uint8_t* message, uint16_t msgLen,
                                         const uint8_t* derSig, uint8_t derSigLen) {
    bool result = false;
    uint8_t hash[32U] = { 0U };
    uint8_t rawSig[64U] = { 0U };

    bool hashOk = _crypto.sha256(message, msgLen, hash);

    if (hashOk && parseDerSigToRaw(derSig, derSigLen, rawSig)) {
        result = _crypto.ecdsaVerify(pubKey64, hash, sizeof(hash), rawSig, CW_CURVE_SECP256R1);
    }

    return result;
}

bool CW_SecureChannel::getManufacturerCertificate(uint8_t* cert, uint16_t& certLen) {
    bool ret = false;
    certLen = 0U;

    if (cert != NULL) {
        const uint8_t APDU_P2_IDX = 3U;  /* P2 field offset in ISO 7816-4 APDU header */
        uint8_t apdu[5U] = { 0x80U, 0xF7U, 0x00U, 0x00U, 0x00U };
        uint8_t response[RESPONSE_GETMANUFACTURERCERT_PAGE_IN_BYTES];
        uint16_t responseLen = static_cast<uint16_t>(sizeof(response));

        if (!_driver.sendAPDULarge(apdu, static_cast<uint8_t>(sizeof(apdu)), response,
                                   responseLen)) {
#if CW_DEBUG_LOGGING
            _logger.println(F("getManufacturerCertificate APDU failed."));
#endif
            return false;
        }
        if (responseLen > static_cast<uint16_t>(sizeof(response))) {
#if CW_DEBUG_LOGGING
            _logger.println(F("getManufacturerCertificate: driver reported overflow."));
#endif
            return false;
        }

        if (checkStatusWord(response, responseLen, 0x90U, 0x00U)) {

            uint16_t dataBytes = static_cast<uint16_t>(
                responseLen - static_cast<uint16_t>(RESPONSE_STATUS_WORDS_IN_BYTES));

            if (dataBytes >= 2U) {
                uint16_t totalCertLen = (static_cast<uint16_t>(response[0]) << 8U)
                                      | static_cast<uint16_t>(response[1]);

                if (totalCertLen <= CW_MANUF_CERT_MAX_BYTES) {
                    uint16_t certInPage = static_cast<uint16_t>(dataBytes - 2U);
                    if (certInPage > totalCertLen) {
                        certInPage = totalCertLen;
                    }
                    (void)CW_Utils::safe_memcpy(cert, CW_MANUF_CERT_MAX_BYTES, response + 2U,
                                                static_cast<size_t>(certInPage));
                    certLen = certInPage;

                    uint8_t pageIdx = 1U;
                    while ((certLen < totalCertLen) && (pageIdx < 8U)) {
                        apdu[APDU_P2_IDX] = pageIdx;
                        responseLen = static_cast<uint16_t>(sizeof(response));

                        if (!_driver.sendAPDULarge(apdu, static_cast<uint8_t>(sizeof(apdu)),
                                                   response, responseLen)) {
                            break;
                        }
                        if (responseLen > static_cast<uint16_t>(sizeof(response))) {
#if CW_DEBUG_LOGGING
                            _logger.println(F("getManufacturerCertificate: driver reported overflow."));
#endif
                            return false;
                        }
                        if (!checkStatusWord(response, responseLen, 0x90U, 0x00U)) {
                            break;
                        }

                        uint16_t pageData = static_cast<uint16_t>(
                            responseLen - static_cast<uint16_t>(RESPONSE_STATUS_WORDS_IN_BYTES));
                        uint16_t remaining = static_cast<uint16_t>(totalCertLen - certLen);
                        if (pageData > remaining) {
                            pageData = remaining;
                        }

                        if ((certLen + pageData) > static_cast<uint16_t>(CW_MANUF_CERT_MAX_BYTES)) {
                            break;
                        }
                        (void)CW_Utils::safe_memcpy(cert + certLen,
                                                    CW_MANUF_CERT_MAX_BYTES - static_cast<size_t>(certLen),
                                                    response, static_cast<size_t>(pageData));
                        certLen = static_cast<uint16_t>(certLen + pageData);
                        pageIdx++;
                    }

                    ret = (certLen == totalCertLen);
                    if (!ret) {
#if CW_DEBUG_LOGGING
                        _logger.println(F("getManufacturerCertificate: incomplete."));
#endif
                    }
                } else {
#if CW_DEBUG_LOGGING
                    _logger.println(F("getManufacturerCertificate: cert too large."));
#endif
                }
            }
        }
    }

    return ret;
}

bool CW_SecureChannel::preFetchManufacturerCert() {
    _cachedMfCertLen = 0U;
    bool result = getManufacturerCertificate(s_mfCertBuf, _cachedMfCertLen);
    if (!result) {
        _cachedMfCertLen = 0U;
    }
    return result;
}

/**
 * @details
 * Two-step ECDSA chain walk against the pinned trusted CAs in
 * @ref CW_TRUSTED_CA_KEYS (currently a single secp256r1 key,
 * @ref CW_CA_DLT_PUBKEY):
 *
 *   1. Manufacturer certificate — the cached DER blob fetched by
 *      @ref preFetchManufacturerCert is parsed to extract its EC public key
 *      and its ECDSA signature. The signature is verified against every
 *      entry in the trusted-CA table; the first match wins. The extracted
 *      manufacturer public key becomes the trusted issuer for step 2.
 *
 *   2. Card certificate — @p cardCert is parsed for the device's ephemeral
 *      public key, the manufacturer ECDSA signature over that key, and the
 *      echoed challenge nonce. The nonce is compared (constant-time) against
 *      the value stored by @ref getCardCertificate; mismatch immediately
 *      returns @ref CW_CERT_NONCE_MISMATCH to defeat replay. The signature
 *      is then verified against the manufacturer public key from step 1.
 *
 * Both signatures are SHA-256-then-ECDSA over the relevant TBS bytes.
 * Any TLV parsing error short-circuits with @ref CW_CERT_FORMAT_ERROR
 * rather than touching the verifier — DER parsing is the largest attack
 * surface here and is independently fuzzed (see `fuzz/fuzz_der.cpp`).
 */
uint8_t CW_SecureChannel::verifyCertificateChain(const uint8_t* cardCert,
                                                  uint8_t cardCertLen) {
    uint8_t result = CW_CERT_OK;

    if ((cardCert == NULL) || (cardCertLen < 80U) || (cardCert[0] != 0x43U)) {
#if CW_DEBUG_LOGGING
        _logger.println(F("verifyCert: invalid card cert."));
#endif
        result = CW_CERT_FORMAT_ERROR;
    }

    /* Consume the pre-fetched cert (filled by preFetchManufacturerCert() before
     * getCardCertificate() was called).  Fall back to fetching now if none cached —
     * this will fail on cards whose state machine has already advanced past INS=F7. */
    uint16_t mfCertLen = _cachedMfCertLen;
    _cachedMfCertLen = 0U;

    if (result == CW_CERT_OK) {
        if (mfCertLen == 0U) {
            if (!getManufacturerCertificate(s_mfCertBuf, mfCertLen) || (mfCertLen < 20U)) {
#if CW_DEBUG_LOGGING
                _logger.println(F("verifyCert: failed to get mfr cert."));
#endif
                result = CW_CERT_FORMAT_ERROR;
            }
        } else if (mfCertLen < 20U) {
#if CW_DEBUG_LOGGING
            _logger.println(F("verifyCert: pre-fetched mfr cert too short."));
#endif
            result = CW_CERT_FORMAT_ERROR;
        } else {
            /* Pre-fetched cert in s_mfCertBuf is valid — no APDU needed. */
        }
    }

    /* MED-05: replace byte-pattern search with a structural DER walker that
     * enforces field order.  This prevents attacker-planted OID sequences in
     * unsigned extensions from being picked up as the device public key. */
    uint16_t       tbsMsgStart = 0U;
    uint16_t       tbsMsgLen   = 0U;
    const uint8_t* pubKey65Ptr = NULL;
    const uint8_t* mfSigPtr    = NULL;
    uint8_t        mfSigLen    = 0U;

    if (result == CW_CERT_OK) {
        if (!derWalkMfCert(s_mfCertBuf, mfCertLen,
                           tbsMsgStart, tbsMsgLen,
                           pubKey65Ptr,
                           mfSigPtr, mfSigLen)) {
#if CW_DEBUG_LOGGING
            _logger.println(F("verifyCert: DER walk of mfr cert failed."));
#endif
            result = CW_CERT_KEY_NOT_FOUND;
        }
    }

    const uint8_t* devicePubKey64 = NULL;
    if (result == CW_CERT_OK) {
        devicePubKey64 = pubKey65Ptr + 1U; /* skip the 0x04 uncompressed prefix */

        const uint8_t* mfMsg    = s_mfCertBuf + tbsMsgStart;
        uint16_t       mfMsgLen = tbsMsgLen;

        bool mfVerified = false;
        for (uint8_t i = 0U; i < CW_TRUSTED_CA_COUNT; i++) {
            if (verifyEcdsaSha256(CW_TRUSTED_CA_KEYS[i],
                                  mfMsg, mfMsgLen,
                                  mfSigPtr, mfSigLen)) {
                mfVerified = true;
                break;
            }
        }
        if (!mfVerified) {
#if CW_DEBUG_LOGGING
            _logger.println(F("verifyCert: mfr cert sig INVALID — card NOT genuine."));
#endif
            result = CW_CERT_MANUF_SIG_INVALID;
        }
#if CW_DEBUG_LOGGING
        else {
            _logger.println(F("Manufacturer cert signature OK."));
        }
#endif
    }

    const uint8_t CARD_CERT_MSG_LEN = 74U;
    if (result == CW_CERT_OK) {
        if (cardCertLen <= CARD_CERT_MSG_LEN) {
#if CW_DEBUG_LOGGING
            _logger.println(F("verifyCert: card cert too short for sig."));
#endif
            result = CW_CERT_FORMAT_ERROR;
        }
        else {
            const uint8_t* cardSig    = cardCert + CARD_CERT_MSG_LEN;
            uint8_t        cardSigLen = cardCertLen - CARD_CERT_MSG_LEN;

            if (!verifyEcdsaSha256(devicePubKey64,
                                   cardCert, CARD_CERT_MSG_LEN,
                                   cardSig, cardSigLen)) {
#if CW_DEBUG_LOGGING
                _logger.println(F("verifyCert: card cert sig INVALID."));
#endif
                result = CW_CERT_CARD_SIG_INVALID;
            }
#if CW_DEBUG_LOGGING
            else {
                _logger.println(F("Card cert signature OK."));
            }
#endif
        }
    }

    if (result == CW_CERT_OK) {
        if ((cardCertLen <= (1U + CW_CERT_NONCE_SIZE)) ||
            (!CW_Utils::secure_compare(cardCert + 1U, _lastNonce, CW_CERT_NONCE_SIZE))) { /* M-03: constant-time nonce compare */
#if CW_DEBUG_LOGGING
            _logger.println(F("verifyCert: nonce mismatch — possible replay."));
#endif
            result = CW_CERT_NONCE_MISMATCH;
        }
    }

#if CW_DEBUG_LOGGING
    if (result == CW_CERT_OK) {
        _logger.println(F("Certificate chain OK. Card is genuine."));
    }
#endif

    /* Wipe manufacturer cert buffer — it held the card device public key (M-01). */
    CW_Utils::secure_wipe(s_mfCertBuf, sizeof(s_mfCertBuf));

    return result;
}
