/*
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Cryptnox SA
 */

/**
 * @file CryptnoxWallet.cpp
 * @brief Implementation of the high-level CryptnoxWallet API.
 *
 * Coordinates the secure channel layer (@ref CW_SecureChannel) with the
 * higher-level wallet operations declared in @ref CryptnoxWallet.h. Handles
 * connection retries, sensitive buffer wiping on every exit path, PIN/sign
 * payload assembly, and DER signature parsing.
 */

/* NOTE: Do NOT include <Arduino.h> here — this is a platform-independent file.
 * Arduino compatibility shims (F(), HEX, delay) are provided via
 * platform_compat.h which is pulled in transitively through CryptnoxWallet.h. */
#include "CryptnoxWallet.h"
#include "CW_Utils.h"

/******************************************************************
 * Constructor
 ******************************************************************/

// cppcheck-suppress misra-c2012-12.3 -- C++: member initializer-list commas are not the comma operator
CryptnoxWallet::CryptnoxWallet(CW_NfcTransport& driver, CW_Logger& logger,
                               CW_CryptoProvider& crypto, CW_Platform& platform)
    : _logger(logger), _platform(platform), _secure(driver, logger, crypto, platform) {
}

/******************************************************************
 * Public methods
 ******************************************************************/

bool CryptnoxWallet::begin() {
    bool ret = _secure.begin();
    if (ret) {
        printPN532FirmwareVersion();
    }
    return ret;
}

bool CryptnoxWallet::connect(CW_SecureSession& session) {
    bool ret = false;
    session.clear(); /* CRIT-04: clear any stale keys from a previous or partial session */

    for (uint8_t attempt = 0U; (attempt < CW_CONNECT_MAX_ATTEMPTS) && (ret == false); attempt++) {
        if (attempt > 0U) {
            session.clear(); /* CRIT-04: clear partial keys left by a failed attempt before retrying */
#if CW_DEBUG_LOGGING
            _logger.print(F("Retrying card connection (attempt "));
            _logger.print((uint8_t)(attempt + 1U));
            _logger.println(F(")..."));
#endif
            _secure.resetReader();
            _platform.sleep_ms(200U);
        }

        if (_secure.inListPassiveTarget()) {
            _platform.sleep_ms(200U);
            if (establishSecureChannel(session)) {
                ret = true;
            }
        }
    }

    if (!ret) {
        session.clear(); /* CRIT-04: clear any partial keys from the final failed attempt */
    }

    return ret;
}

bool CryptnoxWallet::establishSecureChannel(CW_SecureSession& session) {
    bool ret = false;

    /* Declare all sensitive stack buffers at function entry so they can be
     * wiped on every exit path (H-01, M-02). */
    uint8_t cardCertificate[146U]      = { 0U };
    uint8_t cardCertificateLength      = 0U;
    uint8_t cardEphemeralPubKey[64U]   = { 0U };
    uint8_t openSecureChannelSalt[32U] = { 0U };
    uint8_t clientPrivateKey[32U]      = { 0U };
    uint8_t clientPublicKey[64U]       = { 0U };
    CW_Curve sessionCurve              = CW_CURVE_SECP256R1;

    if (_secure.selectApdu()) {
        /* Fetch the manufacturer certificate BEFORE getCardCertificate().
         * The Cryptnox card state machine advances after GET_CARD_CERTIFICATE
         * (INS=F8) and will not respond to GET_MANUFACTURER_CERTIFICATE (INS=F7)
         * after that point.  Pre-fetching here caches the cert inside
         * CW_SecureChannel so that verifyCertificateChain() can use it without
         * issuing another APDU. */
        if (!_secure.preFetchManufacturerCert()) {
#if CW_DEBUG_LOGGING
            _logger.println(F("Failed to pre-fetch manufacturer certificate"));
#endif
        } else {
            if (_secure.getCardCertificate(cardCertificate, cardCertificateLength)) {
                uint8_t certResult = _secure.verifyCertificateChain(cardCertificate,
                                                                    cardCertificateLength);
                if (certResult != CW_CERT_OK) {
#if CW_DEBUG_LOGGING
                    _logger.print(F("Card authenticity check failed (code 0x"));
                    _logger.print(certResult, HEX);
                    _logger.println(F("). Aborting."));
#endif
                } else {
                    if (_secure.extractCardEphemeralKey(cardCertificate, cardEphemeralPubKey)) {
                        if (_secure.openSecureChannel(openSecureChannelSalt, clientPublicKey,
                                                      clientPrivateKey, sessionCurve)) {
                            if (_secure.mutuallyAuthenticate(session, openSecureChannelSalt,
                                                            clientPublicKey, clientPrivateKey,
                                                            sessionCurve, cardEphemeralPubKey)) {
#if CW_DEBUG_LOGGING
                                _logger.println(F("Secure channel established"));
#endif
                                ret = true;
                            } else {
#if CW_DEBUG_LOGGING
                                _logger.println(F("Mutual authentication failed"));
#endif
                            }
                        } else {
#if CW_DEBUG_LOGGING
                            _logger.println(F("Failed to open secure channel"));
#endif
                        }
                    } else {
#if CW_DEBUG_LOGGING
                        _logger.println(F("Failed to extract card ephemeral key"));
#endif
                    }
                }
            } else {
#if CW_DEBUG_LOGGING
                _logger.println(F("Failed to get card certificate"));
#endif
            }
        } /* end preFetchManufacturerCert else */
    } else {
#if CW_DEBUG_LOGGING
        _logger.println(F("Failed to select Cryptnox application"));
#endif
    }

    /* Wipe all sensitive ephemeral key material on every exit path (H-01, M-02). */
    CW_Utils::secure_wipe(clientPrivateKey,      sizeof(clientPrivateKey));
    CW_Utils::secure_wipe(openSecureChannelSalt, sizeof(openSecureChannelSalt));
    CW_Utils::secure_wipe(clientPublicKey,       sizeof(clientPublicKey));
    CW_Utils::secure_wipe(cardEphemeralPubKey,   sizeof(cardEphemeralPubKey));
    CW_Utils::secure_wipe(cardCertificate,       sizeof(cardCertificate));

    return ret;
}

void CryptnoxWallet::disconnect(CW_SecureSession& session) {
    if (isSecureChannelOpen(session)) {
        session.clear();
    }
    _secure.resetReader();
}

bool CryptnoxWallet::getCardInfo(CW_SecureSession& session, CW_CardInfo* info) {
    bool ret = false;
    if (!isSecureChannelOpen(session)) {
#if CW_DEBUG_LOGGING
        _logger.println(F("Error: Secure channel not open. Cannot get card info."));
#endif
        return false;
    }
    uint8_t data[] = { 0x00U };
    uint8_t apdu[] = { 0x80U, 0xFAU, 0x00U, 0x00U };

    uint8_t  decrypted[255U] = { 0U };
    uint16_t decryptedLen    = 0U;

    ret = _secure.aesCbcEncrypt(session, apdu, sizeof(apdu),
                                data, sizeof(data),
                                decrypted, &decryptedLen);

    if (ret && (info != NULL)) {
        /* Response layout (Cryptnox basic_g1 spec):
         *   [byte0] [name_len(1)] [name(name_len)]
         *           [email_len(1)] [email(email_len)] [... more fields ...]
         * byte0 = unused/flags. */
        ret = false;
        if (decryptedLen >= 4U) {
            uint16_t pos     = 1U;
            uint8_t  nameLen = decrypted[pos];
            pos += 1U;
            if ((nameLen <= CW_CARD_NAME_MAX_LEN) &&
                ((uint16_t)(pos + nameLen + 1U) <= decryptedLen)) {
                (void)CW_Utils::safe_memcpy(reinterpret_cast<uint8_t*>(info->name),
                                            sizeof(info->name),
                                            decrypted + pos, nameLen);
                info->name[nameLen] = '\0';
                pos += nameLen;

                uint8_t emailLen = decrypted[pos];
                pos += 1U;
                if ((emailLen <= CW_CARD_EMAIL_MAX_LEN) &&
                    ((uint16_t)(pos + emailLen) <= decryptedLen)) {
                    (void)CW_Utils::safe_memcpy(reinterpret_cast<uint8_t*>(info->email),
                                                sizeof(info->email),
                                                decrypted + pos, emailLen);
                    info->email[emailLen] = '\0';
                    ret = true;
                }
            }
        }
    }

    CW_Utils::secure_wipe(decrypted, sizeof(decrypted));
    return ret;
}

bool CryptnoxWallet::verifyPin(CW_SecureSession& session, const uint8_t* pin, uint8_t pinLength) {
    bool ret = false;
    if (!isSecureChannelOpen(session)) {
#if CW_DEBUG_LOGGING
        _logger.println(F("Error: Secure channel not open. Cannot verify PIN."));
#endif
    }
    else if ((pin == NULL) || (pinLength < CW_MIN_PIN_LENGTH) || (pinLength > CW_MAX_PIN_LENGTH)) {
#if CW_DEBUG_LOGGING
        _logger.println(F("Error: Invalid PIN (must be 4-9 digits)."));
#endif
    }
    else {
        uint8_t paddedPin[CW_MAX_PIN_LENGTH] = { 0U };
        (void)CW_Utils::safe_memcpy(paddedPin, sizeof(paddedPin), pin, pinLength);
        uint8_t apdu[] = { 0x80U, 0x20U, 0x00U, 0x00U };
        ret = _secure.aesCbcEncrypt(session, apdu, sizeof(apdu), paddedPin, CW_MAX_PIN_LENGTH);
        CW_Utils::secure_wipe(paddedPin, sizeof(paddedPin));
    }
    return ret;
}

bool CryptnoxWallet::writeUserData(CW_SecureSession& session, uint8_t slot,
                                    const uint8_t* data, uint16_t dataLength) {
    bool ret = false;

    if (!isSecureChannelOpen(session)) {
#if CW_DEBUG_LOGGING
        _logger.println(F("Error: Secure channel not open. Cannot write user data."));
#endif
    }
    else if ((data == NULL) || (dataLength == 0U)) {
#if CW_DEBUG_LOGGING
        _logger.println(F("Error: Invalid data for write user data."));
#endif
    }
    else {
        uint16_t offset = 0U;
        uint8_t  page   = 0U;
        ret = true;

        while ((offset < dataLength) && ret) {
            uint16_t chunkSize = dataLength - offset;
            if (chunkSize > CW_USER_DATA_PAGE_SIZE) {
                chunkSize = CW_USER_DATA_PAGE_SIZE;
            }

            uint8_t apdu[] = { 0x80U, 0xFCU, slot, page };

#if CW_DEBUG_LOGGING
            _logger.print(F("Writing user data page "));
            _logger.print(page);
            _logger.print(F(" ("));
            _logger.print(chunkSize);
            _logger.println(F(" bytes)..."));
#endif

            if (!_secure.aesCbcEncrypt(session, apdu, sizeof(apdu), data + offset, chunkSize)) {
#if CW_DEBUG_LOGGING
                _logger.print(F("Error: Write user data failed on page "));
                _logger.println(page);
#endif
                ret = false;
            }
            else {
                offset += chunkSize;
                page++;
            }
        }
    }

    return ret;
}

CW_SignResult CryptnoxWallet::sign(CW_SignRequest& request) {
    CW_SignResult result;

    if (validateSignRequest(request, result)) {
        uint8_t data[CW_HASH_SIZE + CW_MAX_DERIVE_PATH_LENGTH + CW_MAX_PIN_LENGTH] = { 0U };
        uint16_t dataLength = 0U;

        buildSignPayload(request, data, dataLength);

        uint8_t derResponse[255U] = { 0U };
        uint16_t derLength = 0U;

        if (sendSignApdu(request, data, dataLength, derResponse, derLength, result)) {
            if (extractRawSignature(derResponse, derLength, result)) {
                debugPrintSignature(result.signature);
                result.errorCode = CW_OK;
            }
        }
        CW_Utils::secure_wipe(data, sizeof(data));
        CW_Utils::secure_wipe(derResponse, sizeof(derResponse));
    }

    return result;
}

/******************************************************************
 * Static public methods
 ******************************************************************/

bool CryptnoxWallet::parseDerSignature(const uint8_t* der, uint8_t derLength,
                                        uint8_t* r, uint8_t& rLength,
                                        uint8_t* s, uint8_t& sLength) {
    bool ret = false;

    if ((der == NULL) || (derLength < 6U) || (r == NULL) || (s == NULL)) {
    }
    else if (der[0] != CW_DER_TAG_SEQUENCE) {
    }
    else {
        uint8_t pos = 2U;

        if (der[pos] != CW_DER_TAG_INTEGER) {
        }
        else {
            pos++;
            rLength = der[pos];
            pos++;
            if ((rLength > 33U) || ((pos + rLength) > derLength)) {
            }
            else {
                (void)CW_Utils::safe_memcpy(r, 33U, der + pos, rLength);
                pos += rLength;

                if ((pos >= derLength) || (der[pos] != CW_DER_TAG_INTEGER)) {
                }
                else {
                    pos++;
                    sLength = der[pos];
                    pos++;
                    if ((sLength > 33U) || ((pos + sLength) > derLength)) {
                    }
                    else {
                        (void)CW_Utils::safe_memcpy(s, 33U, der + pos, sLength);
                        ret = true;
                    }
                }
            }
        }
    }

    return ret;
}

/******************************************************************
 * Private methods
 ******************************************************************/

bool CryptnoxWallet::isSecureChannelOpen(const CW_SecureSession& session) const {
    uint8_t acc = 0U;
    for (uint8_t i = 0U; i < CW_AESKEY_SIZE; i++) {
        acc |= session.aesKey[i];
    }
    return (acc != 0U);
}

bool CryptnoxWallet::printPN532FirmwareVersion() {
    return _secure.printFirmwareVersion();
}

bool CryptnoxWallet::validateSignRequest(const CW_SignRequest& request, CW_SignResult& result) {
    bool ret = false;

    if (!isSecureChannelOpen(request.session)) {
#if CW_DEBUG_LOGGING
        _logger.println(F("Error: Secure channel not open. Cannot sign."));
#endif
        result.errorCode = CW_INVALID_SESSION;
    }
    else if ((request.hash == NULL) || (request.hashLength == 0U)) {
#if CW_DEBUG_LOGGING
        _logger.println(F("Error: Invalid parameters for sign."));
#endif
        result.errorCode = CW_SIGN_KEY_TOO_SHORT;
    }
    else if (request.hashLength > CW_HASH_SIZE) {
#if CW_DEBUG_LOGGING
        _logger.println(F("Error: Hash too large."));
#endif
        result.errorCode = CW_SIGN_KEY_TOO_SHORT;
    }
    else if ((request.pinLessMode) && (request.keyType != CW_SIGN_PINLESS_K1)) {
#if CW_DEBUG_LOGGING
        _logger.println(F("Error: PIN-less mode requires CW_SIGN_PINLESS_K1 key type."));
#endif
        result.errorCode = CW_SIGN_KEY_TOO_SHORT_WITH_PINLESS_MODE;
    }
    else {
        ret = true;

        if (!request.pinLessMode) {
            uint8_t pinLength = 0U;
            for (uint8_t i = 0U; i < CW_MAX_PIN_LENGTH; i++) {
                if (request.pin[i] == 0U) { break; }
                pinLength++;
            }
            if ((pinLength > 0U) && (pinLength < CW_MIN_PIN_LENGTH)) {
#if CW_DEBUG_LOGGING
                _logger.println(F("Error: PIN too short (must be 4-9 digits)."));
#endif
                result.errorCode = CW_SIGN_PIN_INCORRECT;
                ret = false;
            }
        }
    }

    return ret;
}

void CryptnoxWallet::buildSignPayload(const CW_SignRequest& request,
                                       uint8_t* data, uint16_t& dataLength) {
    const size_t kDataBufSize = static_cast<size_t>(CW_HASH_SIZE) + static_cast<size_t>(CW_MAX_DERIVE_PATH_LENGTH) + static_cast<size_t>(CW_MAX_PIN_LENGTH);
    dataLength = request.hashLength;
    (void)CW_Utils::safe_memcpy(data, kDataBufSize, request.hash, request.hashLength);

    if ((request.keyType == CW_SIGN_DERIVE_K1 || request.keyType == CW_SIGN_DERIVE_R1) &&
        (request.derivePath != NULL) && (request.derivePathLength > 0U)) {
        (void)CW_Utils::safe_memcpy(data + dataLength, kDataBufSize - static_cast<size_t>(dataLength), request.derivePath, request.derivePathLength);
        dataLength += request.derivePathLength;
    }

    if (!request.pinLessMode) {
        uint8_t pinLength = 0U;
        for (uint8_t i = 0U; i < CW_MAX_PIN_LENGTH; i++) {
            if (request.pin[i] == 0U) { break; }
            pinLength++;
        }
        if (pinLength > 0U) {
            (void)CW_Utils::safe_memcpy(data + dataLength, kDataBufSize - static_cast<size_t>(dataLength), request.pin, CW_MAX_PIN_LENGTH);
            dataLength += CW_MAX_PIN_LENGTH;
        }
    }
}

bool CryptnoxWallet::sendSignApdu(CW_SignRequest& request, const uint8_t* data,
                                   uint16_t dataLength, uint8_t* derResponse,
                                   uint16_t& derLength, CW_SignResult& result) {
    bool ret = false;
    uint8_t apdu[] = { 0x80U, 0xC0U, request.keyType, request.signatureType };

#if CW_DEBUG_LOGGING
    _logger.println(F("Sending SIGN APDU..."));
#endif

    if (_secure.aesCbcEncrypt(request.session, apdu, sizeof(apdu), data, dataLength,
                               derResponse, &derLength)) {
        ret = true;
    }
    else {
#if CW_DEBUG_LOGGING
        _logger.println(F("Sign APDU failed."));
#endif
        result.errorCode = CW_SIGN_NO_KEY_LOADED;
    }

    return ret;
}

bool CryptnoxWallet::extractRawSignature(const uint8_t* derResponse, uint16_t derLength,
                                          CW_SignResult& result) {
    bool ret = false;

    if ((derLength < 2U) || (derResponse[0] != CW_DER_TAG_SEQUENCE)) {
#if CW_DEBUG_LOGGING
        _logger.println(F("Error: Invalid signature data (missing DER SEQUENCE tag)."));
#endif
        result.errorCode = CW_NOK;
    }
    else {
        uint8_t derContentLength = derResponse[1];
        uint8_t derTotalLength   = 2U + derContentLength;

        if (derTotalLength > derLength) {
#if CW_DEBUG_LOGGING
            _logger.println(F("Error: DER signature length exceeds response."));
#endif
            result.errorCode = CW_NOK;
        }
        else {
            uint8_t r[33U] = { 0U };
            uint8_t s[33U] = { 0U };
            uint8_t rLen = 0U;
            uint8_t sLen = 0U;

            if (!parseDerSignature(derResponse, derTotalLength, r, rLen, s, sLen)) {
#if CW_DEBUG_LOGGING
                _logger.println(F("Error: Failed to parse DER signature."));
#endif
                result.errorCode = CW_NOK;
            }
            else {
                memset(result.signature, 0U, CW_RAW_SIGNATURE_SIZE);

                if (rLen > 0U) {
                    uint8_t rSrc = 0U;
                    uint8_t rDstLen = 32U;
                    if ((rLen == 33U) && (r[0] == 0x00U)) { rSrc = 1U; rLen = 32U; }
                    if (rLen <= rDstLen) {
                        (void)CW_Utils::safe_memcpy(result.signature + (rDstLen - rLen), static_cast<size_t>(rDstLen + rLen), r + rSrc, rLen);
                    }
                }

                if (sLen > 0U) {
                    uint8_t sSrc = 0U;
                    uint8_t sDstLen = 32U;
                    if ((sLen == 33U) && (s[0] == 0x00U)) { sSrc = 1U; sLen = 32U; }
                    if (sLen <= sDstLen) {
                        (void)CW_Utils::safe_memcpy(result.signature + 32U + (sDstLen - sLen), static_cast<size_t>(sLen), s + sSrc, sLen);
                    }
                }

                ret = true;
            }
            CW_Utils::secure_wipe(r, sizeof(r));
            CW_Utils::secure_wipe(s, sizeof(s));
        }
    }

    return ret;
}

void CryptnoxWallet::debugPrintSignature(const uint8_t* signature) {
#if CW_DEBUG_LOGGING
    _logger.print(F("Signature ("));
    _logger.print((uint8_t)CW_RAW_SIGNATURE_SIZE);
    _logger.println(F(" bytes):"));
    for (uint8_t i = 0U; i < CW_RAW_SIGNATURE_SIZE; i++) {
        _logger.print(F("0x"));
        if (signature[i] < 0x10U) { _logger.print(F("0")); }
        _logger.print(signature[i], HEX);
        _logger.print(F(" "));
        if (((i + 1U) % 16U == 0U) && ((i + 1U) != CW_RAW_SIGNATURE_SIZE)) { _logger.println(); }
    }
    _logger.println();
#else
    (void)signature;
#endif
}
