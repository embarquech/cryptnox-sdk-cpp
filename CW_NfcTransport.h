/*
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Cryptnox SA
 */

/**
 * @file CW_NfcTransport.h
 * @brief Abstract NFC transport interface.
 *
 * Declares @ref CW_NfcTransport, the contract that any concrete NFC reader
 * driver (PN532, PN7150, PC/SC, …) must implement so that
 * @ref CW_SecureChannel and @ref CryptnoxWallet remain hardware-agnostic.
 *
 * One of the three adapter interfaces a host integration must provide.
 */

#ifndef CW_NFCTRANSPORT_H
#define CW_NFCTRANSPORT_H

/******************************************************************
 * 1. Included files
 ******************************************************************/

#include "platform_compat.h"
#include <stdint.h>

/******************************************************************
 * 2. Class declaration
 ******************************************************************/

/**
 * @class CW_NfcTransport
 * @ingroup adapters
 * @brief Abstract interface for NFC transport operations.
 *
 * Defines the hardware-agnostic contract for NFC communication so
 * that CW_SecureChannel and CryptnoxWallet remain independent of
 * the physical NFC module (PN532, PN7150, etc.).
 */
class CW_NfcTransport {
public:
    /**
     * @brief Initialize the NFC transport hardware.
     * @return true if initialization succeeded, false otherwise.
     */
    virtual bool begin() = 0;

    /**
     * @brief Detect the presence of a passive ISO-DEP NFC target.
     * @return true if a card is detected, false otherwise.
     */
    virtual bool inListPassiveTarget() = 0;

    /**
     * @brief Send an APDU command to the card and receive the response.
     *
     * @param[in]  apdu         APDU command bytes.
     * @param[in]  apduLen      Length of the APDU command.
     * @param[out] response     Buffer to receive the card response.
     * @param[out] responseLen  Actual number of bytes written to @p response.
     * @return true if the exchange succeeded, false otherwise.
     */
    virtual bool sendAPDU(const uint8_t* apdu, uint8_t apduLen,
                          uint8_t* response, uint8_t& responseLen) = 0;

    /**
     * @brief Send an APDU and receive a response that may exceed 255 bytes.
     *
     * Used for APDUs whose DataOut can be larger than a uint8_t can express
     * (e.g. GET_MANUFACTURER_CERTIFICATE returns up to 415 bytes).
     * Implementations that cannot deliver more than 255 bytes may delegate
     * to sendAPDU; the default below does exactly that.
     *
     * @param[in]     apdu        APDU command bytes.
     * @param[in]     apduLen     Length of the APDU command.
     * @param[out]    response    Buffer to receive the card response.
     * @param[in,out] responseLen On entry: capacity of @p response.
     *                            On exit: actual bytes written.
     * @return true if the exchange succeeded, false otherwise.
     */
    virtual bool sendAPDULarge(const uint8_t* apdu, uint8_t apduLen,
                               uint8_t* response, uint16_t& responseLen) {
        uint8_t smallLen = static_cast<uint8_t>(
            (responseLen > static_cast<uint16_t>(UINT8_MAX))
                ? static_cast<uint16_t>(UINT8_MAX)
                : responseLen);
        bool result = sendAPDU(apdu, apduLen, response, smallLen);
        responseLen = static_cast<uint16_t>(smallLen);
        return result;
    }

    /**
     * @brief Reset the NFC reader/field for the next card detection cycle.
     */
    virtual void resetReader() = 0;

    /**
     * @brief Print NFC module firmware version information to the logger.
     * @return true if firmware info was retrieved successfully, false otherwise.
     */
    virtual bool printFirmwareVersion() = 0;

    virtual ~CW_NfcTransport() {}
};

#endif // CW_NFCTRANSPORT_H
