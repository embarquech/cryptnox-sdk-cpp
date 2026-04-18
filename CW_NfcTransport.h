#ifndef CW_NFCTRANSPORT_H
#define CW_NFCTRANSPORT_H

/******************************************************************
 * 1. Included files
 ******************************************************************/

#include "platform_compat.h"

/******************************************************************
 * 2. Class declaration
 ******************************************************************/

/**
 * @class CW_NfcTransport
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
    virtual bool sendAPDU(const uint8_t* apdu, uint16_t apduLen,
                          uint8_t* response, uint8_t& responseLen) = 0;

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
