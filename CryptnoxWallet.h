#ifndef CRYPTNOXWALLET_H
#define CRYPTNOXWALLET_H

/******************************************************************
 * 1. Included files
 ******************************************************************/

#include "platform_compat.h"
#include "CW_Defs.h"
#include "CW_Logger.h"
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
 * @brief Request parameters for the sign operation.
 */
struct CW_SignRequest {
    CW_SecureSession& session;       /**< Reference to a valid secure session */
    uint8_t keyType;                 /**< Key / path type (e.g. CW_SIGN_CURR_K1) */
    uint8_t signatureType;           /**< Signature type (e.g. CW_SIGN_SIG_ECDSA_LOW_S) */
    uint8_t pin[CW_MAX_PIN_LENGTH];  /**< PIN bytes (4–9 ASCII digits) */
    bool pinLessMode;                /**< false = PIN path, true = PIN-less path */
    const uint8_t* hash;             /**< Pointer to the hash to sign (32 bytes) */
    uint8_t hashLength;              /**< Length of the hash in bytes */
    const uint8_t* derivePath;       /**< BIP32 path bytes for DERIVE modes (NULL for CURR) */
    uint8_t derivePathLength;        /**< Length of derivePath (must be a multiple of 4) */

    explicit CW_SignRequest(CW_SecureSession& sess,
                            uint8_t kType   = CW_SIGN_CURR_K1,
                            uint8_t sigType = CW_SIGN_SIG_ECDSA_LOW_S,
                            bool pinless    = CW_SIGN_WITH_PIN)
        : session(sess), keyType(kType), signatureType(sigType),
          pinLessMode(pinless), hash(NULL), hashLength(0U),
          derivePath(NULL), derivePathLength(0U) {
        memset(pin, 0U, sizeof(pin));
    }

    ~CW_SignRequest() {
        CW_Utils::secure_wipe(pin, sizeof(pin));
    }
};

/**
 * @struct CW_SignResult
 * @brief Result of the sign operation.
 */
struct CW_SignResult {
    uint8_t signature[CW_RAW_SIGNATURE_SIZE]; /**< Raw signature (r[32] + s[32]) */
    uint8_t errorCode;                        /**< Error code (CW_OK on success) */

    CW_SignResult() : errorCode(CW_NOK) {
        memset(signature, 0U, sizeof(signature));
    }
};

/******************************************************************
 * 3. CryptnoxWallet class
 ******************************************************************/

/**
 * @class CryptnoxWallet
 * @brief High-level interface for interacting with a Cryptnox smart card over NFC.
 *
 * Manages card connection, secure channel establishment (delegated to
 * CW_SecureChannel), PIN verification, signing, and user data writing.
 *
 * Dependencies are injected by the caller. CryptnoxWallet interfaces
 * exclusively with CW_SecureChannel (Secure Stack) and CW_Logger (Logging),
 * keeping this class platform-independent.
 */
class CryptnoxWallet {
public:
    /**
     * @brief Construct a CryptnoxWallet.
     *
     * @param driver Reference to the NFC transport implementation.
     * @param logger Reference to the logging implementation.
     * @param crypto Reference to the crypto provider implementation.
     */
    CryptnoxWallet(CW_NfcTransport& driver, CW_Logger& logger, CW_CryptoProvider& crypto);

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
     * Retries the full card activation sequence up to CW_CONNECT_MAX_ATTEMPTS times.
     *
     * @param[out] session Secure session to populate with keys and IV.
     * @return true on success, false otherwise.
     */
    bool connect(CW_SecureSession& session);

    /**
     * @brief Establish a secure channel (SELECT → certificate → ECDH → mutual auth).
     * @param[out] session Secure session to populate.
     * @return true on success, false otherwise.
     */
    bool establishSecureChannel(CW_SecureSession& session);

    /**
     * @brief Disconnect and securely clear the session.
     *
     * MUST be called at the end of each card processing iteration,
     * even if connect() failed, to reset the reader for next use.
     *
     * @param[in,out] session Session to clear.
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
     * @brief Verify the PIN code on the smart card.
     *
     * @param[in,out] session   Valid secure session.
     * @param[in]     pin       PIN bytes (ASCII digits, 4–9 characters).
     * @param[in]     pinLength Length of the PIN.
     * @return true if the card accepted the PIN (status word 0x9000), false on
     *         wrong PIN, closed/invalid session, or transport/MAC failure.
     */
    bool verifyPin(CW_SecureSession& session, const uint8_t* pin, uint8_t pinLength);

    /**
     * @brief Sign a hash using the card's stored key.
     *
     * @param[in] request Sign parameters (session, keyType, signatureType, hash, PIN).
     * @return CW_SignResult with signature[64] and errorCode.
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
    CW_Logger&       _logger;  ///< Logging interface.
    CW_SecureChannel _secure;  ///< Owned secure channel.

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
