#ifndef CW_CRYPTOPROVIDER_H
#define CW_CRYPTOPROVIDER_H

/******************************************************************
 * 1. Included files
 ******************************************************************/

#include "platform_compat.h"
#include <uECC.h>

/******************************************************************
 * 2. Class declaration
 ******************************************************************/

/**
 * @class CW_CryptoProvider
 * @brief Abstract interface for cryptographic operations used by CW_SecureChannel.
 *
 * Decouples the secure channel protocol from any specific crypto library.
 * The concrete implementation (ArduinoCryptoProvider) wraps AESLib, SHA512,
 * micro-ecc, and the RA4M1 hardware TRNG.
 */
class CW_CryptoProvider {
public:
    /**
     * @brief Compute SHA-256 over a contiguous data buffer.
     *
     * @param[in]  data  Input buffer.
     * @param[in]  len   Number of bytes to hash.
     * @param[out] out   32-byte output buffer.
     * @return true on success, false if the underlying hash accelerator faults.
     */
    virtual bool sha256(const uint8_t* data, size_t len, uint8_t* out) = 0;

    /**
     * @brief Compute SHA-512 over a contiguous data buffer.
     *
     * @param[in]  data  Input buffer.
     * @param[in]  len   Number of bytes to hash.
     * @param[out] out   64-byte output buffer.
     * @return true on success, false if the underlying hash accelerator faults.
     */
    virtual bool sha512(const uint8_t* data, size_t len, uint8_t* out) = 0;

    /**
     * @brief AES-CBC encrypt.
     *
     * @param[in]  in         Plaintext input buffer.
     * @param[in]  len        Length of the plaintext.
     * @param[out] out        Ciphertext output buffer (must be large enough for padding).
     * @param[in]  key        AES key bytes.
     * @param[in]  keyLen     AES key length in bytes (16, 24, or 32).
     * @param[in,out] iv      16-byte IV; updated to last cipher block on return.
     * @param[in]  bitPadding true = ISO/IEC 9797-1 Method 2 (Bit) padding;
     *                        false = Null padding (no padding added).
     * @return Length of the ciphertext written to @p out.
     */
    virtual uint16_t aesCbcEncrypt(const uint8_t* in, uint16_t len, uint8_t* out,
                                   const uint8_t* key, uint8_t keyLen,
                                   uint8_t* iv, bool bitPadding) = 0;

    /**
     * @brief AES-CBC decrypt.
     *
     * @param[in]  in         Ciphertext input buffer (non-const; may be modified internally).
     * @param[in]  len        Length of the ciphertext.
     * @param[out] out        Plaintext output buffer.
     * @param[in]  key        AES key bytes.
     * @param[in]  keyLen     AES key length in bytes.
     * @param[in,out] iv      16-byte IV used as decrypt IV.
     * @param[in]  bitPadding true = Bit padding removal; false = Null padding (no removal).
     * @return Length of the plaintext written to @p out.
     */
    virtual uint16_t aesCbcDecrypt(uint8_t* in, uint16_t len, uint8_t* out,
                                   const uint8_t* key, uint8_t keyLen,
                                   uint8_t* iv, bool bitPadding) = 0;

    /**
     * @brief ECDH shared secret computation.
     *
     * @param[in]  pubKey  Remote public key (64 bytes, X||Y, no 0x04 prefix).
     * @param[in]  privKey Local private key (32 bytes).
     * @param[out] secret  32-byte shared secret output.
     * @param[in]  curve   uECC curve (e.g. uECC_secp256r1()).
     * @return true on success, false otherwise.
     */
    virtual bool ecdh(const uint8_t* pubKey, const uint8_t* privKey,
                      uint8_t* secret, const uECC_Curve_t* curve) = 0;

    /**
     * @brief Generate a new EC key pair.
     *
     * @param[out] pubKey   64-byte public key output (X||Y, no prefix).
     * @param[out] privKey  32-byte private key output.
     * @param[in]  curve    uECC curve.
     * @return true on success, false otherwise.
     */
    virtual bool makeKey(uint8_t* pubKey, uint8_t* privKey,
                         const uECC_Curve_t* curve) = 0;

    /**
     * @brief Fill a buffer with cryptographically random bytes.
     *
     * @param[out] dest  Buffer to fill.
     * @param[in]  size  Number of bytes to generate.
     * @return true on success, false otherwise.
     */
    virtual bool random(uint8_t* dest, unsigned size) = 0;

    /**
     * @brief Verify an ECDSA signature (raw r||s, 64 bytes) against a message hash.
     *
     * @param[in] pubKey64  64-byte public key (X||Y, no 0x04 prefix) on secp256r1.
     * @param[in] hash      Message hash buffer.
     * @param[in] hashSize  Length of the hash in bytes.
     * @param[in] rawSig64  64-byte raw signature (r[32]||s[32]).
     * @return true if the signature is valid, false otherwise.
     */
    virtual bool verify(const uint8_t* pubKey64,
                        const uint8_t* hash, size_t hashSize,
                        const uint8_t* rawSig64) = 0;

    virtual ~CW_CryptoProvider() {}
};

#endif // CW_CRYPTOPROVIDER_H
