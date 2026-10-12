/*
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Cryptnox SA
 */

/**
 * @file CW_Tron.h
 * @brief TRON (TRX) network support — BIP44 path and Base58Check addresses.
 *
 * TRON reuses Ethereum's key material and hashing: the account address is
 * @c keccak256(publicKey)[12..32], but it is prefixed with @c 0x41 and
 * presented as Base58Check instead of hex — so every address starts with
 * a capital @c T and is exactly 34 characters long.
 *
 * Provides:
 *  - @ref CW_TRON_DERIVE_PATH — the wire-format BIP44 path for @c CW_SIGN_DERIVE_K1
 *  - public key → address (raw 21 bytes, or Base58Check text)
 *  - Base58Check address → raw 21 bytes, with checksum validation
 *
 * Signing itself is plain secp256k1 ECDSA over a 32-byte digest, so
 * @ref CryptnoxWallet::sign needs no TRON-specific handling. Transaction
 * serialisation (protobuf) is out of scope here — TRON full nodes build the
 * unsigned transaction over HTTP, and the caller verifies it locally before
 * signing (see the ESP32 @c TronSigning example).
 */

#ifndef CW_TRON_H
#define CW_TRON_H

/******************************************************************
 * 1. Included files
 ******************************************************************/

#include "platform_compat.h"
#include "CW_CryptoProvider.h"

/******************************************************************
 * 2. Constants / define declarations
 ******************************************************************/

/** @brief Length of the wire-format TRON BIP44 derivation path in bytes. */
#define CW_TRON_PATH_LENGTH      (20U)

/** @brief Raw TRON address length: @c 0x41 prefix + 20 address bytes. */
#define CW_TRON_ADDRESS_BYTES    (21U)

/** @brief TRON mainnet address prefix byte (renders as a leading @c 'T'). */
#define CW_TRON_ADDRESS_PREFIX   (0x41U)

/** @brief Base58Check address length in characters, excluding the NUL. */
#define CW_TRON_ADDRESS_STR_LEN  (34U)

/** @brief Minimum buffer size for a Base58Check address string (34 + NUL). */
#define CW_TRON_ADDRESS_STR_SIZE (CW_TRON_ADDRESS_STR_LEN + 1U)

/**
 * @brief BIP44 derivation path for TRON: @c m/44'/195'/0'/0/0.
 * @ingroup util
 *
 * Wire format expected by the card's SIGN command: five big-endian uint32
 * levels, hardened levels carrying the high bit. Pass as
 * @c CW_SignRequest::derivePath with @c keyType == @ref CW_SIGN_DERIVE_K1.
 */
extern const uint8_t CW_TRON_DERIVE_PATH[CW_TRON_PATH_LENGTH];

/******************************************************************
 * 3. Class declaration
 ******************************************************************/

/**
 * @class CW_Tron
 * @ingroup util
 * @brief TRON address derivation and Base58Check encoding.
 *
 * Stateless helpers. The Base58Check checksum is a double SHA-256, so the
 * encode / decode entry points take the host's @ref CW_CryptoProvider rather
 * than bundling a second hash implementation. Keccak-256 is implemented
 * internally — no adapter method is needed for it.
 */
class CW_Tron {
public:
    /**
     * @brief Derive the raw 21-byte TRON address from an uncompressed public key.
     *
     * Computes @c 0x41 || keccak256(publicKey64)[12..32].
     *
     * @param[in]  publicKey64 64-byte public key (X||Y, no @c 0x04 prefix).
     * @param[out] out         21-byte output buffer.
     * @return true on success, false if either pointer is @c NULL.
     */
    static bool addressBytesFromPublicKey(const uint8_t* publicKey64,
                                          uint8_t* out);

    /**
     * @brief Derive the Base58Check TRON address from an uncompressed public key.
     *
     * Convenience wrapper: @ref addressBytesFromPublicKey followed by
     * @ref encodeAddress.
     *
     * @param[in]  publicKey64 64-byte public key (X||Y, no @c 0x04 prefix).
     * @param[in]  crypto      Crypto provider (used for the SHA-256 checksum).
     * @param[out] out         Output buffer for the NUL-terminated address.
     * @param[in]  outSize     Capacity of @p out; must be at least
     *                         @ref CW_TRON_ADDRESS_STR_SIZE.
     * @return true on success, false on bad arguments or hash failure.
     */
    static bool addressFromPublicKey(const uint8_t* publicKey64,
                                     CW_CryptoProvider& crypto,
                                     char* out, size_t outSize);

    /**
     * @brief Base58Check-encode a raw 21-byte TRON address.
     *
     * Appends the first 4 bytes of @c sha256(sha256(addressBytes)) as the
     * checksum and Base58-encodes the 25-byte result.
     *
     * @param[in]  addressBytes 21-byte address (must start with @c 0x41).
     * @param[in]  crypto       Crypto provider (used for the SHA-256 checksum).
     * @param[out] out          Output buffer for the NUL-terminated address.
     * @param[in]  outSize      Capacity of @p out; must be at least
     *                          @ref CW_TRON_ADDRESS_STR_SIZE.
     * @return true on success, false on bad arguments, wrong prefix, or hash
     *         failure.
     */
    static bool encodeAddress(const uint8_t* addressBytes,
                              CW_CryptoProvider& crypto,
                              char* out, size_t outSize);

    /**
     * @brief Decode and validate a Base58Check TRON address.
     *
     * Rejects anything that is not a well-formed mainnet address: wrong
     * length, characters outside the Base58 alphabet, a prefix other than
     * @c 0x41, or a checksum mismatch. Use this on every address that
     * arrives from outside the firmware (config, QR code, RPC response)
     * before it is used to build or verify a transaction.
     *
     * @param[in]  address 34-character NUL-terminated Base58Check address.
     * @param[in]  crypto  Crypto provider (used for the SHA-256 checksum).
     * @param[out] out     21-byte output buffer for the raw address.
     * @return true if the address is valid and @p out was written, false
     *         otherwise (@p out is then left untouched).
     */
    static bool decodeAddress(const char* address,
                              CW_CryptoProvider& crypto,
                              uint8_t* out);

    /**
     * @brief Compute Keccak-256 (the pre-standard padding, as used by
     *        Ethereum and TRON — not SHA3-256).
     *
     * Exposed because TRON address derivation needs it and no
     * @ref CW_CryptoProvider method covers it.
     *
     * @param[in]  data Input buffer.
     * @param[in]  len  Number of bytes to hash.
     * @param[out] out  32-byte digest output.
     * @return true on success, false if a pointer is @c NULL.
     */
    static bool keccak256(const uint8_t* data, size_t len, uint8_t* out);
};

#endif // CW_TRON_H
