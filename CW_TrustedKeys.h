/*
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Cryptnox SA
 */

/**
 * @file CW_TrustedKeys.h
 * @brief Cryptnox CA public keys used for offline certificate verification.
 *
 * Holds the trusted secp256r1 public keys that @ref
 * CW_SecureChannel::verifyCertificateChain checks the manufacturer
 * certificate against. Each key is stored as 64 raw bytes (X[32] || Y[32],
 * no 0x04 prefix) so it can be passed directly to `uECC_verify()`.
 *
 * Source: https://verify.cryptnox.tech/certificates/
 *
 * To update a key: download the .crt file from the URL above and extract
 * the EC public-key coordinates with:
 * @code{.sh}
 * python -c "from cryptography import x509; \
 *   c=x509.load_pem_x509_certificate(open('CERT.crt','rb').read()); \
 *   n=c.public_key().public_numbers(); \
 *   print(hex(n.x)); print(hex(n.y))"
 * @endcode
 */

#ifndef CW_TRUSTEDKEYS_H
#define CW_TRUSTEDKEYS_H

#include "platform_compat.h"

/* CRYPTNOX_DLT_CARDS_CA — signs manufacturer certificates for DLT cards.
 * Curve: secp256r1. Issued by CRYPTNOX INTERMEDIATE CA #2. */
static const uint8_t CW_CA_DLT_PUBKEY[64] = {
    /* X */
    0x64, 0x7a, 0x11, 0x2c, 0x2a, 0xcf, 0x5a, 0x49,
    0xb5, 0x2b, 0x32, 0x1c, 0xbd, 0xcf, 0x5a, 0x9e,
    0xa3, 0x07, 0xfc, 0x4c, 0xcd, 0x33, 0xaa, 0x78,
    0xb9, 0xb8, 0x05, 0x5d, 0xd8, 0x4d, 0x03, 0xae,
    /* Y */
    0xda, 0xb0, 0x2c, 0xc7, 0x20, 0xa7, 0x80, 0xcb,
    0x1f, 0xf2, 0x80, 0xaf, 0x50, 0x77, 0x4a, 0x6c,
    0xdc, 0x15, 0x7e, 0xfa, 0x23, 0x5e, 0xa2, 0x53,
    0x11, 0xa4, 0x2b, 0x4c, 0xf5, 0x7d, 0x88, 0x61
};

/* Number of trusted CA keys in the table below. */
#define CW_TRUSTED_CA_COUNT (1U)

/* Table of all trusted CA public keys (each 64 bytes, X||Y).
 * verifyCertificateChain() tries every entry until one succeeds. */
static const uint8_t* const CW_TRUSTED_CA_KEYS[CW_TRUSTED_CA_COUNT] = {
    CW_CA_DLT_PUBKEY
};

#endif /* CW_TRUSTEDKEYS_H */
