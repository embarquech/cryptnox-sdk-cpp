/*
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Cryptnox SA
 */

/**
 * @file CW_Tron.cpp
 * @brief Implementation of TRON address derivation and Base58Check coding.
 *
 * Contains a compact Keccak-f[1600] permutation (file-local) because TRON
 * addresses are Ethereum-style @c keccak256 digests and no
 * @ref CW_CryptoProvider method provides Keccak. Base58 is done with plain
 * long division / multiplication over the fixed 25-byte payload — no
 * bignum library.
 *
 * Self-check (no crypto provider needed, Keccak and Base58 only):
 * @code
 * g++ -DCW_TRON_SELFTEST CW_Tron.cpp CW_Utils.cpp -o cw_tron_selftest
 * ./cw_tron_selftest
 * @endcode
 */

#include "CW_Tron.h"

/******************************************************************
 * 1. Constants
 ******************************************************************/

/* m/44'/195'/0'/0/0 — five big-endian uint32 levels, hardened levels have
 * the high bit set. 195 = 0xC3 is the SLIP-44 coin type for TRON. */
const uint8_t CW_TRON_DERIVE_PATH[CW_TRON_PATH_LENGTH] = {
    0x80U, 0x00U, 0x00U, 0x2CU,   /* 44'  */
    0x80U, 0x00U, 0x00U, 0xC3U,   /* 195' */
    0x80U, 0x00U, 0x00U, 0x00U,   /* 0'   */
    0x00U, 0x00U, 0x00U, 0x00U,   /* 0    */
    0x00U, 0x00U, 0x00U, 0x00U    /* 0    */
};

/** Bitcoin / TRON Base58 alphabet. */
static const char BASE58_ALPHABET[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

#define BASE58_BASE          (58U)
#define TRON_CHECKSUM_BYTES  (4U)
#define TRON_PAYLOAD_BYTES   (CW_TRON_ADDRESS_BYTES + TRON_CHECKSUM_BYTES) /* 25 */
#define KECCAK_DIGEST_BYTES  (32U)
#define KECCAK_RATE_BYTES    (136U)  /* 1600 - 2*256 bits, in bytes */
#define KECCAK_STATE_LANES   (25U)
#define KECCAK_ROUNDS        (24U)
#define ETH_ADDRESS_BYTES    (20U)
#define PUBLIC_KEY_BYTES     (64U)

/******************************************************************
 * 2. Keccak-256 (file-local)
 ******************************************************************/

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64U - (n))))

/** Iota round constants. */
static const uint64_t KECCAK_RC[KECCAK_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
    0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

/** Rho rotation offsets, indexed as @c x+5y. */
static const uint8_t KECCAK_ROT[KECCAK_STATE_LANES] = {
     0U,  1U, 62U, 28U, 27U,
    36U, 44U,  6U, 55U, 20U,
     3U, 10U, 43U, 25U, 39U,
    41U, 45U, 15U, 21U,  8U,
    18U,  2U, 61U, 56U, 14U
};

/**
 * @brief The Keccak-f[1600] permutation, in place.
 * @param a 25-lane state.
 */
static void keccak_f(uint64_t* a) {
    for (unsigned round = 0U; round < KECCAK_ROUNDS; round++) {
        uint64_t c[5];
        uint64_t d[5];
        uint64_t b[KECCAK_STATE_LANES];

        /* Theta */
        for (unsigned x = 0U; x < 5U; x++) {
            c[x] = a[x] ^ a[x + 5U] ^ a[x + 10U] ^ a[x + 15U] ^ a[x + 20U];
        }
        for (unsigned x = 0U; x < 5U; x++) {
            d[x] = c[(x + 4U) % 5U] ^ ROTL64(c[(x + 1U) % 5U], 1U);
        }
        for (unsigned y = 0U; y < 5U; y++) {
            for (unsigned x = 0U; x < 5U; x++) {
                a[x + (5U * y)] ^= d[x];
            }
        }

        /* Rho + Pi */
        for (unsigned y = 0U; y < 5U; y++) {
            for (unsigned x = 0U; x < 5U; x++) {
                const unsigned src = x + (5U * y);
                const unsigned dst = y + (5U * (((2U * x) + (3U * y)) % 5U));
                b[dst] = (KECCAK_ROT[src] == 0U) ? a[src]
                                                 : ROTL64(a[src], KECCAK_ROT[src]);
            }
        }

        /* Chi */
        for (unsigned y = 0U; y < 5U; y++) {
            for (unsigned x = 0U; x < 5U; x++) {
                a[x + (5U * y)] = b[x + (5U * y)] ^
                                  ((~b[((x + 1U) % 5U) + (5U * y)]) &
                                    b[((x + 2U) % 5U) + (5U * y)]);
            }
        }

        /* Iota */
        a[0] ^= KECCAK_RC[round];
    }
}

/**
 * @brief Absorb @p len bytes of @p data into the sponge lane-wise.
 *
 * Byte-indexed XOR into the lanes, so the result is identical on
 * big- and little-endian hosts.
 */
static void keccak_absorb(uint64_t* a, const uint8_t* data, size_t len) {
    size_t offset = 0U;

    while (len >= KECCAK_RATE_BYTES) {
        for (size_t i = 0U; i < KECCAK_RATE_BYTES; i++) {
            a[i / 8U] ^= ((uint64_t)data[offset + i]) << (8U * (i % 8U));
        }
        keccak_f(a);
        offset += KECCAK_RATE_BYTES;
        len    -= KECCAK_RATE_BYTES;
    }

    /* Final (possibly empty) block plus Keccak padding: 0x01 ... 0x80. */
    for (size_t i = 0U; i < len; i++) {
        a[i / 8U] ^= ((uint64_t)data[offset + i]) << (8U * (i % 8U));
    }
    a[len / 8U] ^= ((uint64_t)0x01U) << (8U * (len % 8U));
    a[(KECCAK_RATE_BYTES - 1U) / 8U] ^=
        ((uint64_t)0x80U) << (8U * ((KECCAK_RATE_BYTES - 1U) % 8U));
    keccak_f(a);
}

bool CW_Tron::keccak256(const uint8_t* data, size_t len, uint8_t* out) {
    bool ret = false;

    if (((data != NULL) || (len == 0U)) && (out != NULL)) {
        uint64_t a[KECCAK_STATE_LANES];
        for (unsigned i = 0U; i < KECCAK_STATE_LANES; i++) {
            a[i] = 0ULL;
        }

        keccak_absorb(a, data, len);

        for (unsigned i = 0U; i < KECCAK_DIGEST_BYTES; i++) {
            out[i] = (uint8_t)((a[i / 8U] >> (8U * (i % 8U))) & 0xFFU);
        }
        ret = true;
    }

    return ret;
}

/******************************************************************
 * 3. Base58 over the fixed 25-byte payload (file-local)
 ******************************************************************/

/*
 * ponytail: no leading-zero ('1' padding) handling — a TRON payload always
 * starts with 0x41, so the encoding is always exactly 34 chars. Add the
 * generic leading-zero loop only if this is ever reused for Bitcoin-style
 * payloads, which can start with 0x00.
 */

/**
 * @brief Base58-encode a 25-byte payload into exactly 34 characters + NUL.
 * @param[in]  payload 25 bytes, first byte non-zero.
 * @param[out] out     Buffer of at least @ref CW_TRON_ADDRESS_STR_SIZE bytes.
 * @return true on success, false if the encoding did not come out 34 chars.
 */
static bool base58_encode_payload(const uint8_t* payload, char* out) {
    uint8_t tmp[TRON_PAYLOAD_BYTES];
    char    reversed[CW_TRON_ADDRESS_STR_LEN];
    size_t  digits = 0U;
    size_t  start  = 0U;

    memcpy(tmp, payload, sizeof(tmp));

    while ((start < TRON_PAYLOAD_BYTES) && (digits < sizeof(reversed))) {
        uint32_t remainder = 0U;
        for (size_t i = start; i < TRON_PAYLOAD_BYTES; i++) {
            const uint32_t acc = (remainder << 8U) | (uint32_t)tmp[i];
            tmp[i]    = (uint8_t)(acc / BASE58_BASE);
            remainder = acc % BASE58_BASE;
        }
        reversed[digits] = BASE58_ALPHABET[remainder];
        digits++;

        while ((start < TRON_PAYLOAD_BYTES) && (tmp[start] == 0U)) {
            start++;
        }
    }

    const bool ret = (digits == CW_TRON_ADDRESS_STR_LEN);
    if (ret) {
        for (size_t i = 0U; i < digits; i++) {
            out[i] = reversed[digits - 1U - i];
        }
        out[digits] = '\0';
    }

    return ret;
}

/**
 * @brief Base58-decode a 34-character address into a right-aligned 25-byte payload.
 * @param[in]  address 34-character NUL-terminated Base58 string.
 * @param[out] payload 25-byte output buffer.
 * @return true on success, false on an invalid character or overflow.
 */
static bool base58_decode_payload(const char* address, uint8_t* payload) {
    memset(payload, 0, TRON_PAYLOAD_BYTES);

    for (size_t i = 0U; i < CW_TRON_ADDRESS_STR_LEN; i++) {
        const char* found = strchr(BASE58_ALPHABET, address[i]);
        /* strchr would also match the terminating NUL of the alphabet. */
        if ((found == NULL) || (address[i] == '\0')) {
            return false;
        }

        uint32_t carry = (uint32_t)(found - BASE58_ALPHABET);
        for (size_t j = TRON_PAYLOAD_BYTES; j > 0U; j--) {
            const uint32_t acc = ((uint32_t)payload[j - 1U] * BASE58_BASE) + carry;
            payload[j - 1U] = (uint8_t)(acc & 0xFFU);
            carry           = acc >> 8U;
        }
        if (carry != 0U) {
            return false;   /* value wider than 25 bytes */
        }
    }

    return true;
}

/******************************************************************
 * 4. Public API
 ******************************************************************/

/**
 * @brief Compute the 4-byte Base58Check checksum: sha256(sha256(payload))[0..4].
 */
static bool tron_checksum(const uint8_t* addressBytes, CW_CryptoProvider& crypto,
                          uint8_t* checksum4) {
    uint8_t first[KECCAK_DIGEST_BYTES];
    uint8_t second[KECCAK_DIGEST_BYTES];
    bool    ret = false;

    if (crypto.sha256(addressBytes, CW_TRON_ADDRESS_BYTES, first) &&
        crypto.sha256(first, sizeof(first), second)) {
        memcpy(checksum4, second, TRON_CHECKSUM_BYTES);
        ret = true;
    }

    return ret;
}

bool CW_Tron::addressBytesFromPublicKey(const uint8_t* publicKey64, uint8_t* out) {
    bool ret = false;

    if ((publicKey64 != NULL) && (out != NULL)) {
        uint8_t digest[KECCAK_DIGEST_BYTES];
        if (CW_Tron::keccak256(publicKey64, PUBLIC_KEY_BYTES, digest)) {
            out[0] = CW_TRON_ADDRESS_PREFIX;
            memcpy(&out[1], &digest[KECCAK_DIGEST_BYTES - ETH_ADDRESS_BYTES],
                   ETH_ADDRESS_BYTES);
            ret = true;
        }
    }

    return ret;
}

bool CW_Tron::encodeAddress(const uint8_t* addressBytes, CW_CryptoProvider& crypto,
                            char* out, size_t outSize) {
    bool ret = false;

    if ((addressBytes != NULL) && (out != NULL) &&
        (outSize >= CW_TRON_ADDRESS_STR_SIZE) &&
        (addressBytes[0] == CW_TRON_ADDRESS_PREFIX)) {

        uint8_t payload[TRON_PAYLOAD_BYTES];
        memcpy(payload, addressBytes, CW_TRON_ADDRESS_BYTES);

        if (tron_checksum(addressBytes, crypto, &payload[CW_TRON_ADDRESS_BYTES])) {
            ret = base58_encode_payload(payload, out);
        }
    }

    return ret;
}

bool CW_Tron::addressFromPublicKey(const uint8_t* publicKey64,
                                   CW_CryptoProvider& crypto,
                                   char* out, size_t outSize) {
    uint8_t addressBytes[CW_TRON_ADDRESS_BYTES];

    return CW_Tron::addressBytesFromPublicKey(publicKey64, addressBytes) &&
           CW_Tron::encodeAddress(addressBytes, crypto, out, outSize);
}

bool CW_Tron::decodeAddress(const char* address, CW_CryptoProvider& crypto,
                            uint8_t* out) {
    bool ret = false;

    if ((address != NULL) && (out != NULL) &&
        (strlen(address) == CW_TRON_ADDRESS_STR_LEN)) {

        uint8_t payload[TRON_PAYLOAD_BYTES];
        uint8_t checksum[TRON_CHECKSUM_BYTES];

        if (base58_decode_payload(address, payload) &&
            (payload[0] == CW_TRON_ADDRESS_PREFIX) &&
            tron_checksum(payload, crypto, checksum) &&
            CW_Utils::secure_compare(checksum, &payload[CW_TRON_ADDRESS_BYTES],
                                     TRON_CHECKSUM_BYTES)) {
            memcpy(out, payload, CW_TRON_ADDRESS_BYTES);
            ret = true;
        }
    }

    return ret;
}

/******************************************************************
 * 5. Self-check
 ******************************************************************/

#ifdef CW_TRON_SELFTEST

#include <assert.h>
#include <stdio.h>

/* Vectors derived from secp256k1 private keys 1 and
 * 0x1234...cdef; cross-checked against pycryptodome Keccak + base58. */
static void check_keccak_empty(void) {
    /* The canonical Keccak-256 (not SHA3-256) digest of the empty string. */
    static const uint8_t expected[32] = {
        0xC5U, 0xD2U, 0x46U, 0x01U, 0x86U, 0xF7U, 0x23U, 0x3CU,
        0x92U, 0x7EU, 0x7DU, 0xB2U, 0xDCU, 0xC7U, 0x03U, 0xC0U,
        0xE5U, 0x00U, 0xB6U, 0x53U, 0xCAU, 0x82U, 0x27U, 0x3BU,
        0x7BU, 0xFAU, 0xD8U, 0x04U, 0x5DU, 0x85U, 0xA4U, 0x70U
    };
    uint8_t digest[32];
    assert(CW_Tron::keccak256(NULL, 0U, digest));
    assert(memcmp(digest, expected, sizeof(expected)) == 0);
}

static void check_address_bytes(void) {
    /* Public key for private key 1 (the secp256k1 generator point). */
    static const uint8_t pub[64] = {
        0x79U,0xBEU,0x66U,0x7EU,0xF9U,0xDCU,0xBBU,0xACU,
        0x55U,0xA0U,0x62U,0x95U,0xCEU,0x87U,0x0BU,0x07U,
        0x02U,0x9BU,0xFCU,0xDBU,0x2DU,0xCEU,0x28U,0xD9U,
        0x59U,0xF2U,0x81U,0x5BU,0x16U,0xF8U,0x17U,0x98U,
        0x48U,0x3AU,0xDAU,0x77U,0x26U,0xA3U,0xC4U,0x65U,
        0x5DU,0xA4U,0xFBU,0xFCU,0x0EU,0x11U,0x08U,0xA8U,
        0xFDU,0x17U,0xB4U,0x48U,0xA6U,0x85U,0x54U,0x19U,
        0x9CU,0x47U,0xD0U,0x8FU,0xFBU,0x10U,0xD4U,0xB8U
    };
    /* 0x41 || keccak256(pub)[12..32] */
    static const uint8_t expected[21] = {
        0x41U,0x7EU,0x5FU,0x45U,0x52U,0x09U,0x1AU,0x69U,0x12U,0x5DU,0x5DU,
        0xFCU,0xB7U,0xB8U,0xC2U,0x65U,0x90U,0x29U,0x39U,0x5BU,0xDFU
    };
    uint8_t addr[21];
    assert(CW_Tron::addressBytesFromPublicKey(pub, addr));
    assert(memcmp(addr, expected, sizeof(expected)) == 0);
}

static void check_base58(void) {
    /* addr21 above || sha256(sha256(addr21))[0..4] == 0xB164FB1F */
    static const uint8_t payload[25] = {
        0x41U,0x7EU,0x5FU,0x45U,0x52U,0x09U,0x1AU,0x69U,0x12U,0x5DU,0x5DU,
        0xFCU,0xB7U,0xB8U,0xC2U,0x65U,0x90U,0x29U,0x39U,0x5BU,0xDFU,
        0xB1U,0x64U,0xFBU,0x1FU
    };
    static const char expected[] = "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC";

    char text[CW_TRON_ADDRESS_STR_SIZE];
    assert(base58_encode_payload(payload, text));
    assert(strcmp(text, expected) == 0);

    uint8_t roundTrip[25];
    assert(base58_decode_payload(expected, roundTrip));
    assert(memcmp(roundTrip, payload, sizeof(payload)) == 0);

    /* A second, independent vector (private key 0x1234...cdef). */
    static const uint8_t payload2[25] = {
        0x41U,0x1BU,0xE3U,0x1AU,0x94U,0x36U,0x1AU,0x39U,0x1BU,0xBAU,0xFBU,
        0x2AU,0x4CU,0xCDU,0x70U,0x4FU,0x57U,0xDCU,0x04U,0xD4U,0xBBU,
        0x11U,0xAFU,0x6DU,0xEEU
    };
    assert(base58_encode_payload(payload2, text));
    assert(strcmp(text, "TCWfJguCLonUkvmsptQKHUyUJ713pU7XQ1") == 0);

    /* Characters outside the Base58 alphabet must be rejected. */
    char bad[CW_TRON_ADDRESS_STR_SIZE];
    memcpy(bad, expected, sizeof(bad));
    bad[5] = '0';   /* '0' is not in the Base58 alphabet */
    uint8_t ignored[25];
    assert(!base58_decode_payload(bad, ignored));
}

int main(void) {
    check_keccak_empty();
    check_address_bytes();
    check_base58();
    printf("CW_Tron self-check OK\n");
    return 0;
}

#endif /* CW_TRON_SELFTEST */
