/*
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Cryptnox SA
 */

/**
 * @file CW_Utils.cpp
 * @brief Implementation of the platform-independent utility helpers.
 *
 * @ref CW_Utils::secure_compare iterates over the full length to avoid
 * leaking byte-position information through timing. @ref CW_Utils::secure_wipe
 * uses a volatile pointer so the writes cannot be optimised away.
 * @ref CW_Utils::safe_memcpy validates pointers, length, and source/destination
 * overlap before delegating to memcpy.
 */

#include "CW_Utils.h"

/**
 * @brief Constant-time buffer comparison, resistant to timing side-channel attacks.
 */
bool CW_Utils::secure_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    bool ret = false;
    if ((a != NULL) && (b != NULL) && (len > 0U)) {
        uint8_t diff = 0U;
        for (size_t i = 0U; i < len; i++) {
            diff |= a[i] ^ b[i];
        }
        ret = (diff == 0U);
    }
    return ret;
}

/**
 * @brief Securely zero a buffer, guaranteed not to be optimised away.
 */
void CW_Utils::secure_wipe(uint8_t* buf, size_t len) {
    if ((buf != NULL) && (len > 0U)) {
        volatile uint8_t* p = buf;
        for (size_t i = 0U; i < len; i++) {
            p[i] = 0U;
        }
    }
}

/**
 * @brief Safe memcpy — checks src, dst and size before copying.
 * @return true if copy succeeded, false otherwise.
 */
bool CW_Utils::safe_memcpy(uint8_t* dst, size_t dstSize,
                                 const uint8_t* src, size_t count) {
    bool ret = false;
    if ((dst != NULL) && (src != NULL) && (count > 0U) && (count <= dstSize)) {
        bool overlap = (dst < (src + count)) && (src < (dst + dstSize));
        if (!overlap) {
            memcpy(dst, src, count);
            ret = true;
        }
    }
    return ret;
}
