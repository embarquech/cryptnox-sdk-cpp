#include "CryptnoxUtils.h"

/**
 * @brief Constant-time buffer comparison, resistant to timing side-channel attacks.
 */
bool CryptnoxUtils::secure_compare(const uint8_t* a, const uint8_t* b, size_t len) {
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
void CryptnoxUtils::secure_wipe(uint8_t* buf, size_t len) {
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
bool CryptnoxUtils::safe_memcpy(uint8_t* dst, size_t dstSize,
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
