#ifndef CRYPTNOX_UTILS_H
#define CRYPTNOX_UTILS_H

/******************************************************************
 * 1. Included files
 ******************************************************************/

#include "platform_compat.h"

/******************************************************************
 * 2. Class declaration
 ******************************************************************/

/**
 * @class CryptnoxUtils
 * @brief Portable utility functions for cryptographic and security operations.
 *
 * All methods here are platform-independent pure C++ with no dependency
 * on Arduino or any hardware-specific library.
 *
 * Hardware-specific helpers (e.g. TRNG byte generation) live in the
 * concrete crypto provider implementation (ArduinoCryptoProvider).
 */
class CryptnoxUtils {
public:
    /**
     * @brief Constant-time buffer comparison, resistant to timing side-channel attacks.
     *
     * Always iterates over the full length regardless of where the first difference
     * occurs, preventing an attacker from inferring the correct value byte-by-byte
     * via timing measurements.
     *
     * @param a   Pointer to the first buffer.
     * @param b   Pointer to the second buffer.
     * @param len Number of bytes to compare.
     * @return true if the buffers are identical, false otherwise.
     */
    static bool secure_compare(const uint8_t* a, const uint8_t* b, size_t len);

    /**
     * @brief Securely zero a buffer, guaranteed not to be optimised away.
     *
     * Uses a volatile pointer so the compiler cannot elide the writes,
     * ensuring sensitive material is actually erased from memory.
     *
     * @param buf Pointer to the buffer to wipe.
     * @param len Number of bytes to zero.
     */
    static void secure_wipe(uint8_t* buf, size_t len);

    /**
     * @brief Safe memcpy — validates pointers, sizes, and checks for overlap.
     *
     * @param dst     Destination buffer.
     * @param dstSize Capacity of the destination buffer.
     * @param src     Source buffer.
     * @param count   Number of bytes to copy.
     * @return true if copy succeeded, false if parameters are invalid.
     */
    static bool safe_memcpy(uint8_t* dst, size_t dstSize,
                            const uint8_t* src, size_t count);
};

#endif // CRYPTNOX_UTILS_H
