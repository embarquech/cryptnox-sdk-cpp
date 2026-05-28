/*
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Cryptnox SA
 */

/**
 * @file CW_Platform.h
 * @brief Abstract platform interface for timing primitives.
 *
 * Declares @ref CW_Platform, the contract that hosts implement so the SDK
 * stays independent of any specific RTOS or bare-metal delay mechanism.
 *
 * Currently exposes a single operation (@ref CW_Platform::sleep_ms) used by
 * @ref CW_SecureChannel for inter-APDU spacing on slow NFC stacks.
 */

#ifndef CW_PLATFORM_H
#define CW_PLATFORM_H

/******************************************************************
 * 1. Included files
 ******************************************************************/

#include "platform_compat.h"

/******************************************************************
 * 2. Class declaration
 ******************************************************************/

/**
 * @class CW_Platform
 * @ingroup adapters
 * @brief Abstract interface for platform-specific operations used by the SDK.
 *
 * Decouples the SDK core from any specific RTOS or bare-metal delay
 * mechanism, allowing the same SDK to run on ESP32 (FreeRTOS), Arduino,
 * and hosted (Linux/macOS) test environments.
 */
class CW_Platform {
public:
    /**
     * @brief Block for at least @p ms milliseconds.
     *
     * @param[in] ms  Duration to sleep in milliseconds.
     */
    virtual void sleep_ms(uint32_t ms) = 0;

    virtual ~CW_Platform() {}
};

#endif /* CW_PLATFORM_H */
