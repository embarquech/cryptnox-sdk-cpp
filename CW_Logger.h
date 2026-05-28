/*
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Cryptnox SA
 */

#ifndef CW_LOGGER_H
#define CW_LOGGER_H

/******************************************************************
 * 1. Included files
 ******************************************************************/

#include "platform_compat.h"

/******************************************************************
 * 2. Class declaration
 ******************************************************************/

/**
 * @class CW_Logger
 * @brief Abstract interface for serial/debug output.
 *
 * Provides a hardware-agnostic logging contract so that higher-level
 * components (CryptnoxWallet, CW_SecureChannel) remain independent
 * of the physical output device (UART, LCD, network, etc.).
 *
 * On Arduino, the F() macro returns a __FlashStringHelper* so the
 * dedicated overloads are called, keeping string literals in flash.
 * On non-Arduino, F() is the identity macro (returns const char*),
 * so the print(const char*) overload is called instead.
 */
class CW_Logger {
public:
    /**
     * @brief Initialize the logging interface.
     * @param baudRate Baud rate (relevant for UART implementations).
     * @return true if initialization succeeded, false otherwise.
     */
    virtual bool begin(unsigned long baudRate = 115200UL) = 0;

    /** @name Print methods (no newline) */
    ///@{
    virtual void print(const __FlashStringHelper* str) = 0;
    virtual void print(const char* str) = 0;
    virtual void print(char c) = 0;
    virtual void print(uint8_t value, int base = DEC) = 0;
    virtual void print(uint16_t value, int base = DEC) = 0;
    virtual void print(uint32_t value, int base = DEC) = 0;
    virtual void print(int value, int base = DEC) = 0;
    ///@}

    /** @name Println methods (with newline) */
    ///@{
    virtual void println() = 0;
    virtual void println(const __FlashStringHelper* str) = 0;
    virtual void println(const char* str) = 0;
    virtual void println(char c) = 0;
    virtual void println(uint8_t value, int base = DEC) = 0;
    virtual void println(uint16_t value, int base = DEC) = 0;
    virtual void println(uint32_t value, int base = DEC) = 0;
    virtual void println(int value, int base = DEC) = 0;
    ///@}

    virtual ~CW_Logger() {}
};

#endif // CW_LOGGER_H
