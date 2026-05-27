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
