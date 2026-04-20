#ifndef PLATFORM_COMPAT_H
#define PLATFORM_COMPAT_H

/**
 * @file platform_compat.h
 * @brief Arduino compatibility shims for non-Arduino (plain C++) builds.
 *
 * Include this file instead of <Arduino.h> in platform-independent headers.
 * When building for Arduino, ARDUINO is already defined by the toolchain and
 * this file is a no-op — Arduino.h has already provided all these definitions.
 * When building outside Arduino (desktop, ESP-IDF, CI) this file provides the
 * minimum set of defines/types needed so the SDK headers compile cleanly.
 */

#ifndef ARDUINO
#  include <stdint.h>
#  include <stddef.h>
#  include <string.h>
#  include <stdbool.h>

/* Numeric base constants used as default arguments in CW_Logger. */
#  define DEC  10
#  define HEX  16
#  define OCT   8
#  define BIN   2

/* Flash-string helper type: on Arduino, F("...") returns a pointer to this
 * class so that print() overloads can distinguish ROM from RAM strings.
 * On non-Arduino it is a dummy empty class; F() is the identity macro so
 * F("foo") just returns a plain const char*, which resolves to the
 * print(const char*) overload. */
class __FlashStringHelper {};
#  define F(string_literal) (string_literal)

/* delay() is an Arduino built-in. On non-Arduino targets it is a no-op so
 * that CryptnoxWallet::connect()'s retry logic still compiles. Platforms that
 * need real sleeping should provide their own implementation before including
 * this header. */
#  ifndef delay
static inline void delay(unsigned long /*ms*/) {}
#  endif

#endif /* !ARDUINO */

#endif /* PLATFORM_COMPAT_H */
