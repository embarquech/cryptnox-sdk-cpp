/*
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Cryptnox SA
 */

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

#ifdef ARDUINO
/* On Arduino, pull in Arduino.h so SDK headers that reference __FlashStringHelper,
 * DEC/HEX/OCT/BIN, F(), or delay() compile regardless of whether the including
 * translation unit already included <Arduino.h>. Arduino.h transitively provides
 * <stdint.h>, <stddef.h>, <string.h>, etc., so no need to include them here. */
#  include <Arduino.h>
#else
/* Off Arduino, include the C standard headers explicitly so the SDK compiles
 * without depending on what the including TU may or may not have pulled in. */
#  include <stdint.h>
#  include <stddef.h>
#  include <string.h>
#  include <stdbool.h>

#  define DEC  10
#  define HEX  16
#  define OCT   8
#  define BIN   2

/* F("...") on Arduino returns __FlashStringHelper* to keep string literals in
 * flash.  On non-Arduino it is the identity macro, resolving to const char*. */
class __FlashStringHelper {};
#  define F(string_literal) (string_literal)

#endif /* ARDUINO / !ARDUINO */

#endif /* PLATFORM_COMPAT_H */
