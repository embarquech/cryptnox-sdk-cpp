# Third-party notices

`cryptnox-sdk-cpp` is the platform-independent C++ core SDK for the
Cryptnox smart-card wallet. It is distributed under a dual LGPL-3.0 /
commercial license (see [LICENSE](LICENSE) and [COMMERCIAL.md](COMMERCIAL.md)).

---

## Scope

All source files in this repository (`CryptnoxWallet.*`,
`CW_SecureChannel.*`, `CW_Utils.*`, `CW_Defs.h`, `CW_CryptoProvider.h`,
`CW_Logger.h`, `CW_NfcTransport.h`, `CW_Platform.h`, `CW_TrustedKeys.h`,
`platform_compat.h`, and the fuzz harness under `fuzz/`) are
first-party work, © Cryptnox SA, LGPL-3.0-or-later. Every translation
unit declares its license explicitly via an `SPDX-License-Identifier:
LGPL-3.0-or-later` header.

This SDK depends on:

- A platform-supplied **crypto provider** implementing the
  `CW_CryptoProvider` interface (SHA-256/SHA-512, AES-CBC, ECDH,
  ECDSA, RNG). On Arduino, that role is filled by `micro-ecc`,
  `AESLib` and `Crypto`; on ESP-IDF, by mbedTLS through a thin
  shim. Those libraries carry their own licenses and are not
  redistributed by this SDK.
- A platform-supplied **NFC transport** implementing
  `CW_NfcTransport` (typically wrapping an NXP PN532 driver).

Final-product distributions that bundle a compiled artefact must
include the licenses of these platform components alongside the
LGPL-3.0 grant for `cryptnox-sdk-cpp`.

---

## No ported third-party code

No file in this repository is ported, adapted, or otherwise derived
from a third-party source. If a file ever incorporates upstream code,
the upstream copyright notice and license terms must be reproduced
here and in the file header.
