<div align="center">

<img src="https://github.com/user-attachments/assets/6ce54a27-8fb6-48e6-9d1f-da144f43425a"/>

### cryptnox-sdk-cpp

Platform-independent C++ core SDK for Cryptnox Hardware Wallet

</div>

<br/>
<br/>

[![Static analysis](https://github.com/embarquech/cryptnox-sdk-cpp/actions/workflows/static_analysis.yml/badge.svg)](https://github.com/embarquech/cryptnox-sdk-cpp/actions/workflows/static_analysis.yml)
[![Standard: C++17](https://img.shields.io/badge/Standard-C%2B%2B17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![License: LGPLv3](https://img.shields.io/badge/License-LGPLv3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)

`cryptnox-sdk-cpp` is the **shared C++ core SDK** for the **Cryptnox Hardware Wallet**. It implements the
card-side protocol — secure channel establishment (SELECT → certificate → ECDH → mutual auth),
APDU framing, PIN verification, signing, and user-data writing — independently of any target
platform, NFC reader, or crypto library.

> [!IMPORTANT]
> **This SDK is not usable on its own.** It exposes three abstract interfaces
> (`CW_NfcTransport`, `CW_CryptoProvider`, `CW_Logger`) that **must be implemented by a host
> integration**. It ships no transport driver, no crypto backend, and no logging output.

---

## Used by

This core is consumed as a submodule by the platform-specific SDKs:

| Integration | Repository |
|-------------|------------|
| ESP32-S3 (ESP-IDF v5.5) | [`embarquech/cryptnox-sdk-esp32`](https://github.com/embarquech/cryptnox-sdk-esp32) |
| Arduino R4 (Renesas RA4M1) | [`embarquech/cryptnox-sdk-arduino`](https://github.com/embarquech/cryptnox-sdk-arduino) |

If you want to talk to a Cryptnox card on real hardware, **start from one of those repositories**.

---

## Porting to a new platform

This repository is intended as the **starting point for porting the SDK to a new platform**
(another MCU family, a desktop OS, a different NFC reader, a different crypto backend, etc.).

A port consists of providing concrete implementations of the three adapter interfaces:

| Interface | What you must provide |
|-----------|-----------------------|
| `CW_NfcTransport`   | Driver for your NFC reader (PN532, PN7150, PC/SC, …) |
| `CW_CryptoProvider` | SHA-256/512, AES-CBC, ECDH, EC key generation, RNG (mbedTLS, BearSSL, OpenSSL, hardware peripheral, …) |
| `CW_Logger`         | Output sink (UART, stdout, syslog, network, …) |

Then drop this repository in as a submodule (or copy of its sources) inside your project, build
it together with your adapters, and instantiate `CryptnoxWallet` with the three injected
dependencies. The existing platform SDKs (`cryptnox-sdk-esp32`, `cryptnox-sdk-arduino`) are
useful references for a complete port.

---

## What's inside

| File | Role |
|------|------|
| `CryptnoxWallet.{h,cpp}`        | High-level API: `begin`, `connect`, `verifyPin`, `sign`, `writeUserData`, `disconnect` |
| `CW_SecureChannel.{h,cpp}`      | Secure channel protocol (mutual auth, session keys, encrypted APDU exchange) |
| `CW_NfcTransport.h`             | **Adapter interface** — NFC reader contract |
| `CW_CryptoProvider.h`           | **Adapter interface** — SHA-256/512, AES-CBC, ECDH, EC keygen, RNG |
| `CW_Logger.h`                   | **Adapter interface** — debug/serial output |
| `CW_TrustedKeys.h`              | Cryptnox CA public keys used to verify card certificates |
| `CW_Defs.h`, `CW_Utils.{h,cpp}` | Constants, error codes, small helpers |
| `platform_compat.h`             | Shim for non-Arduino targets |

The three adapter interfaces are the only contract a host must satisfy. Everything else is
self-contained.

---

## Integrating the core

A host integration injects its three adapters into `CryptnoxWallet`:

```cpp
#include "CryptnoxWallet.h"

// MyXxx = concrete adapters provided by the platform SDK:
//   - MyNfcTransport   : public CW_NfcTransport
//   - MyCryptoProvider : public CW_CryptoProvider
//   - MyLogger         : public CW_Logger

MyLogger          logger;
MyCryptoProvider  crypto;
MyNfcTransport    transport(/* platform-specific args */);
CryptnoxWallet    wallet(transport, logger, crypto);

if (!wallet.begin()) { /* reader init failed */ }

CW_SecureSession session;
if (wallet.connect(session)) {
    // wallet.verifyPin(...), wallet.sign(...), wallet.writeUserData(...)
    wallet.disconnect(session);
}
```

Full runnable examples (PIN verify, transaction signing, full ESP-IDF / Arduino boilerplate)
live in the platform SDKs linked above.

---

## Building standalone

There is **no standalone build target** in this repository. The CI workflow runs `cppcheck`
static analysis only (`.github/workflows/static_analysis.yml`); host-supplied headers
(`uECC.h`, `mbedtls/*`, platform logger) are not vendored, so `missingInclude` is suppressed.

To compile and exercise the code, use one of the platform SDKs.

---

## Documentation

The generated documentation for this project is available [here](https://embarquech.github.io/cryptnox-sdk-cpp/).

---

## License

`cryptnox-sdk-cpp` is dual-licensed:

- **LGPL-3.0** for open-source projects and proprietary projects that comply with LGPL requirements
- **Commercial license** for projects that require a proprietary license without LGPL obligations

For commercial inquiries, contact: contact@cryptnox.com
