/*
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Cryptnox SA
 */

/*
 * fuzz_der.cpp — libFuzzer harness for the two DER parser paths in
 *                CW_SecureChannel (SEC-015).
 *
 * Targets:
 *   derWalkMfCert()                   file-static DER X.509 cert walker
 *   CW_SecureChannel::parseDerSigToRaw()  private-static DER sig parser
 *
 * Build (Linux / macOS, clang required):
 *   cd cryptnox-sdk-cpp/fuzz
 *   mkdir build && cd build
 *   cmake .. -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
 *   make
 *
 * Run:
 *   ./fuzz_der corpus/ -max_len=512 -jobs=4
 *
 * Corpus seeds:
 *   Place valid DER ECDSA signatures and manufacturer certificate blobs
 *   inside corpus/.  See corpus/README.md for instructions.
 *
 * Input format (first byte selects target):
 *   0x00 + <bytes>  → parseDerSigToRaw only
 *   0x01 + <bytes>  → derWalkMfCert only
 *   anything else   → both parsers receive the same payload
 */

/* Must be defined before including CW_SecureChannel.h so the friend
 * declaration for DerFuzzTarget is compiled in.                        */
#define CW_FUZZ_BUILD 1

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ── SDK headers ────────────────────────────────────────────────────── */
#include "../CW_CryptoProvider.h"
#include "../CW_NfcTransport.h"
#include "../CW_Logger.h"
#include "../CW_Platform.h"
#include "../CW_SecureChannel.h"

/* ── Minimal concrete stubs for the three abstract interfaces ──────────
 * Required so CW_SecureChannel.cpp compiles; these methods are never
 * reached from the DER-parser call paths exercised by this harness.    */

class StubNfc final : public CW_NfcTransport {
public:
    bool begin() override { return false; }
    bool inListPassiveTarget() override { return false; }
    bool sendAPDU(const uint8_t*, uint8_t,
                  uint8_t*, uint8_t&) override { return false; }
    void resetReader() override {}
    bool printFirmwareVersion() override { return false; }
};

class StubLogger final : public CW_Logger {
public:
    bool begin(unsigned long) override { return true; }
    void print(const __FlashStringHelper*) override {}
    void print(const char*) override {}
    void print(char) override {}
    void print(uint8_t, int) override {}
    void print(uint16_t, int) override {}
    void print(uint32_t, int) override {}
    void print(int, int) override {}
    void println() override {}
    void println(const __FlashStringHelper*) override {}
    void println(const char*) override {}
    void println(char) override {}
    void println(uint8_t, int) override {}
    void println(uint16_t, int) override {}
    void println(uint32_t, int) override {}
    void println(int, int) override {}
};

class StubCrypto final : public CW_CryptoProvider {
public:
    bool sha256(const uint8_t*, size_t, uint8_t*) override { return false; }
    bool sha512(const uint8_t*, size_t, uint8_t*) override { return false; }
    uint16_t aesCbcEncrypt(const uint8_t*, uint16_t, uint8_t*,
                           const uint8_t*, uint8_t,
                           uint8_t*, bool) override { return 0U; }
    uint16_t aesCbcDecrypt(uint8_t*, uint16_t, uint8_t*,
                           const uint8_t*, uint8_t,
                           uint8_t*, bool) override { return 0U; }
    bool ecdh(const uint8_t*, const uint8_t*, uint8_t*,
              CW_Curve) override { return false; }
    bool makeKey(uint8_t*, uint8_t*,
                 CW_Curve) override { return false; }
    bool random(uint8_t*, unsigned) override { return false; }
    bool ecdsaVerify(const uint8_t*, const uint8_t*, size_t,
                     const uint8_t*, CW_Curve) override { return false; }
};

class StubPlatform final : public CW_Platform {
public:
    void sleep_ms(uint32_t) override {}
};

/* ── CW_Utils::fill_secure_random stub ─────────────────────────────────
 * The real implementation is ESP32-specific (esp32_random.cpp).
 * The DER parsers never call this; the stub exists only for the linker. */
bool CW_Utils::fill_secure_random(uint8_t* dest, size_t len) {
    if ((dest != NULL) && (len > 0U)) {
        memset(dest, 0xA5U, len);
    }
    return true;
}

/* ── Pull in the production code under test ─────────────────────────── */
#include "../CW_Utils.cpp"
#include "../CW_SecureChannel.cpp"

/* ── DerFuzzTarget: bridge from friend to private parseDerSigToRaw ──── */
struct DerFuzzTarget {
    static bool parseDerSigToRaw(const uint8_t* der,
                                 uint8_t derLen,
                                 uint8_t* raw64) {
        return CW_SecureChannel::parseDerSigToRaw(der, derLen, raw64);
    }
};

/* ── libFuzzer entry point ─────────────────────────────────────────── */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1U) {
        return 0;
    }

    const uint8_t  selector    = data[0];
    const uint8_t* payload     = data + 1U;
    const size_t   payloadSize = size - 1U;

    /* ── Target A: parseDerSigToRaw ─────────────────────────────────── */
    if ((selector == 0x00U) || (selector > 0x01U)) {
        uint8_t raw64[64U] = { 0U };
        uint8_t derLen = (payloadSize <= 255U)
                             ? static_cast<uint8_t>(payloadSize)
                             : 255U;
        (void)DerFuzzTarget::parseDerSigToRaw(payload, derLen, raw64);
    }

    /* ── Target B: derWalkMfCert ────────────────────────────────────── */
    if ((selector == 0x01U) || (selector > 0x01U)) {
        uint16_t       tbsMsgStart = 0U;
        uint16_t       tbsMsgLen   = 0U;
        const uint8_t* pubKey65Ptr = NULL;
        const uint8_t* sigPtr      = NULL;
        uint8_t        sigLen      = 0U;
        uint16_t bufLen = (payloadSize <= 0xFFFFU)
                              ? static_cast<uint16_t>(payloadSize)
                              : 0xFFFFU;
        (void)derWalkMfCert(payload, bufLen,
                            tbsMsgStart, tbsMsgLen,
                            pubKey65Ptr, sigPtr, sigLen);
    }

    return 0;
}
