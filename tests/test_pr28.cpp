/*
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Cryptnox SA
 */

/* Host tests for the PR #28 review fixes: session clearing in aesCbcEncrypt(),
 * the getPublicKey() key-type allow-list and the Ed25519 applet check.
 *
 * Build and run from the repository root:
 *   g++ -std=c++17 -I. tests/test_pr28.cpp CryptnoxWallet.cpp CW_SecureChannel.cpp CW_Utils.cpp -o test_pr28 && ./test_pr28
 *
 * Fakes only: the reader answers SELECT with a chosen applet version and records
 * every other APDU; AES is a XOR "cipher" in CBC mode, which is enough for the
 * framing and failure paths tested here (no real card or crypto library). */

#include <stdio.h>
#include <stdlib.h>
#include "CryptnoxWallet.h"

/* Not assert(): it vanishes under NDEBUG and would skip the calls under test. */
#define CHECK(cond) do { if (!(cond)) { \
    printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); exit(1); } } while (0)

/******************************************************************
 * Fakes
 ******************************************************************/

class FakeNfc : public CW_NfcTransport {
public:
    uint8_t appletMajor = 2U;        /* version byte returned by SELECT */
    bool    sendOk = false;          /* result for every non-SELECT APDU */
    uint8_t resp[255] = { 0U };      /* response for every non-SELECT APDU */
    uint8_t respLen = 0U;
    unsigned sent = 0U;              /* non-SELECT APDUs sent */
    uint8_t last[255] = { 0U };      /* last non-SELECT APDU */

    bool begin() override { return true; }
    bool inListPassiveTarget() override { return true; }
    void resetReader() override { }
    bool printFirmwareVersion() override { return true; }

    bool sendAPDU(const uint8_t* apdu, uint8_t apduLen,
                  uint8_t* response, uint8_t& responseLen) override {
        if ((apdu[0] == 0x00U) && (apdu[1] == 0xA4U)) {
            const uint8_t sel[] = { 0x42U, appletMajor, 0x00U, 0x00U, 0x00U, 0x50U, 0x90U, 0x00U };
            memcpy(response, sel, sizeof(sel));
            responseLen = sizeof(sel);
            return true;
        }
        sent++;
        memcpy(last, apdu, apduLen);
        memcpy(response, resp, respLen);
        responseLen = respLen;
        return sendOk;
    }
};

class FakeCrypto : public CW_CryptoProvider {
public:
    bool failMacIv = false;   /* fail the 16-byte counter block encryption (v2 MAC IV) */
    bool failMac   = false;   /* fail the MAC computation itself */
    const uint8_t* sessionIv = NULL;   /* session.iv, to spot it being handed to the provider */
    bool gotSessionIv = false;         /* data encryption was given session.iv itself */

    bool sha256(const uint8_t*, size_t, uint8_t* out) override { memset(out, 0, 32); return true; }
    bool sha512(const uint8_t*, size_t, uint8_t* out) override { memset(out, 0, 64); return true; }
    bool ecdh(const uint8_t*, const uint8_t*, uint8_t* s, CW_Curve) override { memset(s, 1, 32); return true; }
    bool makeKey(uint8_t* pub, uint8_t* priv, CW_Curve) override { memset(pub, 2, 64); memset(priv, 3, 32); return true; }
    bool random(uint8_t* d, unsigned n) override { memset(d, 0x5A, n); return true; }
    bool ecdsaVerify(const uint8_t*, const uint8_t*, size_t, const uint8_t*, CW_Curve) override { return false; }

    uint16_t aesCbcEncrypt(const uint8_t* in, uint16_t len, uint8_t* out,
                           const uint8_t* key, uint8_t, uint8_t* iv, bool bitPadding) override {
        if (!bitPadding && (len == 16U) && failMacIv) { return 0U; }
        if (!bitPadding && (len > 16U) && failMac) { return 0U; }
        if (bitPadding && (iv == sessionIv)) { gotSessionIv = true; }
        uint8_t buf[512] = { 0U };
        memcpy(buf, in, len);
        uint16_t total = len;
        if (bitPadding) {
            buf[total++] = 0x80U;
            while ((total % 16U) != 0U) { buf[total++] = 0U; }
        }
        for (uint16_t b = 0U; b < total; b += 16U) {
            for (uint8_t i = 0U; i < 16U; i++) { iv[i] = (uint8_t)(buf[b + i] ^ iv[i] ^ key[i]); }
            memcpy(out + b, iv, 16U);
        }
        return total;
    }

    uint16_t aesCbcDecrypt(uint8_t* in, uint16_t len, uint8_t* out,
                           const uint8_t* key, uint8_t, uint8_t* iv, bool bitPadding) override {
        for (uint16_t b = 0U; b < len; b += 16U) {
            for (uint8_t i = 0U; i < 16U; i++) {
                out[b + i] = (uint8_t)(in[b + i] ^ key[i] ^ iv[i]);
                iv[i] = in[b + i];
            }
        }
        uint16_t n = len;
        if (bitPadding) {
            while ((n > 0U) && (out[n - 1U] == 0U)) { n--; }
            if ((n > 0U) && (out[n - 1U] == 0x80U)) { n--; }
        }
        return n;
    }
};

class NullLogger : public CW_Logger {
public:
    bool begin(unsigned long) override { return true; }
    void print(const __FlashStringHelper*) override { }
    void print(const char*) override { }
    void print(char) override { }
    void print(uint8_t, int) override { }
    void print(uint16_t, int) override { }
    void print(uint32_t, int) override { }
    void print(int, int) override { }
    void println() override { }
    void println(const __FlashStringHelper*) override { }
    void println(const char*) override { }
    void println(char) override { }
    void println(uint8_t, int) override { }
    void println(uint16_t, int) override { }
    void println(uint32_t, int) override { }
    void println(int, int) override { }
};

class NullPlatform : public CW_Platform {
public:
    void sleep_ms(uint32_t) override { }
};

static NullLogger   logger;
static NullPlatform platform;

static void openSession(CW_SecureSession& s) {
    s.clear();
    memset(s.aesKey, 0x11, sizeof(s.aesKey));
    memset(s.macKey, 0x22, sizeof(s.macKey));
    memset(s.iv,     0x33, sizeof(s.iv));
}

static bool isCleared(const CW_SecureSession& s) {
    uint8_t acc = 0U;
    for (uint8_t i = 0U; i < sizeof(s.aesKey); i++) { acc |= s.aesKey[i]; }
    for (uint8_t i = 0U; i < sizeof(s.macKey); i++) { acc |= s.macKey[i]; }
    return (acc == 0U) && (s.macCounter == 0U);
}

static const uint8_t HDR[] = { 0x80U, 0xCAU, 0x00U, 0x00U };
static const uint8_t DATA[] = { 1U, 2U, 3U };

/******************************************************************
 * aesCbcEncrypt(): which failures clear the session (review point 4)
 ******************************************************************/

/* Fresh fakes + a v2 channel + an open session for each case. */
struct Rig {
    FakeNfc nfc;
    FakeCrypto crypto;
    CW_SecureChannel ch;
    CW_SecureSession s;
    Rig() : ch(nfc, logger, crypto, platform) {
        CHECK(ch.selectApdu() && (ch.appletMajor() == 2U));
        openSession(s);
    }
    bool send(const uint8_t* data, uint16_t len) {
        return ch.aesCbcEncrypt(s, HDR, sizeof(HDR), data, len);
    }
};

static void check_session_clearing(void) {
    { /* Exhausted counter: cleared, nothing sent. */
        Rig r;
        r.s.macCounter = UINT32_MAX;
        CHECK(!r.send(DATA, sizeof(DATA)));
        CHECK(isCleared(r.s) && (r.nfc.sent == 0U));
    }
    { /* MAC IV derivation failure: cleared, nothing sent. */
        Rig r;
        r.crypto.failMacIv = true;
        CHECK(!r.send(DATA, sizeof(DATA)));
        CHECK(isCleared(r.s) && (r.nfc.sent == 0U));
    }
    { /* MAC computation failure: cleared, nothing sent. */
        Rig r;
        r.crypto.failMac = true;
        CHECK(!r.send(DATA, sizeof(DATA)));
        CHECK(isCleared(r.s) && (r.nfc.sent == 0U));
    }
    { /* Transport failure: cleared. */
        Rig r;
        CHECK(!r.send(DATA, sizeof(DATA)));
        CHECK(isCleared(r.s) && (r.nfc.sent == 1U));
    }
    { /* Bad response MAC (SW 9000, junk MAC): cleared. */
        Rig r;
        r.nfc.sendOk = true;
        memset(r.nfc.resp, 0xEEU, 32U);
        r.nfc.resp[32] = 0x90U;
        r.nfc.resp[33] = 0x00U;
        r.nfc.respLen = 34U;
        CHECK(!r.send(DATA, sizeof(DATA)));
        CHECK(isCleared(r.s));
    }
    { /* Bare error SW (unauthenticated, may be injected): cleared, so the next
       * command cannot go out with a stale IV. */
        Rig r;
        r.nfc.sendOk = true;
        r.nfc.resp[0] = 0x6FU;
        r.nfc.resp[1] = 0x00U;
        r.nfc.respLen = 2U;
        CHECK(!r.send(DATA, sizeof(DATA)));
        CHECK(isCleared(r.s));
    }
    { /* Response too short to hold an SW: cleared. */
        Rig r;
        r.nfc.sendOk = true;
        r.nfc.respLen = 1U;
        CHECK(!r.send(DATA, sizeof(DATA)));
        CHECK(isCleared(r.s));
    }
    { /* Oversized payload, rejected before anything is sent: session kept. */
        static const uint8_t big[CW_USER_DATA_PAGE_SIZE + 1U] = { 0U };
        Rig r;
        CHECK(!r.send(big, sizeof(big)));
        CHECK(!isCleared(r.s) && (r.s.macCounter == 0U) && (r.nfc.sent == 0U));
    }
    { /* The provider advances the IV it is given: it must get a copy, so
       * session.iv only moves after a verified response (M1). */
        Rig r;
        r.crypto.sessionIv = r.s.iv;
        (void)r.send(DATA, sizeof(DATA));
        CHECK(!r.crypto.gotSessionIv);
    }
}

/******************************************************************
 * getPublicKey(): key-type allow-list (review point 1)
 ******************************************************************/

static const uint8_t PATH[16] = {
    0x80U, 0x00U, 0x00U, 0x2CU, 0x80U, 0x00U, 0x01U, 0xF5U,
    0x80U, 0x00U, 0x00U, 0x00U, 0x80U, 0x00U, 0x00U, 0x00U
};

/* connect() fails after SELECT (the fake answers nothing else), which leaves the
 * wallet's applet version set; the session is then opened by hand. */
static void selectOnly(CryptnoxWallet& wallet, FakeNfc& nfc, CW_SecureSession& s) {
    const bool connected = wallet.connect(s);
    CHECK(!connected);
    nfc.sent = 0U;
}

static bool pathFor(uint8_t keyType) {
    return ((keyType & 0x0FU) == 1U) || ((keyType & 0x0FU) == 2U);
}

static void check_pubkey_allow_list(void) {
    FakeNfc nfc;
    FakeCrypto crypto;
    CryptnoxWallet wallet(nfc, logger, crypto, platform);
    CW_SecureSession s;
    selectOnly(wallet, nfc, s);

    uint8_t pk[65] = { 0U };
    uint16_t pkLen = 0U;

    /* Refused locally: derive-and-make-current, PIN-less, unknown curve. */
    const uint8_t refused[] = { 0x02U, 0x12U, 0x22U, 0x03U, 0x13U, 0x30U, 0x31U, 0xF0U };
    for (uint8_t i = 0U; i < sizeof(refused); i++) {
        const uint8_t t = refused[i];
        openSession(s);
        CHECK(!wallet.getPublicKey(s, t, pathFor(t) ? PATH : NULL, pathFor(t) ? sizeof(PATH) : 0U,
                                    pk, sizeof(pk), pkLen));
        CHECK((nfc.sent == 0U) && !isCleared(s));
    }

    /* Allowed: reaches the card with P1 = keyType (the fake then fails the exchange). */
    const uint8_t allowed[] = { CW_SIGN_CURR_K1, CW_SIGN_CURR_R1, CW_SIGN_DERIVE_K1,
                                CW_SIGN_DERIVE_R1, CW_SIGN_CURR_ED25519, CW_SIGN_DERIVE_ED25519 };
    for (uint8_t i = 0U; i < sizeof(allowed); i++) {
        const uint8_t t = allowed[i];
        openSession(s);
        nfc.sent = 0U;
        (void)wallet.getPublicKey(s, t, pathFor(t) ? PATH : NULL, pathFor(t) ? sizeof(PATH) : 0U,
                                  pk, sizeof(pk), pkLen);
        CHECK((nfc.sent == 1U) && (nfc.last[1] == 0xC2U) && (nfc.last[2] == t));
    }
}

/******************************************************************
 * Ed25519 needs applet 2.0+ (review point 2)
 ******************************************************************/

static CW_SignResult signWith(CryptnoxWallet& wallet, CW_SecureSession& s, uint8_t keyType) {
    static const uint8_t msg[32] = { 0x01U };
    CW_SignRequest req(s, keyType, CW_SIGN_SIG_ECDSA_LOW_S, CW_SIGN_WITH_PIN);
    req.hash = msg;
    req.hashLength = sizeof(msg);
    memcpy(req.pin, "000000000", 9U);
    return wallet.sign(req);
}

static void check_ed25519_applet_gate(void) {
    /* Applet 1.6.x: refused before anything is sent. */
    {
        uint8_t pk[65] = { 0U };
        uint16_t pkLen = 0U;
        FakeNfc nfc;
        nfc.appletMajor = 1U;
        FakeCrypto crypto;
        CryptnoxWallet wallet(nfc, logger, crypto, platform);
        CW_SecureSession s;
        selectOnly(wallet, nfc, s);

        openSession(s);
        CHECK(!wallet.getPublicKey(s, CW_SIGN_CURR_ED25519, NULL, 0U, pk, sizeof(pk), pkLen));
        CHECK(nfc.sent == 0U);

        openSession(s);
        CHECK(signWith(wallet, s, CW_SIGN_CURR_ED25519).errorCode == CW_SIGN_UNSUPPORTED_KEY_TYPE);
        CHECK(nfc.sent == 0U);

        /* k1 is not affected. */
        openSession(s);
        (void)signWith(wallet, s, CW_SIGN_CURR_K1);
        CHECK(nfc.sent == 1U);
    }

    /* Applet 2.x: sent, with P2 forced to EdDSA whatever signatureType says. */
    {
        FakeNfc nfc;
        FakeCrypto crypto;
        CryptnoxWallet wallet(nfc, logger, crypto, platform);
        CW_SecureSession s;
        selectOnly(wallet, nfc, s);

        openSession(s);
        CHECK(signWith(wallet, s, CW_SIGN_CURR_ED25519).errorCode != CW_SIGN_UNSUPPORTED_KEY_TYPE);
        CHECK((nfc.sent == 1U) && (nfc.last[1] == 0xC0U) &&
               (nfc.last[2] == CW_SIGN_CURR_ED25519) && (nfc.last[3] == CW_SIGN_SIG_EDDSA));
    }
}

int main(void) {
    check_session_clearing();
    check_pubkey_allow_list();
    check_ed25519_applet_gate();
    printf("test_pr28: OK\n");
    return 0;
}
