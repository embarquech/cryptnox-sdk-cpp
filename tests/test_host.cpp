/*
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 Cryptnox SA
 */

/* Host tests: session clearing in aesCbcEncrypt(), the getPublicKey() and sign()
 * request checks, the Ed25519 applet check, and the security-notes fixes
 * (M1-M5, L6, L10-L15).
 *
 * Build and run from the repository root:
 *   g++ -std=c++17 -I. tests/test_host.cpp CryptnoxWallet.cpp CW_SecureChannel.cpp CW_Utils.cpp -o test_host && ./test_host
 *
 * Fakes only: the reader answers SELECT with a chosen applet version and records
 * every other APDU; AES is a XOR "cipher" in CBC mode, which is enough for the
 * framing and failure paths tested here (no real card or crypto library). With
 * wrapped = true the reader answers like a 2.x card: a MAC-valid encrypted
 * response carrying payload || innerSw. */

#include <stdio.h>
#include <stdlib.h>
#include <type_traits>
#include "CryptnoxWallet.h"

/* L12: copies of Kenc / Kmac must not be possible. */
static_assert(!std::is_copy_constructible<CW_SecureSession>::value, "CW_SecureSession must not be copyable");
static_assert(!std::is_copy_assignable<CW_SecureSession>::value, "CW_SecureSession must not be assignable");

/* Not assert(): it vanishes under NDEBUG and would skip the calls under test. */
#define CHECK(cond) do { if (!(cond)) { \
    printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); exit(1); } } while (0)

/******************************************************************
 * Fakes
 ******************************************************************/

/* The fake "AES": CBC over block = in ^ iv ^ key, with optional bit padding. */
static uint16_t xorCbc(const uint8_t* in, uint16_t len, uint8_t* out,
                       const uint8_t* key, uint8_t* iv, bool bitPadding) {
    uint8_t buf[512] = { 0U };
    if (len > 0U) { memcpy(buf, in, len); }   /* in may be NULL for an empty payload */
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

/* Session keys set by openSession() below. */
static const uint8_t KENC = 0x11U;
static const uint8_t KMAC = 0x22U;

class FakeNfc : public CW_NfcTransport {
public:
    uint8_t appletMajor = 2U;        /* version byte returned by SELECT */
    uint8_t selectOverReport = 0U;   /* non-zero: SELECT reports this length (M3) */
    uint8_t overReport = 0U;         /* non-zero: other APDUs report this length, writing only respLen (M3) */
    uint8_t lastRespMac[16] = { 0U };/* first 16 bytes of the last wrapped response (its MAC) */
    bool    sendOk = false;          /* result for every non-SELECT APDU */
    uint8_t resp[255] = { 0U };      /* response for every non-SELECT APDU */
    uint8_t respLen = 0U;
    unsigned sent = 0U;              /* non-SELECT APDUs sent */
    uint8_t last[255] = { 0U };      /* last non-SELECT APDU */
    uint8_t lastLen = 0U;

    bool     wrapped = false;        /* answer as a 2.x card: resp[0..respLen) || innerSw, MAC'd */
    uint16_t innerSw = 0x9000U;
    uint32_t ctr = 0U;               /* MAC counter, in step with a hand-opened session */

    bool begin() override { return true; }
    bool inListPassiveTarget() override { return true; }
    void resetReader() override { }
    bool printFirmwareVersion() override { return true; }

    bool sendAPDU(const uint8_t* apdu, uint8_t apduLen,
                  uint8_t* response, uint8_t& responseLen) override {
        if ((apdu[0] == 0x00U) && (apdu[1] == 0xA4U)) {
            const uint8_t sel[] = { 0x42U, appletMajor, 0x00U, 0x00U, 0x00U, 0x50U, 0x90U, 0x00U };
            memcpy(response, sel, sizeof(sel));
            responseLen = (selectOverReport != 0U) ? selectOverReport : (uint8_t)sizeof(sel);
            return true;
        }
        sent++;
        memcpy(last, apdu, apduLen);
        lastLen = apduLen;
        if (wrapped) {
            ctr++;
            wrap(apdu + 5U, response, responseLen);
            memcpy(lastRespMac, response, 16U);
            return true;
        }
        memcpy(response, resp, respLen);
        responseLen = (overReport != 0U) ? overReport : respLen;
        return sendOk;
    }

private:
    /* MAC(16) || E_Kenc(payload || SW, IV = request MAC) || 90 00, the MAC being
     * CBC-MAC_Kmac([len block] || cipher) with IV = E_Kmac(counter block). */
    void wrap(const uint8_t* reqMac, uint8_t* response, uint8_t& responseLen) {
        uint8_t kenc[32] = { 0U }, kmac[32] = { 0U };
        memset(kenc, KENC, sizeof(kenc));
        memset(kmac, KMAC, sizeof(kmac));

        uint8_t plain[256] = { 0U };
        memcpy(plain, resp, respLen);
        plain[respLen] = (uint8_t)(innerSw >> 8);
        plain[respLen + 1U] = (uint8_t)innerSw;
        uint8_t iv[16] = { 0U };
        memcpy(iv, reqMac, 16U);
        uint8_t cipher[256] = { 0U };
        const uint16_t clen = xorCbc(plain, (uint16_t)(respLen + 2U), cipher, kenc, iv, true);

        uint8_t ctrBlock[16] = { 0U }, zero[16] = { 0U }, macIv[16] = { 0U };
        ctrBlock[12] = (uint8_t)(ctr >> 24); ctrBlock[13] = (uint8_t)(ctr >> 16);
        ctrBlock[14] = (uint8_t)(ctr >> 8);  ctrBlock[15] = (uint8_t)ctr;
        (void)xorCbc(ctrBlock, 16U, macIv, kmac, zero, false);

        uint8_t macIn[272] = { 0U }, macOut[272] = { 0U };
        macIn[0] = (uint8_t)(16U + clen);
        memcpy(macIn + 16, cipher, clen);
        (void)xorCbc(macIn, (uint16_t)(16U + clen), macOut, kmac, macIv, false);

        memcpy(response, macOut + clen, 16U);   /* last block of the chain */
        memcpy(response + 16, cipher, clen);
        response[16U + clen] = 0x90U;
        response[17U + clen] = 0x00U;
        responseLen = (uint8_t)(18U + clen);
    }
};

class FakeCrypto : public CW_CryptoProvider {
public:
    bool failMacIv = false;   /* fail the 16-byte counter block encryption (v2 MAC IV) */
    bool failMac   = false;   /* fail the MAC computation itself */
    bool failEnc   = false;   /* fail the data encryption (bit padding) */
    bool failEcdh  = false;
    const uint8_t* sessionIv = NULL;   /* session.iv, to spot it being handed to the provider */
    bool gotSessionIv = false;         /* data encryption was given session.iv itself */

    bool sha256(const uint8_t*, size_t, uint8_t* out) override { memset(out, 0, 32); return true; }
    bool sha512(const uint8_t*, size_t, uint8_t* out) override { memset(out, 0, 64); return true; }
    bool ecdh(const uint8_t*, const uint8_t*, uint8_t* s, CW_Curve) override { memset(s, 1, 32); return !failEcdh; }
    bool makeKey(uint8_t* pub, uint8_t* priv, CW_Curve) override { memset(pub, 2, 64); memset(priv, 3, 32); return true; }
    bool random(uint8_t* d, unsigned n) override { memset(d, 0x5A, n); return true; }
    bool ecdsaVerify(const uint8_t*, const uint8_t*, size_t, const uint8_t*, CW_Curve) override { return false; }

    uint16_t aesCbcEncrypt(const uint8_t* in, uint16_t len, uint8_t* out,
                           const uint8_t* key, uint8_t, uint8_t* iv, bool bitPadding) override {
        if (!bitPadding && (len == 16U) && failMacIv) { return 0U; }
        if (!bitPadding && (len > 16U) && failMac) { return 0U; }
        if (bitPadding && (iv == sessionIv)) { gotSessionIv = true; }
        if (bitPadding && failEnc) { return 0U; }
        return xorCbc(in, len, out, key, iv, bitPadding);
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
    memset(s.aesKey, KENC, sizeof(s.aesKey));
    memset(s.macKey, KMAC, sizeof(s.macKey));
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
    { /* Data encryption failure, before the counter advances: session kept, nothing sent. */
        Rig r;
        r.crypto.failEnc = true;
        CHECK(!r.send(DATA, sizeof(DATA)));
        CHECK(!isCleared(r.s) && (r.s.macCounter == 0U) && (r.nfc.sent == 0U));
    }
    { /* Header that is not CLA INS P1 P2: refused, session kept, nothing sent. */
        Rig r;
        CHECK(!r.ch.aesCbcEncrypt(r.s, HDR, 3U, DATA, sizeof(DATA)));
        CHECK(!isCleared(r.s) && (r.nfc.sent == 0U));
    }
    { /* Response ciphertext not a whole number of blocks (16 + 17 + SW): cleared. */
        Rig r;
        r.nfc.sendOk = true;
        memset(r.nfc.resp, 0xEEU, 33U);
        r.nfc.resp[33] = 0x90U;
        r.nfc.resp[34] = 0x00U;
        r.nfc.respLen = 35U;
        CHECK(!r.send(DATA, sizeof(DATA)));
        CHECK(isCleared(r.s));
    }
}

/******************************************************************
 * M1: rolling IV only moves on a verified response
 ******************************************************************/

static void check_rolling_iv(void) {
    { /* The provider advances the IV it is given: it must get a copy. */
        Rig r;
        r.crypto.sessionIv = r.s.iv;
        (void)r.send(DATA, sizeof(DATA));
        CHECK(!r.crypto.gotSessionIv);
    }
    { /* Verified exchanges: IV = the response MAC, counter +1 each time. */
        Rig r;
        r.nfc.wrapped = true;
        for (uint32_t n = 1U; n <= 3U; n++) {
            CHECK(r.send(DATA, sizeof(DATA)));
            CHECK((r.s.macCounter == n) && (memcmp(r.s.iv, r.nfc.lastRespMac, 16U) == 0));
            CHECK(r.ch.lastCardSw() == 0x9000U);
        }
    }
}

/******************************************************************
 * M5: lastCardSw()
 ******************************************************************/

static void check_last_card_sw(void) {
    { /* Authenticated inner SW. */
        Rig r;
        r.nfc.wrapped = true;
        r.nfc.innerSw = 0x63C1U;
        CHECK(!r.send(DATA, sizeof(DATA)) && (r.ch.lastCardSw() == 0x63C1U));
    }
    { /* Bare SW. */
        Rig r;
        r.nfc.sendOk = true;
        r.nfc.resp[0] = 0x6AU; r.nfc.resp[1] = 0x82U; r.nfc.respLen = 2U;
        CHECK(!r.send(DATA, sizeof(DATA)) && (r.ch.lastCardSw() == 0x6A82U));
    }
    { /* No answer: 0, and a stale value from the previous call is reset. */
        Rig r;
        r.nfc.wrapped = true;
        CHECK(r.send(DATA, sizeof(DATA)) && (r.ch.lastCardSw() == 0x9000U));
        openSession(r.s);
        r.nfc.wrapped = false;
        CHECK(!r.send(DATA, sizeof(DATA)) && (r.ch.lastCardSw() == 0U));
    }
}

/******************************************************************
 * L3: ECDH failure clears the session
 ******************************************************************/

static void check_mutual_auth_ecdh_failure(void) {
    Rig r;
    r.crypto.failEcdh = true;
    const uint8_t salt[32] = { 0U }, priv[32] = { 0U }, cardKey[64] = { 0U };
    uint8_t pub[64] = { 0U };
    CHECK(!r.ch.mutuallyAuthenticate(r.s, salt, pub, priv, CW_CURVE_SECP256R1, cardKey));
    CHECK(isCleared(r.s) && (r.nfc.sent == 0U));
}

/******************************************************************
 * L18: safe_memcpy
 ******************************************************************/

static void check_safe_memcpy(void) {
    uint8_t buf[32] = { 0U };
    const uint8_t src[8] = { 1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U };
    CHECK(CW_Utils::safe_memcpy(buf, sizeof(buf), src, sizeof(src)) && (buf[7] == 8U));
    CHECK(!CW_Utils::safe_memcpy(buf, 4U, src, sizeof(src)));            /* too large */
    CHECK(!CW_Utils::safe_memcpy(buf + 4, 8U, buf, 8U));                  /* overlap */
    CHECK(!CW_Utils::safe_memcpy(buf, 8U, buf + 4, 8U));                  /* overlap */
    CHECK(CW_Utils::safe_memcpy(buf + 8, 8U, buf, 8U) && (buf[15] == 8U)); /* adjacent */
    CHECK(!CW_Utils::safe_memcpy(NULL, 8U, src, 8U) && !CW_Utils::safe_memcpy(buf, 8U, NULL, 8U));
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

/******************************************************************
 * Security notes
 ******************************************************************/

/* A wallet whose reader answers like a 2.x card, with the session opened by hand. */
struct WalletRig {
    FakeNfc nfc;
    FakeCrypto crypto;
    CryptnoxWallet wallet;
    CW_SecureSession s;
    WalletRig() : wallet(nfc, logger, crypto, platform) {
        selectOnly(wallet, nfc, s);
        openSession(s);
        nfc.wrapped = true;
    }
};

static const uint8_t DIGEST[32] = {
    0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U,
    0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU, 0x10U,
    0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U, 0x18U,
    0x19U, 0x1AU, 0x1BU, 0x1CU, 0x1DU, 0x1EU, 0x1FU, 0x20U
};

/* Decrypt the data field of the last wrapped command (IV 0x33.., Kenc). */
static uint16_t lastPlain(const FakeNfc& nfc, uint8_t* out) {
    const uint8_t* c = nfc.last + 5U + 16U;           /* after header, Lc, MAC */
    const uint16_t clen = (uint16_t)(nfc.lastLen - 21U);
    uint8_t prev[16] = { 0U };
    memset(prev, 0x33, sizeof(prev));
    for (uint16_t b = 0U; b < clen; b += 16U) {
        for (uint8_t i = 0U; i < 16U; i++) { out[b + i] = (uint8_t)(c[b + i] ^ KENC ^ prev[i]); }
        memcpy(prev, c + b, 16U);
    }
    return clen;
}

static void check_parsers(void) {   /* M4, L6 */
    uint8_t raw[64] = { 0U };
    uint8_t r[33] = { 0U }, s[33] = { 0U }, rl = 0U, sl = 0U;

    const uint8_t ok[] = { 0x30U, 0x06U, 0x02U, 0x01U, 0x05U, 0x02U, 0x01U, 0x07U };
    CHECK(CW_SecureChannel::parseDerSigToRaw(ok, sizeof(ok), raw) && (raw[31] == 5U) && (raw[63] == 7U));
    CHECK(CryptnoxWallet::parseDerSignature(ok, sizeof(ok), r, rl, s, sl) && (rl == 1U) && (sl == 1U));

    const uint8_t zero[] = { 0x30U, 0x06U, 0x02U, 0x01U, 0x00U, 0x02U, 0x01U, 0x00U };   /* r = s = 0 */
    const uint8_t sZero[] = { 0x30U, 0x06U, 0x02U, 0x01U, 0x05U, 0x02U, 0x01U, 0x00U };
    const uint8_t empty[] = { 0x30U, 0x07U, 0x02U, 0x00U, 0x02U, 0x01U, 0x07U, 0x00U, 0x00U };
    uint8_t long33[2U + 35U + 3U] = { 0x30U, 38U, 0x02U, 33U, 0x7FU };       /* 33 bytes, no 0x00 pad */
    long33[2U + 35U] = 0x02U; long33[2U + 36U] = 0x01U; long33[2U + 37U] = 0x07U;
    const uint8_t noSLen[] = { 0x30U, 0x06U, 0x02U, 0x01U, 0x05U, 0x02U };    /* s length byte missing */
    const uint8_t trailing[] = { 0x30U, 0x07U, 0x02U, 0x01U, 0x05U, 0x02U, 0x01U, 0x07U, 0xEEU };

    const uint8_t* bad[] = { zero, sZero, empty, long33, noSLen, trailing };
    const uint8_t badLen[] = { sizeof(zero), sizeof(sZero), sizeof(empty), sizeof(long33),
                               sizeof(noSLen), sizeof(trailing) };
    for (uint8_t i = 0U; i < 6U; i++) {
        memset(raw, 0xAAU, sizeof(raw));
        CHECK(!CW_SecureChannel::parseDerSigToRaw(bad[i], badLen[i], raw));
        CHECK(raw[0] == 0U);   /* zeroed on failure */
    }
    for (uint8_t i = 0U; i < 5U; i++) {   /* the public parser does not police the SEQUENCE end */
        CHECK(!CryptnoxWallet::parseDerSignature(bad[i], badLen[i], r, rl, s, sl));
    }
}

static void check_transport_overreport(void) {   /* M3 */
    FakeNfc nfc;
    FakeCrypto crypto;
    CW_SecureChannel ch(nfc, logger, crypto, platform);
    nfc.selectOverReport = 200U;   /* more than the 40-byte SELECT buffer */
    CHECK(!ch.selectApdu());

    /* Same for GET CARD CERTIFICATE (148 B) and OPEN SECURE CHANNEL (34 B):
     * the reported length is refused, never used to index the buffer. */
    Rig r;
    r.nfc.sendOk = true;
    r.nfc.resp[0] = 0x90U; r.nfc.resp[1] = 0x00U; r.nfc.respLen = 2U;
    r.nfc.overReport = 200U;
    uint8_t cert[146] = { 0U };
    uint8_t certLen = 0U;
    CHECK(!r.ch.getCardCertificate(cert, certLen));
    uint8_t salt[32] = { 0U }, pub[64] = { 0U }, priv[32] = { 0U };
    CHECK(!r.ch.openSecureChannel(salt, pub, priv, CW_CURVE_SECP256R1));
}

static void check_sign_requests(void) {   /* M2, L10, L11, L13 */
    { /* Stale bytes after the PIN terminator are not sent. */
        WalletRig w;
        CW_SignRequest req(w.s);
        req.hash = DIGEST; req.hashLength = 32U;
        memcpy(req.pin, "1234\0" "6789", 9U);
        (void)w.wallet.sign(req);
        CHECK(w.nfc.sent == 1U);
        uint8_t plain[256] = { 0U };
        (void)lastPlain(w.nfc, plain);
        CHECK(memcmp(plain, DIGEST, 32U) == 0);
        CHECK(memcmp(plain + 32, "1234\0\0\0\0\0", 9U) == 0);
        uint8_t zeros[9] = { 0U };
        CHECK(memcmp(req.pin, zeros, sizeof(zeros)) == 0);   /* L13: wiped by sign() */
    }

    struct Bad { uint8_t keyType; uint8_t sigType; bool pinless; uint8_t hashLen; bool path; const char* pin; uint8_t code; };
    const Bad bad[] = {
        { CW_SIGN_CURR_K1,   0U, false, 23U, false, "1234",  CW_SIGN_KEY_TOO_SHORT },   /* PIN would enter the digest */
        { CW_SIGN_CURR_K1,   2U, false, 31U, false, "1234",  CW_SIGN_KEY_TOO_SHORT },   /* Schnorr too */
        { CW_SIGN_CURR_K1,   0U, false, 32U, false, "12a4",  CW_SIGN_PIN_INCORRECT },
        { CW_SIGN_CURR_K1,   0U, false, 32U, false, "123",   CW_SIGN_PIN_INCORRECT },
        { 0x02U,             0U, false, 32U, true,  "1234",  CW_SIGN_UNSUPPORTED_KEY_TYPE },  /* derive-and-make-current */
        { 0x30U,             0U, false, 32U, false, "1234",  CW_SIGN_UNSUPPORTED_KEY_TYPE },
        { CW_SIGN_CURR_K1,   5U, false, 32U, false, "1234",  CW_SIGN_UNSUPPORTED_KEY_TYPE },
        { CW_SIGN_PINLESS_K1, 0U, false, 32U, false, "1234", CW_SIGN_KEY_TOO_SHORT_WITH_PINLESS_MODE },
        { CW_SIGN_CURR_K1,   0U, true,  32U, false, "",      CW_SIGN_KEY_TOO_SHORT_WITH_PINLESS_MODE },
        { CW_SIGN_CURR_K1,   0U, false, 32U, true,  "1234",  CW_SIGN_INVALID_PATH },    /* path ignored = wrong account */
    };
    for (uint8_t i = 0U; i < sizeof(bad) / sizeof(bad[0]); i++) {
        WalletRig w;
        CW_SignRequest req(w.s, bad[i].keyType, bad[i].sigType, bad[i].pinless);
        req.hash = DIGEST; req.hashLength = bad[i].hashLen;
        if (bad[i].path) { req.derivePath = PATH; req.derivePathLength = sizeof(PATH); }
        memcpy(req.pin, bad[i].pin, strlen(bad[i].pin));
        CHECK(w.wallet.sign(req).errorCode == bad[i].code);
        CHECK(w.nfc.sent == 0U);
    }
}

static CW_SignResult signK1(WalletRig& w) {
    CW_SignRequest req(w.s);
    req.hash = DIGEST; req.hashLength = 32U;
    memcpy(req.pin, "1234", 4U);
    return w.wallet.sign(req);
}

static void check_sign_results(void) {   /* M4, M5 */
    { /* Valid DER answer. */
        WalletRig w;
        const uint8_t der[] = { 0x30U, 0x06U, 0x02U, 0x01U, 0x05U, 0x02U, 0x01U, 0x07U };
        memcpy(w.nfc.resp, der, sizeof(der)); w.nfc.respLen = sizeof(der);
        CW_SignResult r = signK1(w);
        CHECK((r.errorCode == CW_OK) && (r.cardSw == 0x9000U) && (r.signature[31] == 5U) && (r.signature[63] == 7U));
    }
    { /* r = s = 0 is never CW_OK. */
        WalletRig w;
        const uint8_t der[] = { 0x30U, 0x06U, 0x02U, 0x01U, 0x00U, 0x02U, 0x01U, 0x00U };
        memcpy(w.nfc.resp, der, sizeof(der)); w.nfc.respLen = sizeof(der);
        CHECK(signK1(w).errorCode == CW_NOK);
    }
    { /* Wrong PIN, authenticated inner SW. */
        WalletRig w;
        w.nfc.innerSw = 0x63C2U;
        CW_SignResult r = signK1(w);
        CHECK((r.errorCode == CW_SIGN_PIN_REJECTED) && (r.cardSw == 0x63C2U));
    }
    { /* Wrong PIN, bare SW. */
        WalletRig w;
        w.nfc.wrapped = false; w.nfc.sendOk = true;
        w.nfc.resp[0] = 0x63U; w.nfc.resp[1] = 0xC1U; w.nfc.respLen = 2U;
        CW_SignResult r = signK1(w);
        CHECK((r.errorCode == CW_SIGN_PIN_REJECTED) && (r.cardSw == 0x63C1U));
    }
    { /* Other card refusal. */
        WalletRig w;
        w.nfc.innerSw = 0x6A88U;
        CW_SignResult r = signK1(w);
        CHECK((r.errorCode == CW_SIGN_NO_KEY_LOADED) && (r.cardSw == 0x6A88U));
    }
    { /* Transport failure: no SW at all. */
        WalletRig w;
        w.nfc.wrapped = false;
        CW_SignResult r = signK1(w);
        CHECK((r.errorCode == CW_SIGN_CHANNEL_ERROR) && (r.cardSw == 0U));
    }
}

static void check_pubkey_results(void) {   /* L11, L14 */
    uint8_t pk[65] = { 0U };
    uint16_t pkLen = 0U;
    { /* Path with a current-key type: refused, nothing sent. */
        WalletRig w;
        CHECK(!w.wallet.getPublicKey(w.s, CW_SIGN_CURR_K1, PATH, sizeof(PATH), pk, sizeof(pk), pkLen));
        CHECK(w.nfc.sent == 0U);
    }
    struct Case { uint8_t keyType; uint8_t len; uint8_t first; bool ok; };
    const Case cases[] = {
        { CW_SIGN_CURR_K1,      65U, 0x04U, true  },
        { CW_SIGN_CURR_K1,      64U, 0x11U, true  },   /* bare X || Y (older applets) */
        { CW_SIGN_CURR_K1,      65U, 0x02U, false },
        { CW_SIGN_CURR_K1,      33U, 0x02U, false },
        { CW_SIGN_CURR_K1,       1U, 0x04U, false },
        { CW_SIGN_CURR_ED25519, 32U, 0x11U, true  },
        { CW_SIGN_CURR_ED25519, 65U, 0x04U, false },
    };
    for (uint8_t i = 0U; i < sizeof(cases) / sizeof(cases[0]); i++) {
        WalletRig w;
        memset(w.nfc.resp, 0x11U, cases[i].len);
        w.nfc.resp[0] = cases[i].first;
        w.nfc.respLen = cases[i].len;
        CHECK(w.wallet.getPublicKey(w.s, cases[i].keyType, NULL, 0U, pk, sizeof(pk), pkLen) == cases[i].ok);
        CHECK(!cases[i].ok || (pkLen == cases[i].len));
    }
}

static void check_card_info(void) {   /* L15 */
    {
        WalletRig w;
        const uint8_t info[] = { 0x00U, 3U, 'B', 'o', 'b', 3U, 'a', '@', 'b' };
        memcpy(w.nfc.resp, info, sizeof(info)); w.nfc.respLen = sizeof(info);
        CW_CardInfo ci;
        CHECK(w.wallet.getCardInfo(w.s, &ci) && (strcmp(ci.name, "Bob") == 0) && (strcmp(ci.email, "a@b") == 0));
    }
    { /* Control character in the email: refused, and the name is not written either. */
        WalletRig w;
        const uint8_t info[] = { 0x00U, 3U, 'B', 'o', 'b', 3U, 'a', 0x1BU, 'b' };
        memcpy(w.nfc.resp, info, sizeof(info)); w.nfc.respLen = sizeof(info);
        CW_CardInfo ci;
        CHECK(!w.wallet.getCardInfo(w.s, &ci) && (ci.name[0] == '\0'));
    }
}

static void check_disconnect(void) {   /* L12 */
    FakeNfc nfc;
    FakeCrypto crypto;
    CryptnoxWallet wallet(nfc, logger, crypto, platform);
    CW_SecureSession s;
    openSession(s);
    memset(s.aesKey, 0, sizeof(s.aesKey));   /* looks closed, still holds Kmac */
    wallet.disconnect(s);
    CHECK(isCleared(s));
}

int main(void) {
    check_session_clearing();
    check_pubkey_allow_list();
    check_ed25519_applet_gate();
    check_parsers();
    check_transport_overreport();
    check_sign_requests();
    check_sign_results();
    check_pubkey_results();
    check_card_info();
    check_disconnect();
    check_rolling_iv();
    check_last_card_sw();
    check_mutual_auth_ecdh_failure();
    check_safe_memcpy();
    printf("test_host: OK\n");
    return 0;
}
