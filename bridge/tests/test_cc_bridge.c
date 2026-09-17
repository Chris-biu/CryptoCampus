#include "cc_bridge.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "bsl_types.h"
#include "bsl_sal.h"
#include "hitls_pki_csr.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_errno.h"

static int fails = 0;

#define CHECK(cond, msg)                                                    \
    do {                                                                    \
        if (!(cond)) {                                                      \
            printf("FAIL: %s\n", msg);                                      \
            fails++;                                                        \
        } else {                                                            \
            printf("ok: %s\n", msg);                                        \
        }                                                                   \
    } while (0)

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}
static void unhex(const char *hex, uint8_t *out, size_t *outlen) {
    size_t n = strlen(hex) / 2, i;
    for (i = 0; i < n; i++)
        out[i] = (uint8_t)((hexval(hex[2 * i]) << 4) | hexval(hex[2 * i + 1]));
    *outlen = n;
}

int main(void) {
    uint8_t digest[32];
    uint8_t digest2[32];
    cc_bridge_buffer buf;
    cc_bridge_buffer buf2;
    uint8_t rnd[16];
    uint8_t small[16];
    cc_bridge_buffer smallbuf;

    CHECK(cc_bridge_init(NULL) == CCB_OK, "init ok");
    CHECK(cc_bridge_version() != NULL && cc_bridge_version()[0] != '\0',
          "version non-empty");

    CHECK(cc_bridge_random_bytes(rnd, sizeof(rnd)) == CCB_OK, "random 16 bytes");
    CHECK(cc_bridge_random_bytes(rnd, 1) == CCB_OK, "random 1 byte");

    /* SM3("abc") == official KAT vector */
    memset(digest, 0, sizeof(digest));
    buf.data = digest;
    buf.capacity = sizeof(digest);
    buf.len = 0;
    CHECK(cc_bridge_sm3_digest((const uint8_t *)"abc", 3, &buf) == CCB_OK,
          "sm3(abc) ok");
    CHECK(buf.len == 32, "sm3(abc) len 32");
    {
        static const uint8_t exp[32] = {
            0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
            0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
            0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
            0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0
        };
        CHECK(memcmp(digest, exp, 32) == 0, "sm3(abc) matches official KAT");
    }

    /* SM3("") == official KAT vector */
    memset(digest2, 0, sizeof(digest2));
    buf2.data = digest2;
    buf2.capacity = sizeof(digest2);
    buf2.len = 0;
    CHECK(cc_bridge_sm3_digest((const uint8_t *)"", 0, &buf2) == CCB_OK,
          "sm3(\"\") ok");
    {
        static const uint8_t exp2[32] = {
            0x1a, 0xb2, 0x1d, 0x83, 0x55, 0xcf, 0xa1, 0x7f,
            0x8e, 0x61, 0x19, 0x48, 0x31, 0xe8, 0x1a, 0x8f,
            0x22, 0xbe, 0xc8, 0xc7, 0x28, 0xfe, 0xfb, 0x74,
            0x7e, 0xd0, 0x35, 0xeb, 0x50, 0x82, 0xaa, 0x2b
        };
        CHECK(memcmp(digest2, exp2, 32) == 0, "sm3(\"\") matches official KAT");
    }

    /* buffer too small */
    smallbuf.data = small;
    smallbuf.capacity = sizeof(small);
    smallbuf.len = 0;
    CHECK(cc_bridge_sm3_digest((const uint8_t *)"abc", 3, &smallbuf) ==
              CCB_BUFFER_TOO_SMALL,
          "sm3 buffer too small");

    /* constant-time equality */
    CHECK(cc_bridge_constant_time_equal((const uint8_t *)"aaa", 3,
                                        (const uint8_t *)"aaa", 3) == 1,
          "cte equal");
    CHECK(cc_bridge_constant_time_equal((const uint8_t *)"aaa", 3,
                                        (const uint8_t *)"aab", 3) == 0,
          "cte different");
    CHECK(cc_bridge_constant_time_equal((const uint8_t *)"aa", 2,
                                        (const uint8_t *)"aaa", 3) == 0,
          "cte length diff");

    /* --- SM4-GCM KAT (RFC 8998 A.1) --- */
    {
        uint8_t key[16], iv[12], aad[20], pt_exp[64], ct[64], tag[16], out[64], badtag[16];
        size_t l;
        cc_bridge_buffer ptbuf;
        unhex("0123456789ABCDEFFEDCBA9876543210", key, &l);
        unhex("00001234567800000000ABCD", iv, &l);
        unhex("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2", aad, &l);
        unhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA", pt_exp, &l);
        unhex("17F399F08C67D5EE19D0DC9969C4BB7D5FD46FD3756489069157B282BB200735D82710CA5C22F0CCFA7CBF93D496AC15A56834CBCF98C397B4024A2691233B8D", ct, &l);
        unhex("83DE3541E4C2B58177E065A9BF7B62EC", tag, &l);

        ptbuf.data = out; ptbuf.capacity = sizeof(out); ptbuf.len = 0;
        CHECK(cc_bridge_sm4_gcm_decrypt(key, iv, ct, 64, aad, 20, tag, 16, &ptbuf) == CCB_OK, "gcm decrypt ok");
        CHECK(ptbuf.len == 64 && memcmp(out, pt_exp, 64) == 0, "gcm RFC8998 plaintext match");

        memcpy(badtag, tag, 16); badtag[0] ^= 0x01;
        ptbuf.data = out; ptbuf.capacity = sizeof(out); ptbuf.len = 0;
        CHECK(cc_bridge_sm4_gcm_decrypt(key, iv, ct, 64, aad, 20, badtag, 16, &ptbuf) == CCB_INTEGRITY_FAILED, "gcm tampered tag fails");
        CHECK(ptbuf.len == 0, "gcm tampered tag -> no plaintext");
    }

    /* --- SM4-GCM roundtrip (auto nonce) --- */
    {
        uint8_t key[16], nonce[12], cbuf[64], tbuf[16], pbuf[64];
        cc_bridge_buffer c, n, t, p;
        const char *msg = "hello sm4-gcm";
        size_t mlen = strlen(msg);

        memset(key, 0x11, sizeof(key));
        c.data = cbuf; c.capacity = sizeof(cbuf); c.len = 0;
        n.data = nonce; n.capacity = sizeof(nonce); n.len = 0;
        t.data = tbuf; t.capacity = sizeof(tbuf); t.len = 0;
        CHECK(cc_bridge_sm4_gcm_encrypt(key, (const uint8_t *)msg, mlen, NULL, 0, &c, &n, &t) == CCB_OK, "gcm encrypt ok");
        CHECK(n.len == 12 && t.len == 16, "gcm nonce/tag length");

        p.data = pbuf; p.capacity = sizeof(pbuf); p.len = 0;
        CHECK(cc_bridge_sm4_gcm_decrypt(key, nonce, cbuf, c.len, NULL, 0, tbuf, 16, &p) == CCB_OK, "gcm roundtrip ok");
        CHECK(p.len == mlen && memcmp(pbuf, msg, mlen) == 0, "gcm roundtrip plaintext match");
    }

    /* --- SM2 roundtrips --- */
    {
        uint8_t privA[32], pubA[65], privB[32], pubB[65];
        cc_bridge_buffer pbuf, qbuf;
        uint8_t dg[32];
        cc_bridge_buffer db;
        uint8_t sig[64];
        cc_bridge_buffer sbuf;
        uint8_t ct[512], pt[128];
        cc_bridge_buffer cbuf, pb;
        uint8_t share1[32], share2[32];
        cc_bridge_buffer s1, s2;

        /* keypair A */
        pbuf.data = privA; pbuf.capacity = sizeof(privA); pbuf.len = 0;
        qbuf.data = pubA; qbuf.capacity = sizeof(pubA); qbuf.len = 0;
        CHECK(cc_bridge_sm2_generate_keypair(&pbuf, &qbuf) == CCB_OK, "sm2 keypair A ok");
        CHECK(pbuf.len == 32 && qbuf.len == 65, "sm2 key sizes 32/65");
        CHECK(pubA[0] == 0x04, "sm2 pubkey uncompressed prefix");

        /* keypair B */
        pbuf.data = privB; pbuf.capacity = sizeof(privB); pbuf.len = 0;
        qbuf.data = pubB; qbuf.capacity = sizeof(pubB); qbuf.len = 0;
        CHECK(cc_bridge_sm2_generate_keypair(&pbuf, &qbuf) == CCB_OK, "sm2 keypair B ok");

        /* digest for signing */
        db.data = dg; db.capacity = sizeof(dg); db.len = 0;
        CHECK(cc_bridge_sm3_digest((const uint8_t *)"hello sm2", 9, &db) == CCB_OK, "sm3 digest for sm2");

        /* sign / verify roundtrip */
        sbuf.data = sig; sbuf.capacity = sizeof(sig); sbuf.len = 0;
        CHECK(cc_bridge_sm2_sign(privA, dg, &sbuf) == CCB_OK, "sm2 sign ok");
        CHECK(sbuf.len == 64, "sm2 signature len 64");
        CHECK(cc_bridge_sm2_verify(pubA, dg, sig, 64) == 1, "sm2 verify ok");

        /* tampered signature fails */
        sig[0] ^= 0x01;
        CHECK(cc_bridge_sm2_verify(pubA, dg, sig, 64) == 0, "sm2 tampered sig fails");
        sig[0] ^= 0x01;

        /* encrypt / decrypt roundtrip */
        cbuf.data = ct; cbuf.capacity = sizeof(ct); cbuf.len = 0;
        CHECK(cc_bridge_sm2_encrypt(pubA, (const uint8_t *)"sm2 secret", 10, &cbuf) == CCB_OK, "sm2 encrypt ok");
        CHECK(cbuf.len > 10 && cbuf.len <= 10 + 512, "sm2 ciphertext len in range");
        pb.data = pt; pb.capacity = sizeof(pt); pb.len = 0;
        CHECK(cc_bridge_sm2_decrypt(privA, ct, cbuf.len, &pb) == CCB_OK, "sm2 decrypt ok");
        CHECK(pb.len == 10 && memcmp(pt, "sm2 secret", 10) == 0, "sm2 plaintext match");

        /* tampered ciphertext fails */
        ct[0] ^= 0x01;
        pb.data = pt; pb.capacity = sizeof(pt); pb.len = 0;
        CHECK(cc_bridge_sm2_decrypt(privA, ct, cbuf.len, &pb) == CCB_INTEGRITY_FAILED, "sm2 tampered ct fails");

        /* ECDH consistency */
        s1.data = share1; s1.capacity = sizeof(share1); s1.len = 0;
        s2.data = share2; s2.capacity = sizeof(share2); s2.len = 0;
        CHECK(cc_bridge_sm2_ecdh(privA, pubB, &s1) == CCB_OK, "sm2 ecdh A->B ok");
        CHECK(cc_bridge_sm2_ecdh(privB, pubA, &s2) == CCB_OK, "sm2 ecdh B->A ok");
        CHECK(s1.len == 32 && s2.len == 32, "sm2 shared secret len 32");
        CHECK(memcmp(share1, share2, 32) == 0, "sm2 ecdh shared secret equal");
    }
    /* --- SM3 口令哈希 KAT --- */
    {
        uint8_t salt[16], out[32];
        cc_bridge_buffer ob;
        static const uint8_t exp[32] = {
            0x20,0x2b,0xee,0x36,0x1b,0xc0,0xc6,0x24,0x55,0x57,0xe0,0xb1,0xf1,0x81,0x84,0xa3,
            0x8c,0x18,0x42,0x94,0xc4,0xeb,0x7e,0x2a,0x00,0xa9,0x0f,0xb3,0xc6,0x7a,0x72,0x91
        };
        memset(salt, 0xaa, sizeof(salt));
        ob.data = out; ob.capacity = sizeof(out); ob.len = 0;
        CHECK(cc_bridge_sm3_hash_password((const uint8_t *)"password123", 11, salt, 16, &ob) == CCB_OK,
              "sm3 hash password ok");
        CHECK(ob.len == 32 && memcmp(out, exp, 32) == 0, "sm3 hash password matches reference");
    }

    /* --- HKDF-SM3 KAT（RFC5869 形状，SM3 作哈希，L=42） --- */
    {
        uint8_t ikm[22], salt[13], info[10], out[42];
        cc_bridge_buffer ob;
        size_t l;
        static const uint8_t exp[42] = {
            0xc6,0x9f,0xe9,0x1b,0x7a,0xae,0xe2,0xdd,0x57,0x18,0xd7,0x2d,0xca,0xee,
            0x0c,0xce,0x93,0xf1,0xb8,0xe4,0x1f,0x79,0x2d,0xa5,0x12,0x61,0xb6,0xa5,
            0x17,0xe6,0x8b,0x36,0xed,0x2c,0x59,0x55,0x72,0xb0,0x1d,0xfa,0x35,0x9b
        };
        memset(ikm, 0x0b, sizeof(ikm));
        unhex("000102030405060708090a0b0c", salt, &l);
        unhex("f0f1f2f3f4f5f6f7f8f9", info, &l);
        ob.data = out; ob.capacity = sizeof(out); ob.len = 0;
        CHECK(cc_bridge_hkdf_sm3(ikm, sizeof(ikm), salt, sizeof(salt), info, sizeof(info), &ob) == CCB_OK,
              "hkdf-sm3 ok");
        CHECK(ob.len == 42 && memcmp(out, exp, 42) == 0, "hkdf-sm3 matches reference");
    }

    /* ======================================================================
     * 数字信封 v2（对齐 server/app/services/drop.py 契约）
     * ====================================================================== */
    {
        uint8_t r_priv[32], r_pub[65];
        uint8_t s_priv[32], s_pub[65];
        cc_bridge_buffer pbuf, qbuf;
        uint8_t fake_cert[128];
        uint8_t ctbuf[256], noncebuf[12], tagbuf[16], ek2buf[512], sigbuf[64], certbuf[128];
        uint8_t ptout[256];
        uint8_t dgbuf[32];
        uint8_t factor[32], wrong_factor[32];
        cc_bridge_envelope env;
        cc_bridge_buffer pt;
        cc_bridge_buffer dg;
        const char *msg = "CryptoCampus drop payload";
        size_t mlen = strlen(msg);

        memset(fake_cert, 0x5a, sizeof(fake_cert));

        pbuf.data = r_priv; pbuf.capacity = sizeof(r_priv); pbuf.len = 0;
        qbuf.data = r_pub; qbuf.capacity = sizeof(r_pub); qbuf.len = 0;
        CHECK(cc_bridge_sm2_generate_keypair(&pbuf, &qbuf) == CCB_OK, "env: recipient keypair");
        pbuf.data = s_priv; pbuf.capacity = sizeof(s_priv); pbuf.len = 0;
        qbuf.data = s_pub; qbuf.capacity = sizeof(s_pub); qbuf.len = 0;
        CHECK(cc_bridge_sm2_generate_keypair(&pbuf, &qbuf) == CCB_OK, "env: sender keypair");

        memset(&env, 0, sizeof(env));
        env.ciphertext.data = ctbuf; env.ciphertext.capacity = sizeof(ctbuf);
        env.nonce.data = noncebuf; env.nonce.capacity = sizeof(noncebuf);
        env.tag.data = tagbuf; env.tag.capacity = sizeof(tagbuf);
        env.enc_key_sm2.data = ek2buf; env.enc_key_sm2.capacity = sizeof(ek2buf);
        env.sender_signature.data = sigbuf; env.sender_signature.capacity = sizeof(sigbuf);
        env.sender_certificate.data = certbuf; env.sender_certificate.capacity = sizeof(certbuf);
        CHECK(cc_bridge_envelope_seal((const uint8_t *)msg, mlen, r_pub, 0, NULL,
                                      s_priv, fake_cert, sizeof(fake_cert),
                                      NULL, 0, &env) == CCB_OK, "env: seal ok");
        CHECK(env.nonce.len == 12 && env.tag.len == 16, "env: nonce/tag lengths");
        CHECK(env.ciphertext.len == mlen, "env: ciphertext len == plaintext len");
        CHECK(env.enc_key_sm2.len > 0 && env.enc_key_sm2.len <= 512, "env: enc_key_sm2 in range");
        CHECK(env.sender_signature.len == 64, "env: signature len 64");
        CHECK(env.sender_certificate.len == sizeof(fake_cert) &&
              memcmp(certbuf, fake_cert, sizeof(fake_cert)) == 0, "env: cert echoed");
        CHECK(env.enc_key_mlkem.len == 0, "env: mlkem empty in classic mode");

        /* 签名契约：SM2_sign(priv, SM3(ciphertext)) —— 与 drop.py 一致 */
        dg.data = dgbuf; dg.capacity = sizeof(dgbuf); dg.len = 0;
        CHECK(cc_bridge_sm3_digest(ctbuf, env.ciphertext.len, &dg) == CCB_OK, "env: sm3(ciphertext)");
        CHECK(cc_bridge_sm2_verify(s_pub, dgbuf, sigbuf, 64) == 1,
              "env: signature over SM3(ciphertext)");

        /* open 成功 */
        pt.data = ptout; pt.capacity = sizeof(ptout); pt.len = 0;
        CHECK(cc_bridge_envelope_open(&env, r_priv, 0, NULL, NULL, 0, &pt) == CCB_OK, "env: open ok");
        CHECK(pt.len == mlen && memcmp(ptout, msg, mlen) == 0, "env: plaintext roundtrip");

        /* 篡改 tag → fail closed */
        tagbuf[0] ^= 0x01;
        pt.data = ptout; pt.capacity = sizeof(ptout); pt.len = 0;
        CHECK(cc_bridge_envelope_open(&env, r_priv, 0, NULL, NULL, 0, &pt) == CCB_INTEGRITY_FAILED,
              "env: tampered tag fails");
        CHECK(pt.len == 0, "env: tampered tag -> no plaintext");
        tagbuf[0] ^= 0x01;

        /* 篡改密文 → fail closed */
        ctbuf[0] ^= 0x01;
        pt.data = ptout; pt.capacity = sizeof(ptout); pt.len = 0;
        CHECK(cc_bridge_envelope_open(&env, r_priv, 0, NULL, NULL, 0, &pt) == CCB_INTEGRITY_FAILED,
              "env: tampered ciphertext fails");
        ctbuf[0] ^= 0x01;

        /* 错误收件人私钥 → fail closed */
        pt.data = ptout; pt.capacity = sizeof(ptout); pt.len = 0;
        CHECK(cc_bridge_envelope_open(&env, s_priv, 0, NULL, NULL, 0, &pt) == CCB_INTEGRITY_FAILED,
              "env: wrong recipient key fails");

        /* 提取口令：seal(带 factor) / open(缺 factor) 失败 / open(错 factor) 失败 / open(对 factor) 成功 */
        memset(factor, 0x33, sizeof(factor));
        memset(wrong_factor, 0x44, sizeof(wrong_factor));
        memset(&env, 0, sizeof(env));
        env.ciphertext.data = ctbuf; env.ciphertext.capacity = sizeof(ctbuf);
        env.nonce.data = noncebuf; env.nonce.capacity = sizeof(noncebuf);
        env.tag.data = tagbuf; env.tag.capacity = sizeof(tagbuf);
        env.enc_key_sm2.data = ek2buf; env.enc_key_sm2.capacity = sizeof(ek2buf);
        env.sender_signature.data = sigbuf; env.sender_signature.capacity = sizeof(sigbuf);
        env.sender_certificate.data = certbuf; env.sender_certificate.capacity = sizeof(certbuf);
        CHECK(cc_bridge_envelope_seal((const uint8_t *)msg, mlen, r_pub, 0, NULL,
                                      s_priv, fake_cert, sizeof(fake_cert),
                                      factor, sizeof(factor), &env) == CCB_OK,
              "env: seal with access factor ok");
        pt.data = ptout; pt.capacity = sizeof(ptout); pt.len = 0;
        CHECK(cc_bridge_envelope_open(&env, r_priv, 0, NULL, NULL, 0, &pt) == CCB_INTEGRITY_FAILED,
              "env: missing factor fails");
        pt.data = ptout; pt.capacity = sizeof(ptout); pt.len = 0;
        CHECK(cc_bridge_envelope_open(&env, r_priv, 0, NULL, wrong_factor, sizeof(wrong_factor), &pt) == CCB_INTEGRITY_FAILED,
              "env: wrong factor fails");
        pt.data = ptout; pt.capacity = sizeof(ptout); pt.len = 0;
        CHECK(cc_bridge_envelope_open(&env, r_priv, 0, NULL, factor, sizeof(factor), &pt) == CCB_OK,
              "env: correct factor opens");
        CHECK(pt.len == mlen && memcmp(ptout, msg, mlen) == 0, "env: factor roundtrip");

        /* PQC 暂不支持 */
        CHECK(cc_bridge_envelope_seal((const uint8_t *)msg, mlen, r_pub, 1, NULL,
                                      s_priv, fake_cert, sizeof(fake_cert),
                                      NULL, 0, &env) == CCB_UNSUPPORTED,
              "env: pqc_mode seal unsupported");

        /* 负例 */
        CHECK(cc_bridge_envelope_seal(NULL, 0, r_pub, 0, NULL, s_priv, fake_cert,
                                      sizeof(fake_cert), NULL, 0, &env) == CCB_INVALID_ARGUMENT,
              "env: null plaintext invalid");
        CHECK(cc_bridge_envelope_seal((const uint8_t *)msg, mlen, r_pub, 0, NULL,
                                      s_priv, fake_cert, sizeof(fake_cert),
                                      (const uint8_t *)"short", 5, &env) == CCB_INVALID_ARGUMENT,
              "env: short access factor invalid");
    }

    /* ======================================================================
     * PKI：CSR / 证书签发 / 证书链验证 / CRL
     * ====================================================================== */
    {
        uint8_t ca_prv[32], ca_pub[65], ee_prv[32], ee_pub[65];
        uint8_t csrbuf[4096], rootbuf[8192], eebuf[8192], serialbuf[32], crlbuf[16384];
        uint8_t tinybuf[8];
        cc_bridge_buffer pbuf, qbuf;
        cc_bridge_buffer csr = { csrbuf, sizeof(csrbuf), 0 };
        cc_bridge_buffer root = { rootbuf, sizeof(rootbuf), 0 };
        cc_bridge_buffer ee = { eebuf, sizeof(eebuf), 0 };
        cc_bridge_buffer serial = { serialbuf, sizeof(serialbuf), 0 };
        cc_bridge_buffer crl = { crlbuf, sizeof(crlbuf), 0 };
        cc_bridge_buffer tiny = { tinybuf, sizeof(tinybuf), 0 };
        char serial_hex[64];
        size_t k;
        const int64_t nb = 1789000000;            /* 2026-09-10 前后 */
        const int64_t na = nb + 86400LL * 365;    /* +1 年 */
        const uint32_t ku_ca = HITLS_X509_EXT_KU_KEY_CERT_SIGN | HITLS_X509_EXT_KU_CRL_SIGN;
        const uint32_t ku_ee = HITLS_X509_EXT_KU_DIGITAL_SIGN |
                               HITLS_X509_EXT_KU_KEY_ENCIPHERMENT |
                               HITLS_X509_EXT_KU_KEY_AGREEMENT;

        pbuf.data = ca_prv; pbuf.capacity = sizeof(ca_prv); pbuf.len = 0;
        qbuf.data = ca_pub; qbuf.capacity = sizeof(ca_pub); qbuf.len = 0;
        CHECK(cc_bridge_sm2_generate_keypair(&pbuf, &qbuf) == CCB_OK, "pki: CA keypair");
        pbuf.data = ee_prv; pbuf.capacity = sizeof(ee_prv); pbuf.len = 0;
        qbuf.data = ee_pub; qbuf.capacity = sizeof(ee_pub); qbuf.len = 0;
        CHECK(cc_bridge_sm2_generate_keypair(&pbuf, &qbuf) == CCB_OK, "pki: EE keypair");

        /* CSR */
        CHECK(cc_bridge_csr_create(ca_prv, 32, ca_pub, 65, "CryptoCampus Root CA", &csr) == CCB_OK,
              "pki: csr_create(root)");
        CHECK(csr.len > 0, "pki: CSR non-empty");
        CHECK(cc_bridge_csr_create(ca_prv, 32, ca_pub, 65, "CryptoCampus Root CA", &tiny) == CCB_BUFFER_TOO_SMALL,
              "pki: csr tiny buffer");
        CHECK(cc_bridge_csr_create(ca_prv, 31, ca_pub, 65, "x", &csr) == CCB_INVALID_ARGUMENT,
              "pki: csr bad prv len");
        CHECK(cc_bridge_csr_create(ca_prv, 32, ca_pub, 65, "", &csr) == CCB_INVALID_ARGUMENT,
              "pki: csr empty CN");

        /* CSR 回读：解析 + 自签校验 + subject DN 存在 */
        {
            BSL_Buffer enc = { csrbuf, (uint32_t)csr.len };
            HITLS_X509_Csr *pcsr = NULL;
            BslList *subject = NULL;
            int32_t pr = HITLS_X509_CsrParseBuff(BSL_FORMAT_ASN1, &enc, &pcsr);
            CHECK(pr == HITLS_PKI_SUCCESS && pcsr != NULL, "pki: CSR parses back");
            if (pcsr != NULL) {
                CHECK(HITLS_X509_CsrVerify(pcsr) == HITLS_PKI_SUCCESS,
                      "pki: CSR self-signature verifies");
                pr = HITLS_X509_CsrCtrl(pcsr, HITLS_X509_GET_SUBJECT_DN, &subject,
                                        (uint32_t)sizeof(BslList *));
                CHECK(pr == HITLS_PKI_SUCCESS && subject != NULL, "pki: CSR subject DN present");
                HITLS_X509_CsrFree(pcsr);
            }
        }

        /* 自签根证书 */
        CHECK(cc_bridge_cert_sign(csrbuf, csr.len, NULL, 0, ca_prv, 32, nb, na, ku_ca,
                                  &root, &serial) == CCB_OK, "pki: cert_sign(self-signed root)");
        CHECK(root.len > 0, "pki: root DER non-empty");
        CHECK(serial.len == 16, "pki: serial 16 bytes");

        /* 终端实体证书（由 CA 签发） */
        csr.len = 0;
        CHECK(cc_bridge_csr_create(ee_prv, 32, ee_pub, 65, "student50", &csr) == CCB_OK,
              "pki: csr_create(EE)");
        serial.len = 0;
        CHECK(cc_bridge_cert_sign(csrbuf, csr.len, rootbuf, root.len, ca_prv, 32, nb, na, ku_ee,
                                  &ee, &serial) == CCB_OK, "pki: cert_sign(EE by CA)");
        CHECK(serial.len == 16, "pki: EE serial 16 bytes");
        CHECK(cc_bridge_cert_sign(csrbuf, csr.len, rootbuf, root.len, ca_prv, 32, na, nb, ku_ee,
                                  &ee, &serial) == CCB_INVALID_ARGUMENT, "pki: cert_sign bad time range");
        CHECK(cc_bridge_cert_sign(csrbuf, 8, NULL, 0, ca_prv, 32, nb, na, ku_ca,
                                  &root, NULL) == CCB_INVALID_ARGUMENT, "pki: cert_sign garbage CSR");

        /* 证书链验证 */
        CHECK(cc_bridge_cert_chain_verify(eebuf, ee.len, rootbuf, root.len,
                                          rootbuf, root.len, nb + 100, ku_ee) == 1,
              "pki: chain verify EE OK");
        CHECK(cc_bridge_cert_chain_verify(rootbuf, root.len, NULL, 0,
                                          rootbuf, root.len, nb + 100, ku_ca) == 1,
              "pki: chain verify self-signed root OK");
        CHECK(cc_bridge_cert_chain_verify(eebuf, ee.len, rootbuf, root.len,
                                          rootbuf, root.len, nb + 100,
                                          HITLS_X509_EXT_KU_KEY_CERT_SIGN) == 0,
              "pki: chain verify wrong KU fails");
        CHECK(cc_bridge_cert_chain_verify(eebuf, ee.len, rootbuf, root.len,
                                          rootbuf, root.len, na + 100000, ku_ee) == 0,
              "pki: chain verify expired fails");
        CHECK(cc_bridge_cert_chain_verify(eebuf, ee.len, NULL, 0,
                                          eebuf, ee.len, nb + 100, ku_ee) == 0,
              "pki: chain verify wrong trust root fails");

        /* CRL：吊销 EE 序列号 */
        {
            static const char hexd[] = "0123456789abcdef";
            for (k = 0; k < serial.len; k++) {
                serial_hex[2 * k] = hexd[serialbuf[k] >> 4];
                serial_hex[2 * k + 1] = hexd[serialbuf[k] & 0x0f];
            }
            serial_hex[2 * serial.len] = '\0';
        }
        CHECK(cc_bridge_crl_create((const uint8_t *)serial_hex, strlen(serial_hex),
                                   rootbuf, root.len, ca_prv, 32, nb, na, &crl) == CCB_OK,
              "pki: crl_create ok");
        CHECK(crl.len > 0, "pki: CRL non-empty");
        CHECK(cc_bridge_crl_verify(eebuf, ee.len, crlbuf, crl.len, nb + 100) == 0,
              "pki: crl_verify revoked EE -> 0");
        CHECK(cc_bridge_crl_verify(rootbuf, root.len, crlbuf, crl.len, nb + 100) == 1,
              "pki: crl_verify root not revoked -> 1");
        CHECK(cc_bridge_crl_verify(eebuf, ee.len, crlbuf, 8, nb + 100) == 0,
              "pki: crl_verify garbage CRL -> fail closed");
    }
/* --- SM2 盲签名：两轮 EC-Schnorr 盲签名（SM2 曲线 + SM3） --- */
    {
        static const uint8_t bmsg[] = "tuition-2026-autumn|vote|period-3";
        const size_t blen = sizeof(bmsg) - 1;
        uint8_t bpriv[32], bpub[65], bpriv2[32], bpub2[65];
        uint8_t R1[65], Rp1[65], k1[32], cp1[32], st1[64], sp1[32], s1[32];
        uint8_t R2[65], Rp2[65], k2[32], cp2[32], st2[64], sp2[32], s2[32];
        uint8_t badpt[65], badsig[32], zerosig[32];
        cc_bridge_buffer bpb, bqb, bkb, bRb, bcpb, bstb, bRpb, bspb, bsb;

        /* 签名方密钥对 + 另一把（“错公钥”用例用） */
        bpb.data = bpriv;  bpb.capacity = sizeof(bpriv);  bpb.len = 0;
        bqb.data = bpub;   bqb.capacity = sizeof(bpub);   bqb.len = 0;
        CHECK(cc_bridge_sm2_generate_keypair(&bpb, &bqb) == CCB_OK, "blind: signer keypair ok");
        CHECK(bpb.len == 32 && bqb.len == 65, "blind: signer key sizes 32/65");

        bpb.data = bpriv2; bpb.capacity = sizeof(bpriv2); bpb.len = 0;
        bqb.data = bpub2;  bqb.capacity = sizeof(bpub2);  bqb.len = 0;
        CHECK(cc_bridge_sm2_generate_keypair(&bpb, &bqb) == CCB_OK, "blind: second keypair ok");

        /* ---- 第 1 次完整往返：commit -> blind -> sign -> unblind -> verify ---- */
        bkb.data = k1;   bkb.capacity = sizeof(k1);   bkb.len = 0;
        bRb.data = R1;   bRb.capacity = sizeof(R1);   bRb.len = 0;
        CHECK(cc_bridge_sm2_blind_commit(&bkb, &bRb) == CCB_OK, "blind: commit ok");
        CHECK(bkb.len == 32 && bRb.len == 65, "blind: commit sizes 32/65");
        CHECK(R1[0] == 0x04, "blind: commitment uncompressed prefix");

        bcpb.data = cp1; bcpb.capacity = sizeof(cp1); bcpb.len = 0;
        bstb.data = st1; bstb.capacity = sizeof(st1); bstb.len = 0;
        bRpb.data = Rp1; bRpb.capacity = sizeof(Rp1); bRpb.len = 0;
        CHECK(cc_bridge_sm2_blind_blind(R1, bpub, bmsg, blen, &bcpb, &bstb, &bRpb) == CCB_OK,
              "blind: blind ok");
        CHECK(bcpb.len == 32 && bstb.len == 64 && bRpb.len == 65, "blind: blind sizes 32/64/65");
        CHECK(memcmp(Rp1, R1, 65) != 0, "blind: R' differs from R");

        bspb.data = sp1; bspb.capacity = sizeof(sp1); bspb.len = 0;
        CHECK(cc_bridge_sm2_blind_sign(k1, cp1, bpriv, &bspb) == CCB_OK, "blind: sign ok");
        CHECK(bspb.len == 32, "blind: s' len 32");

        bsb.data = s1;   bsb.capacity = sizeof(s1);   bsb.len = 0;
        CHECK(cc_bridge_sm2_blind_unblind(sp1, st1, &bsb) == CCB_OK, "blind: unblind ok");
        CHECK(bsb.len == 32, "blind: s len 32");
        CHECK(memcmp(s1, sp1, 32) != 0, "blind: s differs from s'");

        CHECK(cc_bridge_sm2_blind_verify(Rp1, bmsg, blen, s1, bpub) == 1,
              "blind: roundtrip verify == 1");

        /* ---- 第 2 次往返：换一次 commit（新的 k），同一个 M ---- */
        bkb.data = k2;   bkb.capacity = sizeof(k2);   bkb.len = 0;
        bRb.data = R2;   bRb.capacity = sizeof(R2);   bRb.len = 0;
        CHECK(cc_bridge_sm2_blind_commit(&bkb, &bRb) == CCB_OK, "blind: 2nd commit ok");

        bcpb.data = cp2; bcpb.capacity = sizeof(cp2); bcpb.len = 0;
        bstb.data = st2; bstb.capacity = sizeof(st2); bstb.len = 0;
        bRpb.data = Rp2; bRpb.capacity = sizeof(Rp2); bRpb.len = 0;
        CHECK(cc_bridge_sm2_blind_blind(R2, bpub, bmsg, blen, &bcpb, &bstb, &bRpb) == CCB_OK,
              "blind: 2nd blind ok");

        bspb.data = sp2; bspb.capacity = sizeof(sp2); bspb.len = 0;
        CHECK(cc_bridge_sm2_blind_sign(k2, cp2, bpriv, &bspb) == CCB_OK, "blind: 2nd sign ok");

        bsb.data = s2;   bsb.capacity = sizeof(s2);   bsb.len = 0;
        CHECK(cc_bridge_sm2_blind_unblind(sp2, st2, &bsb) == CCB_OK, "blind: 2nd unblind ok");
        CHECK(cc_bridge_sm2_blind_verify(Rp2, bmsg, blen, s2, bpub) == 1,
              "blind: 2nd roundtrip verify == 1");

        /* ---- 盲性可观测：同一个 M 两轮，签名方视角与产物全不同 ---- */
        CHECK(memcmp(k1, k2, 32) != 0, "blind: k is one-time (k1 != k2)");
        CHECK(memcmp(R1, R2, 65) != 0, "blind: R1 != R2");
        CHECK(memcmp(Rp1, Rp2, 65) != 0, "blind: R'1 != R'2 (blinding randomized)");
        CHECK(memcmp(cp1, cp2, 32) != 0, "blind: c'1 != c'2 (signer view randomized)");
        CHECK(memcmp(s1, s2, 32) != 0, "blind: s1 != s2");
        CHECK(cc_bridge_sm2_blind_verify(Rp1, bmsg, blen, s1, bpub) == 1 &&
              cc_bridge_sm2_blind_verify(Rp2, bmsg, blen, s2, bpub) == 1,
              "blind: both credentials valid under the same pubkey");

        /* ---- 篡改矩阵：任何一处改动都必须验签失败 ---- */
        memcpy(badsig, s1, 32);
        badsig[0] ^= 0x01;
        CHECK(cc_bridge_sm2_blind_verify(Rp1, bmsg, blen, badsig, bpub) == 0, "blind: tampered s -> 0");

        memcpy(badpt, Rp1, 65);
        badpt[1] ^= 0x01;
        CHECK(cc_bridge_sm2_blind_verify(badpt, bmsg, blen, s1, bpub) == 0, "blind: tampered R' -> 0");

        CHECK(cc_bridge_sm2_blind_verify(Rp1, (const uint8_t *)"tuition-2026-autumn|vote|period-4",
                                         blen, s1, bpub) == 0, "blind: tampered message -> 0");
        CHECK(cc_bridge_sm2_blind_verify(Rp1, bmsg, blen, s1, bpub2) == 0, "blind: wrong pubkey -> 0");
        CHECK(cc_bridge_sm2_blind_verify(Rp2, bmsg, blen, s1, bpub) == 0, "blind: R'2 with s1 -> 0");

        memset(zerosig, 0, sizeof(zerosig));
        CHECK(cc_bridge_sm2_blind_verify(Rp1, bmsg, blen, zerosig, bpub) == 0, "blind: s = 0 -> 0");

        memset(badpt, 0x11, sizeof(badpt));
        badpt[0] = 0x04;
        CHECK(cc_bridge_sm2_blind_verify(badpt, bmsg, blen, s1, bpub) == 0, "blind: off-curve R' -> 0");

        /* ---- 参数边界 ---- */
        {
            uint8_t tiny[32];
            cc_bridge_buffer tb;
            tb.data = tiny; tb.capacity = 16; tb.len = 0;
            CHECK(cc_bridge_sm2_blind_commit(&tb, &bRb) == CCB_BUFFER_TOO_SMALL,
                  "blind: small k buffer rejected");
            tb.data = R2; tb.capacity = 64; tb.len = 0;
            CHECK(cc_bridge_sm2_blind_commit(&bkb, &tb) == CCB_BUFFER_TOO_SMALL,
                  "blind: small R buffer rejected");
        }
        CHECK(cc_bridge_sm2_blind_commit(NULL, &bRb) == CCB_INVALID_ARGUMENT, "blind: NULL k_out");
        CHECK(cc_bridge_sm2_blind_verify(NULL, bmsg, blen, s1, bpub) == CCB_INVALID_ARGUMENT,
              "blind: NULL R' rejected");
        CHECK(cc_bridge_sm2_blind_verify(Rp1, bmsg, blen, NULL, bpub) == CCB_INVALID_ARGUMENT,
              "blind: NULL s rejected");
        {
            uint8_t zeroprv[32], zout[32];
            cc_bridge_buffer zb;
            memset(zeroprv, 0, sizeof(zeroprv));
            zb.data = zout; zb.capacity = sizeof(zout); zb.len = 0;
            CHECK(cc_bridge_sm2_blind_sign(k1, cp1, zeroprv, &zb) == CCB_INVALID_ARGUMENT,
                  "blind: zero private key rejected");
        }
    }

    {
        uint8_t signer_prv[32], signer_pub[65];
        uint8_t other_prv[32], other_pub[65];
        uint8_t k1[32], R1[65];
        uint8_t k2[32], R2[65];
        uint8_t cp[32], state[64], Rp[65], sp[32], s[32];
        uint8_t cp2[32], state2[64], Rp2[65], sp2[32], s2[32];
        uint8_t bad[65], bad_s[32], tiny[16];
        cc_bridge_buffer pbuf, qbuf;
        cc_bridge_buffer kb, Rb, cpb, stb, Rpb, spb, sb;
        cc_bridge_buffer tinyb;
        const char *msg = "SN|hole_post|2026-09-17";
        size_t mlen = strlen(msg);

        /* 两对密钥：签名方 / 无关方 */
        pbuf.data = signer_prv; pbuf.capacity = sizeof(signer_prv); pbuf.len = 0;
        qbuf.data = signer_pub; qbuf.capacity = sizeof(signer_pub); qbuf.len = 0;
        CHECK(cc_bridge_sm2_generate_keypair(&pbuf, &qbuf) == CCB_OK, "blind: signer keypair");
        pbuf.data = other_prv; pbuf.capacity = sizeof(other_prv); pbuf.len = 0;
        qbuf.data = other_pub; qbuf.capacity = sizeof(other_pub); qbuf.len = 0;
        CHECK(cc_bridge_sm2_generate_keypair(&pbuf, &qbuf) == CCB_OK, "blind: other keypair");

        /* 长度边界：缓冲区不足 */
        tinyb.data = tiny; tinyb.capacity = sizeof(tiny); tinyb.len = 0;
        kb.data = k1; kb.capacity = sizeof(k1); kb.len = 0;
        CHECK(cc_bridge_sm2_blind_commit(&tinyb, &Rb) == CCB_BUFFER_TOO_SMALL,
              "blind: commit tiny k buffer");
        Rb.data = R1; Rb.capacity = sizeof(R1); Rb.len = 0;
        CHECK(cc_bridge_sm2_blind_commit(&kb, &tinyb) == CCB_BUFFER_TOO_SMALL,
              "blind: commit tiny R buffer");

        /* --- 完整往返 --- */
        /* 1) 签名方承诺 */
        kb.data = k1; kb.capacity = sizeof(k1); kb.len = 0;
        Rb.data = R1; Rb.capacity = sizeof(R1); Rb.len = 0;
        CHECK(cc_bridge_sm2_blind_commit(&kb, &Rb) == CCB_OK, "blind: commit ok");
        CHECK(kb.len == 32 && Rb.len == 65 && R1[0] == 0x04, "blind: commit lengths");

        /* 2) 客户端盲化 */
        cpb.data = cp; cpb.capacity = sizeof(cp); cpb.len = 0;
        stb.data = state; stb.capacity = sizeof(state); stb.len = 0;
        Rpb.data = Rp; Rpb.capacity = sizeof(Rp); Rpb.len = 0;
        CHECK(cc_bridge_sm2_blind_blind(R1, signer_pub, (const uint8_t *)msg, mlen,
                                        &cpb, &stb, &Rpb) == CCB_OK, "blind: blind ok");
        CHECK(cpb.len == 32 && stb.len == 64 && Rpb.len == 65 &&
              Rp[0] == 0x04, "blind: blind lengths");
        CHECK(memcmp(Rp, R1, sizeof(Rp)) != 0, "blind: R' differs from R");

        /* 3) 签名方对盲化挑战签名 */
        spb.data = sp; spb.capacity = sizeof(sp); spb.len = 0;
        CHECK(cc_bridge_sm2_blind_sign(k1, cp, signer_prv, &spb) == CCB_OK, "blind: sign ok");
        CHECK(spb.len == 32, "blind: s' length 32");

        /* 4) 客户端去盲 */
        sb.data = s; sb.capacity = sizeof(s); sb.len = 0;
        CHECK(cc_bridge_sm2_blind_unblind(sp, state, &sb) == CCB_OK, "blind: unblind ok");
        CHECK(sb.len == 32, "blind: s length 32");

        /* 5) 任意第三方公开验证 */
        CHECK(cc_bridge_sm2_blind_verify(Rp, (const uint8_t *)msg, mlen, s, signer_pub) == 1,
              "blind: verify ok");

        /* --- 盲性可观测：同一消息第二次往返应得到不同的 (R', s) --- */
        kb.data = k2; kb.capacity = sizeof(k2); kb.len = 0;
        Rb.data = R2; Rb.capacity = sizeof(R2); Rb.len = 0;
        CHECK(cc_bridge_sm2_blind_commit(&kb, &Rb) == CCB_OK, "blind: commit #2 ok");
        cpb.data = cp2; cpb.capacity = sizeof(cp2); cpb.len = 0;
        stb.data = state2; stb.capacity = sizeof(state2); stb.len = 0;
        Rpb.data = Rp2; Rpb.capacity = sizeof(Rp2); Rpb.len = 0;
        CHECK(cc_bridge_sm2_blind_blind(R2, signer_pub, (const uint8_t *)msg, mlen,
                                        &cpb, &stb, &Rpb) == CCB_OK, "blind: blind #2 ok");
        spb.data = sp2; spb.capacity = sizeof(sp2); spb.len = 0;
        CHECK(cc_bridge_sm2_blind_sign(k2, cp2, signer_prv, &spb) == CCB_OK, "blind: sign #2 ok");
        sb.data = s2; sb.capacity = sizeof(s2); sb.len = 0;
        CHECK(cc_bridge_sm2_blind_unblind(sp2, state2, &sb) == CCB_OK, "blind: unblind #2 ok");
        CHECK(cc_bridge_sm2_blind_verify(Rp2, (const uint8_t *)msg, mlen, s2, signer_pub) == 1,
              "blind: verify #2 ok");
        CHECK(memcmp(Rp, Rp2, sizeof(Rp)) != 0, "blind: R' differs across sessions");
        CHECK(memcmp(s, s2, sizeof(s)) != 0, "blind: s differs across sessions");
        CHECK(memcmp(cp, cp2, sizeof(cp)) != 0, "blind: c' differs across sessions");

        /* --- 篡改与负例：任一改动都必须验证失败 --- */
        memcpy(bad_s, s, sizeof(s)); bad_s[0] ^= 0x01;
        CHECK(cc_bridge_sm2_blind_verify(Rp, (const uint8_t *)msg, mlen, bad_s, signer_pub) == 0,
              "blind: tampered s rejected");

        memcpy(bad, Rp, sizeof(bad)); bad[10] ^= 0x01;
        CHECK(cc_bridge_sm2_blind_verify(bad, (const uint8_t *)msg, mlen, s, signer_pub) == 0,
              "blind: tampered R' rejected");

        CHECK(cc_bridge_sm2_blind_verify(Rp, (const uint8_t *)"SN|hole_post|2026-09-18", 26,
                                         s, signer_pub) == 0,
              "blind: tampered message rejected");

        CHECK(cc_bridge_sm2_blind_verify(Rp, (const uint8_t *)msg, mlen, s, other_pub) == 0,
              "blind: wrong signer public key rejected");

        /* 篡改盲化挑战后重新签名 → 去盲也验不过 */
        memcpy(cp2, cp, sizeof(cp2)); cp2[0] ^= 0x01;
        spb.data = sp2; spb.capacity = sizeof(sp2); spb.len = 0;
        CHECK(cc_bridge_sm2_blind_sign(k1, cp2, signer_prv, &spb) == CCB_OK,
              "blind: sign on tampered c' still computes");
        sb.data = s2; sb.capacity = sizeof(s2); sb.len = 0;
        CHECK(cc_bridge_sm2_blind_unblind(sp2, state, &sb) == CCB_OK, "blind: unblind tampered ok");
        CHECK(cc_bridge_sm2_blind_verify(Rp, (const uint8_t *)msg, mlen, s2, signer_pub) == 0,
              "blind: tampered c' cannot produce a valid credential");

        /* 非法输入 */
        CHECK(cc_bridge_sm2_blind_verify(Rp, (const uint8_t *)msg, mlen, s, NULL) ==
                  CCB_INVALID_ARGUMENT,
              "blind: null public key invalid");
        CHECK(cc_bridge_sm2_blind_blind(NULL, signer_pub, (const uint8_t *)msg, mlen,
                                        &cpb, &stb, &Rpb) == CCB_INVALID_ARGUMENT,
              "blind: null R invalid");
        sb.data = s; sb.capacity = sizeof(s); sb.len = 0;
        CHECK(cc_bridge_sm2_blind_unblind(NULL, state, &sb) == CCB_INVALID_ARGUMENT,
              "blind: null s' invalid");
    }

    if (fails == 0) {
        printf("ALL TESTS PASSED\n");
        return 0;
    }
    printf("%d TEST(S) FAILED\n", fails);
    return 1;
}