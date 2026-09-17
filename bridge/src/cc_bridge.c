#include "cc_bridge.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypt_eal_init.h"
#include "crypt_eal_md.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_eal_kdf.h"
#include "crypt_params_key.h"
#include "bsl_params.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_ecc.h"   /* openHiTLS 内部头：ECC 点运算 */
#include "crypt_bn.h"    /* openHiTLS 内部头：大数与模运算 */
#include "bsl_types.h"
#include "bsl_obj.h"
#include "bsl_list.h"
#include "hitls_pki_csr.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_crl.h"
#include "hitls_pki_x509.h"
#include "hitls_pki_errno.h"

static const char *g_version = "cryptocampus-bridge-0.7.0";
static int g_init_done = 0;

static void *cc_malloc(uint32_t len) { return malloc((size_t)len); }

static void cc_report(const char *op, int32_t ret) {
    const char *file = NULL;
    uint32_t line = 0;
    (void)BSL_ERR_GetLastErrorFileLine(&file, &line);
    fprintf(stderr, "cc_bridge: %s failed ret=0x%08x at %s:%u\n",
            op, (unsigned)ret, file ? file : "?", (unsigned)line);
}

static void openhitls_init(void) {
    BSL_ERR_Init();
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, cc_malloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free);
    CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_PROVIDER);
    (void)CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_SHA256, "provider=default", NULL, 0, NULL);
}

/* ---- DER 签名 <-> 64 字节 r||s 转换（openHiTLS 的 SM2 签名是 DER 编码） ---- */

static int cc_int_to_der(const uint8_t *v, uint32_t len, uint8_t *out) {
    uint32_t start = 0, n, pad, o;
    while (start < len && v[start] == 0x00) start++;
    n = len - start;
    if (n == 0) {
        out[0] = 0x02; out[1] = 0x01; out[2] = 0x00;
        return 3;
    }
    pad = (v[start] & 0x80) ? 1u : 0u;
    out[0] = 0x02;
    out[1] = (uint8_t)(n + pad);
    o = 2;
    if (pad) out[o++] = 0x00;
    memcpy(out + o, v + start, n);
    return (int)(o + n);
}

static int cc_raw_sig_to_der(const uint8_t raw[64], uint8_t *der, uint32_t *der_len) {
    uint8_t body[80];
    int n = 0;
    n += cc_int_to_der(raw, 32, body + n);
    n += cc_int_to_der(raw + 32, 32, body + n);
    if (n > 127) return -1;
    der[0] = 0x30;
    der[1] = (uint8_t)n;
    memcpy(der + 2, body, (size_t)n);
    memset(body, 0, sizeof(body));
    *der_len = (uint32_t)n + 2;
    return 0;
}

static int cc_der_sig_to_raw(const uint8_t *der, uint32_t der_len, uint8_t out[64]) {
    uint32_t i = 0, r_len, s_len;
    if (der_len < 8 || der[0] != 0x30) return -1;
    i = 1;
    if (der[i] & 0x80) return -1;   /* 只处理短长度形式 */
    i += 1;
    if (der[i] != 0x02) return -1;
    i += 1;
    r_len = der[i++];
    if (i + r_len + 2 > der_len) return -1;
    if (der[i + r_len] != 0x02) return -1;
    s_len = der[i + r_len + 1];
    if (i + r_len + 2 + s_len > der_len) return -1;

    memset(out, 0, 64);
    {
        const uint8_t *r = der + i;
        uint32_t rl = r_len;
        while (rl > 0 && *r == 0x00) { r++; rl--; }
        if (rl > 32) return -1;
        memcpy(out + (32 - rl), r, rl);
    }
    {
        const uint8_t *s = der + i + r_len + 2;
        uint32_t sl = s_len;
        while (sl > 0 && *s == 0x00) { s++; sl--; }
        if (sl > 32) return -1;
        memcpy(out + 32 + (32 - sl), s, sl);
    }
    return 0;
}

/* ------------------------------------------------------------------ */

int cc_bridge_init(const char *provider_dir) {
    (void)provider_dir;
    if (!g_init_done) { openhitls_init(); g_init_done = 1; }
    return CCB_OK;
}

const char *cc_bridge_version(void) { return g_version; }

int cc_bridge_random_bytes(uint8_t *out, size_t out_len) {
    size_t n;
    FILE *f;
    if (out == NULL || out_len == 0) return CCB_INVALID_ARGUMENT;
    f = fopen("/dev/urandom", "rb");
    if (f == NULL) return CCB_RANDOM_FAILED;
    n = fread(out, 1, out_len, f);
    fclose(f);
    if (n != out_len) return CCB_RANDOM_FAILED;
    return CCB_OK;
}

int cc_bridge_sm3_digest(const uint8_t *message, size_t message_len,
                         cc_bridge_buffer *digest) {
    uint32_t out_len;
    int32_t ret;
    if (digest == NULL) return CCB_INVALID_ARGUMENT;
    if (message == NULL && message_len > 0) return CCB_INVALID_ARGUMENT;
    if (digest->data == NULL || digest->capacity < 32) return CCB_BUFFER_TOO_SMALL;
    if (!g_init_done) { openhitls_init(); g_init_done = 1; }

    out_len = (uint32_t)digest->capacity;
    ret = CRYPT_EAL_Md(CRYPT_MD_SM3, message, (uint32_t)message_len, digest->data, &out_len);
    if (ret != CRYPT_SUCCESS) { cc_report("CRYPT_EAL_Md(SM3)", ret); return CCB_INTERNAL_ERROR; }
    digest->len = out_len;
    return CCB_OK;
}

int cc_bridge_sm3_hash_password(const uint8_t *password_utf8, size_t password_len,
                                const uint8_t *salt_a, size_t salt_a_len,
                                cc_bridge_buffer *auth_hash) {
    uint8_t buf[640];
    uint32_t out_len;
    int32_t ret;
    size_t total;

    if (password_utf8 == NULL || salt_a == NULL || auth_hash == NULL) return CCB_INVALID_ARGUMENT;
    if (auth_hash->data == NULL || auth_hash->capacity < 32) return CCB_BUFFER_TOO_SMALL;
    if (password_len == 0 || password_len > 512) return CCB_INVALID_ARGUMENT;
    if (salt_a_len < 16 || salt_a_len > 64) return CCB_INVALID_ARGUMENT;
    total = salt_a_len + password_len;
    if (total > sizeof(buf)) return CCB_INVALID_ARGUMENT;
    if (!g_init_done) { openhitls_init(); g_init_done = 1; }

    memcpy(buf, salt_a, salt_a_len);
    memcpy(buf + salt_a_len, password_utf8, password_len);

    out_len = (uint32_t)auth_hash->capacity;
    ret = CRYPT_EAL_Md(CRYPT_MD_SM3, buf, (uint32_t)total, auth_hash->data, &out_len);
    memset(buf, 0, sizeof(buf));
    if (ret != CRYPT_SUCCESS) { cc_report("CRYPT_EAL_Md(SM3 password)", ret); return CCB_INTERNAL_ERROR; }
    auth_hash->len = out_len;
    return CCB_OK;
}

int cc_bridge_hkdf_sm3(const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len,
                       cc_bridge_buffer *out) {
    CRYPT_EAL_KdfCtx *ctx;
    CRYPT_MAC_AlgId mac_id = CRYPT_MAC_HMAC_SM3;
    uint32_t mode = CRYPT_KDF_HKDF_MODE_FULL;
    BSL_Param params[6] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    const uint8_t *salt_ptr;
    int32_t ret;

    if (ikm == NULL || info == NULL || out == NULL) return CCB_INVALID_ARGUMENT;
    if (ikm_len == 0 || ikm_len > 4096) return CCB_INVALID_ARGUMENT;
    if (info_len == 0 || info_len > 128) return CCB_INVALID_ARGUMENT;
    if (salt == NULL && salt_len != 0) return CCB_INVALID_ARGUMENT;
    if (salt_len > 64) return CCB_INVALID_ARGUMENT;
    if (out->data == NULL || out->capacity < 16 || out->capacity > 64) return CCB_BUFFER_TOO_SMALL;
    if (!g_init_done) { openhitls_init(); g_init_done = 1; }

    salt_ptr = (salt != NULL) ? salt : (const uint8_t *)"";

    ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    if (ctx == NULL) { cc_report("KdfNewCtx(HKDF)", -1); return CCB_INTERNAL_ERROR; }

    (void)BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
                              &mac_id, sizeof(mac_id));
    (void)BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
                              (void *)ikm, (uint32_t)ikm_len);
    (void)BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
                              (void *)salt_ptr, (uint32_t)salt_len);
    (void)BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS,
                              (void *)info, (uint32_t)info_len);
    (void)BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32,
                              &mode, sizeof(mode));

    ret = CRYPT_EAL_KdfSetParam(ctx, params);
    if (ret != CRYPT_SUCCESS) {
        cc_report("KdfSetParam(HKDF)", ret);
        CRYPT_EAL_KdfFreeCtx(ctx);
        return CCB_INTERNAL_ERROR;
    }
    ret = CRYPT_EAL_KdfDerive(ctx, out->data, (uint32_t)out->capacity);
    CRYPT_EAL_KdfFreeCtx(ctx);
    if (ret != CRYPT_SUCCESS) { cc_report("KdfDerive(HKDF)", ret); return CCB_INTERNAL_ERROR; }
    out->len = out->capacity;
    return CCB_OK;
}
int cc_bridge_sm4_gcm_encrypt(const uint8_t *key, const uint8_t *plaintext, size_t plaintext_len,
                              const uint8_t *aad, size_t aad_len,
                              cc_bridge_buffer *ciphertext, cc_bridge_buffer *nonce, cc_bridge_buffer *tag) {
    CRYPT_EAL_CipherCtx *ctx;
    uint32_t out_len, final_len, tag_len = 16;
    int32_t ret;

    if (key == NULL || ciphertext == NULL || nonce == NULL || tag == NULL) return CCB_INVALID_ARGUMENT;
    if (plaintext == NULL && plaintext_len > 0) return CCB_INVALID_ARGUMENT;
    if (nonce->data == NULL || nonce->capacity < 12) return CCB_BUFFER_TOO_SMALL;
    if (tag->data == NULL || tag->capacity < 16) return CCB_BUFFER_TOO_SMALL;
    if (ciphertext->data == NULL || ciphertext->capacity < plaintext_len + 16) return CCB_BUFFER_TOO_SMALL;
    if (!g_init_done) { openhitls_init(); g_init_done = 1; }

    if (cc_bridge_random_bytes(nonce->data, 12) != CCB_OK) return CCB_RANDOM_FAILED;
    nonce->len = 12;

    ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_GCM);
    if (ctx == NULL) return CCB_INTERNAL_ERROR;
    ret = CRYPT_EAL_CipherInit(ctx, key, 16, nonce->data, 12, true);
    if (ret != CRYPT_SUCCESS) { CRYPT_EAL_CipherFreeCtx(ctx); return CCB_INTERNAL_ERROR; }
    (void)CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tag_len, sizeof(tag_len));
    if (aad != NULL && aad_len > 0) {
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, (void *)aad, (uint32_t)aad_len);
        if (ret != CRYPT_SUCCESS) { CRYPT_EAL_CipherFreeCtx(ctx); return CCB_INTERNAL_ERROR; }
    }

    out_len = (uint32_t)ciphertext->capacity;
    ret = CRYPT_EAL_CipherUpdate(ctx, plaintext, (uint32_t)plaintext_len, ciphertext->data, &out_len);
    if (ret != CRYPT_SUCCESS) { CRYPT_EAL_CipherFreeCtx(ctx); return CCB_INTERNAL_ERROR; }
    final_len = (uint32_t)(ciphertext->capacity - out_len);
    ret = CRYPT_EAL_CipherFinal(ctx, ciphertext->data + out_len, &final_len);
    if (ret != CRYPT_SUCCESS) { CRYPT_EAL_CipherFreeCtx(ctx); return CCB_INTERNAL_ERROR; }
    ciphertext->len = out_len + final_len;

    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag->data, 16);
    CRYPT_EAL_CipherFreeCtx(ctx);
    if (ret != CRYPT_SUCCESS) return CCB_INTERNAL_ERROR;
    tag->len = 16;
    return CCB_OK;
}

int cc_bridge_sm4_gcm_decrypt(const uint8_t *key, const uint8_t *nonce,
                              const uint8_t *ciphertext, size_t ciphertext_len,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *tag, size_t tag_len,
                              cc_bridge_buffer *plaintext) {
    CRYPT_EAL_CipherCtx *ctx;
    uint32_t out_len, final_len, set_taglen = 16;
    int32_t ret;

    if (key == NULL || nonce == NULL || tag == NULL || plaintext == NULL) return CCB_INVALID_ARGUMENT;
    if (ciphertext == NULL && ciphertext_len > 0) return CCB_INVALID_ARGUMENT;
    if (tag_len != 16) return CCB_INVALID_ARGUMENT;
    if (plaintext->data == NULL || plaintext->capacity < ciphertext_len) return CCB_BUFFER_TOO_SMALL;
    if (!g_init_done) { openhitls_init(); g_init_done = 1; }

    ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_GCM);
    if (ctx == NULL) return CCB_INTERNAL_ERROR;
    ret = CRYPT_EAL_CipherInit(ctx, key, 16, nonce, 12, false);
    if (ret != CRYPT_SUCCESS) { CRYPT_EAL_CipherFreeCtx(ctx); return CCB_INTERNAL_ERROR; }
    (void)CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &set_taglen, sizeof(set_taglen));
    if (aad != NULL && aad_len > 0) {
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, (void *)aad, (uint32_t)aad_len);
        if (ret != CRYPT_SUCCESS) { CRYPT_EAL_CipherFreeCtx(ctx); return CCB_INTERNAL_ERROR; }
    }
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAG, (void *)tag, (uint32_t)tag_len);
    if (ret != CRYPT_SUCCESS) { CRYPT_EAL_CipherFreeCtx(ctx); return CCB_INTERNAL_ERROR; }

    out_len = (uint32_t)plaintext->capacity;
    ret = CRYPT_EAL_CipherUpdate(ctx, ciphertext, (uint32_t)ciphertext_len, plaintext->data, &out_len);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(ctx);
        memset(plaintext->data, 0, plaintext->capacity);
        plaintext->len = 0;
        return CCB_INTEGRITY_FAILED;
    }
    final_len = (uint32_t)(plaintext->capacity - out_len);
    ret = CRYPT_EAL_CipherFinal(ctx, plaintext->data + out_len, &final_len);
    CRYPT_EAL_CipherFreeCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        memset(plaintext->data, 0, plaintext->capacity);
        plaintext->len = 0;
        return CCB_INTEGRITY_FAILED;
    }
    plaintext->len = out_len + final_len;
    return CCB_OK;
}

int cc_bridge_sm2_generate_keypair(cc_bridge_buffer *private_key, cc_bridge_buffer *public_key) {
    CRYPT_EAL_PkeyCtx *ctx;
    CRYPT_EAL_PkeyPrv prv;
    CRYPT_EAL_PkeyPub pub;
    int32_t ret;

    if (private_key == NULL || public_key == NULL) return CCB_INVALID_ARGUMENT;
    if (private_key->data == NULL || private_key->capacity < 32) return CCB_BUFFER_TOO_SMALL;
    if (public_key->data == NULL || public_key->capacity < 65) return CCB_BUFFER_TOO_SMALL;
    if (!g_init_done) { openhitls_init(); g_init_done = 1; }

    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    if (ctx == NULL) { cc_report("PkeyNewCtx(SM2)", -1); return CCB_INTERNAL_ERROR; }
    ret = CRYPT_EAL_PkeyGen(ctx);
    if (ret != CRYPT_SUCCESS) { cc_report("PkeyGen", ret); CRYPT_EAL_PkeyFreeCtx(ctx); return CCB_INTERNAL_ERROR; }

    memset(&prv, 0, sizeof(prv));
    memset(&pub, 0, sizeof(pub));
    prv.id = CRYPT_PKEY_SM2;
    pub.id = CRYPT_PKEY_SM2;
    prv.key.eccPrv.data = private_key->data;
    prv.key.eccPrv.len = (uint32_t)private_key->capacity;
    pub.key.eccPub.data = public_key->data;
    pub.key.eccPub.len = (uint32_t)public_key->capacity;

    ret = CRYPT_EAL_PkeyGetPrv(ctx, &prv);
    if (ret != CRYPT_SUCCESS) { cc_report("PkeyGetPrv", ret); CRYPT_EAL_PkeyFreeCtx(ctx); return CCB_INTERNAL_ERROR; }
    ret = CRYPT_EAL_PkeyGetPub(ctx, &pub);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    if (ret != CRYPT_SUCCESS) { cc_report("PkeyGetPub", ret); return CCB_INTERNAL_ERROR; }

    if (prv.key.eccPrv.len != 32 || pub.key.eccPub.len != 65) return CCB_INTERNAL_ERROR;
    private_key->len = 32;
    public_key->len = 65;
    return CCB_OK;
}

int cc_bridge_sm2_sign(const uint8_t *private_key, const uint8_t *digest,
                       cc_bridge_buffer *signature) {
    CRYPT_EAL_PkeyCtx *ctx;
    CRYPT_EAL_PkeyPrv prv;
    uint8_t der[128];
    uint8_t raw[64];
    uint32_t der_len = (uint32_t)sizeof(der);
    int32_t ret;

    if (private_key == NULL || digest == NULL || signature == NULL) return CCB_INVALID_ARGUMENT;
    if (signature->data == NULL || signature->capacity < 64) return CCB_BUFFER_TOO_SMALL;
    if (!g_init_done) { openhitls_init(); g_init_done = 1; }

    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    if (ctx == NULL) { cc_report("PkeyNewCtx(SM2)", -1); return CCB_INTERNAL_ERROR; }
    (void)CRYPT_EAL_PkeySetParaById(ctx, CRYPT_ECC_SM2);

    memset(&prv, 0, sizeof(prv));
    prv.id = CRYPT_PKEY_SM2;
    prv.key.eccPrv.data = (uint8_t *)private_key;
    prv.key.eccPrv.len = 32;
    ret = CRYPT_EAL_PkeySetPrv(ctx, &prv);
    if (ret != CRYPT_SUCCESS) { cc_report("PkeySetPrv(sign)", ret); CRYPT_EAL_PkeyFreeCtx(ctx); return CCB_INTERNAL_ERROR; }

    /* openHiTLS 的 SM2 签名为 DER 编码，需给足缓冲（最长 72 字节） */
    ret = CRYPT_EAL_PkeySignData(ctx, digest, 32, der, &der_len);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    if (ret != CRYPT_SUCCESS) { cc_report("PkeySignData", ret); return CCB_INTERNAL_ERROR; }

    if (cc_der_sig_to_raw(der, der_len, raw) != 0) {
        fprintf(stderr, "cc_bridge: DER signature decode failed (len=%u)\n", (unsigned)der_len);
        memset(der, 0, sizeof(der));
        return CCB_INTERNAL_ERROR;
    }
    memcpy(signature->data, raw, 64);
    signature->len = 64;
    memset(der, 0, sizeof(der));
    memset(raw, 0, sizeof(raw));
    return CCB_OK;
}

int cc_bridge_sm2_verify(const uint8_t *public_key, const uint8_t *digest,
                         const uint8_t *signature, size_t signature_len) {
    CRYPT_EAL_PkeyCtx *ctx;
    CRYPT_EAL_PkeyPub pub;
    uint8_t der[80];
    uint32_t der_len = 0;
    int32_t ret;

    if (public_key == NULL || digest == NULL || signature == NULL) return CCB_INVALID_ARGUMENT;
    if (signature_len != 64) return CCB_INVALID_ARGUMENT;
    if (!g_init_done) { openhitls_init(); g_init_done = 1; }

    if (cc_raw_sig_to_der(signature, der, &der_len) != 0) return 0;

    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    if (ctx == NULL) { cc_report("PkeyNewCtx(SM2)", -1); return CCB_INTERNAL_ERROR; }
    (void)CRYPT_EAL_PkeySetParaById(ctx, CRYPT_ECC_SM2);

    memset(&pub, 0, sizeof(pub));
    pub.id = CRYPT_PKEY_SM2;
    pub.key.eccPub.data = (uint8_t *)public_key;
    pub.key.eccPub.len = 65;
    ret = CRYPT_EAL_PkeySetPub(ctx, &pub);
    if (ret != CRYPT_SUCCESS) { cc_report("PkeySetPub(verify)", ret); CRYPT_EAL_PkeyFreeCtx(ctx); return CCB_INTERNAL_ERROR; }

    ret = CRYPT_EAL_PkeyVerifyData(ctx, digest, 32, der, der_len);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    memset(der, 0, sizeof(der));
    return (ret == CRYPT_SUCCESS) ? 1 : 0;
}

int cc_bridge_sm2_encrypt(const uint8_t *public_key, const uint8_t *plaintext, size_t plaintext_len,
                          cc_bridge_buffer *ciphertext) {
    CRYPT_EAL_PkeyCtx *ctx;
    CRYPT_EAL_PkeyPub pub;
    uint32_t out_len;
    int32_t ret;

    if (public_key == NULL || plaintext == NULL || ciphertext == NULL) return CCB_INVALID_ARGUMENT;
    if (ciphertext->data == NULL || ciphertext->capacity < plaintext_len + 128) return CCB_BUFFER_TOO_SMALL;
    if (!g_init_done) { openhitls_init(); g_init_done = 1; }

    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    if (ctx == NULL) { cc_report("PkeyNewCtx(SM2)", -1); return CCB_INTERNAL_ERROR; }
    (void)CRYPT_EAL_PkeySetParaById(ctx, CRYPT_ECC_SM2);

    memset(&pub, 0, sizeof(pub));
    pub.id = CRYPT_PKEY_SM2;
    pub.key.eccPub.data = (uint8_t *)public_key;
    pub.key.eccPub.len = 65;
    ret = CRYPT_EAL_PkeySetPub(ctx, &pub);
    if (ret != CRYPT_SUCCESS) { cc_report("PkeySetPub(encrypt)", ret); CRYPT_EAL_PkeyFreeCtx(ctx); return CCB_INTERNAL_ERROR; }

    out_len = (uint32_t)ciphertext->capacity;
    ret = CRYPT_EAL_PkeyEncrypt(ctx, plaintext, (uint32_t)plaintext_len, ciphertext->data, &out_len);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    if (ret != CRYPT_SUCCESS) { cc_report("PkeyEncrypt", ret); return CCB_INTERNAL_ERROR; }
    ciphertext->len = out_len;
    return CCB_OK;
}

int cc_bridge_sm2_decrypt(const uint8_t *private_key, const uint8_t *ciphertext, size_t ciphertext_len,
                          cc_bridge_buffer *plaintext) {
    CRYPT_EAL_PkeyCtx *ctx;
    CRYPT_EAL_PkeyPrv prv;
    uint32_t out_len;
    int32_t ret;

    if (private_key == NULL || ciphertext == NULL || plaintext == NULL) return CCB_INVALID_ARGUMENT;
    if (plaintext->data == NULL || plaintext->capacity == 0) return CCB_BUFFER_TOO_SMALL;
    if (!g_init_done) { openhitls_init(); g_init_done = 1; }

    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    if (ctx == NULL) { cc_report("PkeyNewCtx(SM2)", -1); return CCB_INTERNAL_ERROR; }
    (void)CRYPT_EAL_PkeySetParaById(ctx, CRYPT_ECC_SM2);

    memset(&prv, 0, sizeof(prv));
    prv.id = CRYPT_PKEY_SM2;
    prv.key.eccPrv.data = (uint8_t *)private_key;
    prv.key.eccPrv.len = 32;
    ret = CRYPT_EAL_PkeySetPrv(ctx, &prv);
    if (ret != CRYPT_SUCCESS) { cc_report("PkeySetPrv(decrypt)", ret); CRYPT_EAL_PkeyFreeCtx(ctx); return CCB_INTERNAL_ERROR; }

    out_len = (uint32_t)plaintext->capacity;
    ret = CRYPT_EAL_PkeyDecrypt(ctx, ciphertext, (uint32_t)ciphertext_len, plaintext->data, &out_len);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        memset(plaintext->data, 0, plaintext->capacity);
        plaintext->len = 0;
        return CCB_INTEGRITY_FAILED;
    }
    plaintext->len = out_len;
    return CCB_OK;
}

int cc_bridge_sm2_ecdh(const uint8_t *private_key, const uint8_t *peer_public_key,
                       cc_bridge_buffer *shared_secret) {
    /* SM2 的密钥交换是完整的双方案协议（需 R 值/角色/校验和），
     * 契约要求的是标准 ECDH，故使用 ECDH + SM2 曲线（CRYPT_ECC_SM2）。 */
    CRYPT_EAL_PkeyCtx *prv_ctx = NULL;
    CRYPT_EAL_PkeyCtx *pub_ctx = NULL;
    CRYPT_EAL_PkeyPrv prv;
    CRYPT_EAL_PkeyPub pub;
    uint32_t share_len = 32;
    int32_t ret;

    if (private_key == NULL || peer_public_key == NULL || shared_secret == NULL) return CCB_INVALID_ARGUMENT;
    if (shared_secret->data == NULL || shared_secret->capacity < 32) return CCB_BUFFER_TOO_SMALL;
    if (!g_init_done) { openhitls_init(); g_init_done = 1; }

    prv_ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    pub_ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    if (prv_ctx == NULL || pub_ctx == NULL) {
        if (prv_ctx != NULL) CRYPT_EAL_PkeyFreeCtx(prv_ctx);
        if (pub_ctx != NULL) CRYPT_EAL_PkeyFreeCtx(pub_ctx);
        cc_report("PkeyNewCtx(ECDH)", -1);
        return CCB_INTERNAL_ERROR;
    }

    ret = CRYPT_EAL_PkeySetParaById(prv_ctx, CRYPT_ECC_SM2);
    if (ret == CRYPT_SUCCESS) ret = CRYPT_EAL_PkeySetParaById(pub_ctx, CRYPT_ECC_SM2);
    if (ret != CRYPT_SUCCESS) { cc_report("PkeySetParaById(ECDH)", ret); goto EXIT; }

    memset(&prv, 0, sizeof(prv));
    memset(&pub, 0, sizeof(pub));
    prv.id = CRYPT_PKEY_ECDH;
    pub.id = CRYPT_PKEY_ECDH;
    prv.key.eccPrv.data = (uint8_t *)private_key;
    prv.key.eccPrv.len = 32;
    pub.key.eccPub.data = (uint8_t *)peer_public_key;
    pub.key.eccPub.len = 65;

    ret = CRYPT_EAL_PkeySetPrv(prv_ctx, &prv);
    if (ret != CRYPT_SUCCESS) { cc_report("PkeySetPrv(ecdh)", ret); goto EXIT; }
    ret = CRYPT_EAL_PkeySetPub(pub_ctx, &pub);
    if (ret != CRYPT_SUCCESS) { cc_report("PkeySetPub(ecdh)", ret); goto EXIT; }

    share_len = 32;
    ret = CRYPT_EAL_PkeyComputeShareKey(prv_ctx, pub_ctx, shared_secret->data, &share_len);
    if (ret != CRYPT_SUCCESS) { cc_report("PkeyComputeShareKey", ret); goto EXIT; }

EXIT:
    CRYPT_EAL_PkeyFreeCtx(prv_ctx);
    CRYPT_EAL_PkeyFreeCtx(pub_ctx);
    if (ret != CRYPT_SUCCESS) return CCB_INTERNAL_ERROR;
    shared_secret->len = share_len;
    return CCB_OK;
}

int cc_bridge_constant_time_equal(const uint8_t *a, size_t a_len,
                                  const uint8_t *b, size_t b_len) {
    uint8_t diff = 0;
    size_t i;
    if (a == NULL || b == NULL) return 0;
    if (a_len != b_len) return 0;
    for (i = 0; i < a_len; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return (diff == 0) ? 1 : 0;
}

void cc_bridge_buffer_free(void *ptr, size_t len, int sensitive) {
    volatile uint8_t *p;
    if (ptr == NULL) return;
    if (sensitive) { p = (volatile uint8_t *)ptr; while (len--) *p++ = 0; }
    free(ptr);
}

/* ==========================================================================
 * 数字信封 v2（对齐 server/app/crypto/engine.py + types.py 契约）
 *
 *   sender_signature = SM2_sign(sender_priv, SM3(ciphertext))
 *   K = HKDF-SM3(ikm=seed, salt=access_factor|"", info="drop-access-factor", 16)
 *   SM4-GCM AAD = "CryptoCampus-Drop-v1"
 *   enc_key_sm2 = SM2_encrypt(recipient_pub, seed)
 * pqc_mode != 0 当前返回 CCB_UNSUPPORTED（ML-KEM 分量待接）。
 * ========================================================================== */

#define CC_ENV_DOMAIN       "CryptoCampus-Drop-v1"
#define CC_ENV_KDF_INFO     "drop-access-factor"
#define CC_ENV_SEED_SIZE    16
#define CC_ENV_KEY_SIZE     16

int cc_bridge_envelope_seal(const uint8_t *plaintext, size_t plaintext_len,
                            const uint8_t *recipient_sm2_public_key,
                            int pqc_mode,
                            const uint8_t *recipient_mlkem_public_key,
                            const uint8_t *sender_private_key,
                            const uint8_t *sender_certificate_der, size_t sender_certificate_len,
                            const uint8_t *access_factor, size_t access_factor_len,
                            cc_bridge_envelope *out) {
    uint8_t seed[CC_ENV_SEED_SIZE];
    uint8_t key[CC_ENV_KEY_SIZE];
    uint8_t digest[32];
    cc_bridge_buffer seed_buf = { seed, sizeof(seed), 0 };
    cc_bridge_buffer key_buf = { key, sizeof(key), 0 };
    cc_bridge_buffer digest_buf = { digest, sizeof(digest), 0 };
    int rc;

    if (out == NULL) return CCB_INVALID_ARGUMENT;
    if (plaintext == NULL || plaintext_len == 0) return CCB_INVALID_ARGUMENT;
    if (recipient_sm2_public_key == NULL) return CCB_INVALID_ARGUMENT;
    if (sender_private_key == NULL) return CCB_INVALID_ARGUMENT;
    if (sender_certificate_der == NULL || sender_certificate_len == 0) return CCB_INVALID_ARGUMENT;
    if (access_factor == NULL && access_factor_len != 0) return CCB_INVALID_ARGUMENT;
    if (access_factor != NULL && (access_factor_len < 16 || access_factor_len > 32)) return CCB_INVALID_ARGUMENT;
    if (pqc_mode != 0) return CCB_UNSUPPORTED;
    if (recipient_mlkem_public_key != NULL) return CCB_INVALID_ARGUMENT;
    if (out->ciphertext.data == NULL || out->ciphertext.capacity < plaintext_len + 16) return CCB_BUFFER_TOO_SMALL;
    if (out->nonce.data == NULL || out->nonce.capacity < 12) return CCB_BUFFER_TOO_SMALL;
    if (out->tag.data == NULL || out->tag.capacity < 16) return CCB_BUFFER_TOO_SMALL;
    if (out->enc_key_sm2.data == NULL || out->enc_key_sm2.capacity < 512) return CCB_BUFFER_TOO_SMALL;
    if (out->sender_signature.data == NULL || out->sender_signature.capacity < 64) return CCB_BUFFER_TOO_SMALL;
    if (out->sender_certificate.data == NULL || out->sender_certificate.capacity < sender_certificate_len) return CCB_BUFFER_TOO_SMALL;
    if (!g_init_done) { openhitls_init(); g_init_done = 1; }

    /* 1. 会话种子 */
    rc = cc_bridge_random_bytes(seed, sizeof(seed));
    if (rc != CCB_OK) return rc;

    /* 2. K = HKDF-SM3(seed, access_factor|"", "drop-access-factor", 16) */
    rc = cc_bridge_hkdf_sm3(seed, sizeof(seed), access_factor, access_factor_len,
                            (const uint8_t *)CC_ENV_KDF_INFO, strlen(CC_ENV_KDF_INFO), &key_buf);
    if (rc != CCB_OK) goto EXIT;

    /* 3. SM4-GCM（AAD = 域分隔常量） */
    rc = cc_bridge_sm4_gcm_encrypt(key, plaintext, plaintext_len,
                                   (const uint8_t *)CC_ENV_DOMAIN, strlen(CC_ENV_DOMAIN),
                                   &out->ciphertext, &out->nonce, &out->tag);
    if (rc != CCB_OK) goto EXIT;

    /* 4. SM2 封装种子 */
    rc = cc_bridge_sm2_encrypt(recipient_sm2_public_key, seed, sizeof(seed), &out->enc_key_sm2);
    if (rc != CCB_OK) goto EXIT;

    /* 5. sender_signature = SM2_sign(priv, SM3(ciphertext)) —— 与 drop.py 一致 */
    rc = cc_bridge_sm3_digest(out->ciphertext.data, out->ciphertext.len, &digest_buf);
    if (rc != CCB_OK) goto EXIT;
    rc = cc_bridge_sm2_sign(sender_private_key, digest, &out->sender_signature);
    if (rc != CCB_OK) goto EXIT;

    /* 6. 回填证书；PQC 分量留空 */
    memcpy(out->sender_certificate.data, sender_certificate_der, sender_certificate_len);
    out->sender_certificate.len = sender_certificate_len;
    out->enc_key_mlkem.len = 0;

EXIT:
    memset(seed, 0, sizeof(seed));
    memset(key, 0, sizeof(key));
    memset(digest, 0, sizeof(digest));
    return rc;
}

int cc_bridge_envelope_open(const cc_bridge_envelope *env,
                            const uint8_t *recipient_sm2_private_key,
                            int pqc_mode,
                            const uint8_t *recipient_mlkem_private_key,
                            const uint8_t *access_factor, size_t access_factor_len,
                            cc_bridge_buffer *plaintext) {
    uint8_t seed[CC_ENV_SEED_SIZE];
    uint8_t key[CC_ENV_KEY_SIZE];
    cc_bridge_buffer seed_buf = { seed, sizeof(seed), 0 };
    cc_bridge_buffer key_buf = { key, sizeof(key), 0 };
    int rc;

    if (env == NULL || plaintext == NULL) return CCB_INVALID_ARGUMENT;
    if (recipient_sm2_private_key == NULL) return CCB_INVALID_ARGUMENT;
    if (env->ciphertext.data == NULL || env->ciphertext.len == 0) return CCB_INVALID_ARGUMENT;
    if (env->nonce.data == NULL || env->nonce.len != 12) return CCB_INVALID_ARGUMENT;
    if (env->tag.data == NULL || env->tag.len != 16) return CCB_INVALID_ARGUMENT;
    if (env->enc_key_sm2.data == NULL || env->enc_key_sm2.len == 0 || env->enc_key_sm2.len > 512) return CCB_INVALID_ARGUMENT;
    if (env->sender_signature.len != 64) return CCB_INVALID_ARGUMENT;
    if (env->enc_key_mlkem.len != 0) return CCB_INVALID_ARGUMENT;
    if (access_factor == NULL && access_factor_len != 0) return CCB_INVALID_ARGUMENT;
    if (access_factor != NULL && (access_factor_len < 16 || access_factor_len > 32)) return CCB_INVALID_ARGUMENT;
    if (pqc_mode != 0) return CCB_UNSUPPORTED;
    if (recipient_mlkem_private_key != NULL) return CCB_INVALID_ARGUMENT;
    if (plaintext->data == NULL || plaintext->capacity < env->ciphertext.len) return CCB_BUFFER_TOO_SMALL;
    if (!g_init_done) { openhitls_init(); g_init_done = 1; }

    /* 1. SM2 解封种子（错钥/篡改 → INTEGRITY_FAILED） */
    rc = cc_bridge_sm2_decrypt(recipient_sm2_private_key,
                               env->enc_key_sm2.data, env->enc_key_sm2.len, &seed_buf);
    if (rc != CCB_OK) goto EXIT;
    if (seed_buf.len != CC_ENV_SEED_SIZE) { rc = CCB_INTEGRITY_FAILED; goto EXIT; }

    /* 2. K = HKDF-SM3(seed, access_factor|"", "drop-access-factor", 16) */
    rc = cc_bridge_hkdf_sm3(seed, sizeof(seed), access_factor, access_factor_len,
                            (const uint8_t *)CC_ENV_KDF_INFO, strlen(CC_ENV_KDF_INFO), &key_buf);
    if (rc != CCB_OK) goto EXIT;

    /* 3. SM4-GCM 解密（tag/AAD/密文篡改或因子错误 → INTEGRITY_FAILED） */
    rc = cc_bridge_sm4_gcm_decrypt(key, env->nonce.data,
                                   env->ciphertext.data, env->ciphertext.len,
                                   (const uint8_t *)CC_ENV_DOMAIN, strlen(CC_ENV_DOMAIN),
                                   env->tag.data, env->tag.len, plaintext);

EXIT:
    memset(seed, 0, sizeof(seed));
    memset(key, 0, sizeof(key));
    return rc;
}

/* ==========================================================================
 * PKI：CSR / 证书签发 / 证书链验证 / CRL
 * 用法对齐 openHiTLS 官方 apps/src/app_req.c / app_x509.c / app_verify.c /
 * app_crl.c 与 include/pki/*.h。
 * ========================================================================== */

static int cc_pki_copy_out(const BSL_Buffer *src, cc_bridge_buffer *dst) {
    if (src == NULL || src->data == NULL || src->dataLen == 0) return CCB_INTERNAL_ERROR;
    if (dst == NULL) return CCB_INVALID_ARGUMENT;
    if (dst->data == NULL || dst->capacity < (size_t)src->dataLen) return CCB_BUFFER_TOO_SMALL;
    (void)memcpy(dst->data, src->data, (size_t)src->dataLen);
    dst->len = (size_t)src->dataLen;
    return CCB_OK;
}

/* 造 SM2 pkey ctx。pub 传 NULL 表示只需私钥（纯签名场景）。 */
static CRYPT_EAL_PkeyCtx *cc_pki_new_sm2_ctx(const uint8_t *prv, size_t prv_len,
                                             const uint8_t *pub, size_t pub_len) {
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyPrv prv_param;
    CRYPT_EAL_PkeyPub pub_param;
    int32_t ret;

    if (prv == NULL || prv_len != 32) return NULL;
    if (pub != NULL && pub_len != 65) return NULL;

    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    if (ctx == NULL) return NULL;

    /* SM2 曲线内禀于 CRYPT_PKEY_SM2；SetParaById 返回 0x0116000d 属无害，
     * 与既有 sm2_sign/verify/encrypt/decrypt 一致：忽略返回值即可。 */
    (void)CRYPT_EAL_PkeySetParaById(ctx, CRYPT_ECC_SM2);

    memset(&prv_param, 0, sizeof(prv_param));
    prv_param.id = CRYPT_PKEY_SM2;
    prv_param.key.eccPrv.data = (uint8_t *)prv;
    prv_param.key.eccPrv.len = (uint32_t)prv_len;
    ret = CRYPT_EAL_PkeySetPrv(ctx, &prv_param);
    if (ret != CRYPT_SUCCESS) { cc_report("PkeySetPrv(PKI)", ret); goto FAIL; }

    if (pub != NULL) {
        memset(&pub_param, 0, sizeof(pub_param));
        pub_param.id = CRYPT_PKEY_SM2;
        pub_param.key.eccPub.data = (uint8_t *)pub;
        pub_param.key.eccPub.len = (uint32_t)pub_len;
        ret = CRYPT_EAL_PkeySetPub(ctx, &pub_param);
        if (ret != CRYPT_SUCCESS) { cc_report("PkeySetPub(PKI)", ret); goto FAIL; }
    }
    return ctx;
FAIL:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return NULL;
}

int cc_bridge_csr_create(const uint8_t *private_key, size_t private_key_len,
                         const uint8_t *public_key, size_t public_key_len,
                         const char *common_name,
                         cc_bridge_buffer *csr_der) {
    CRYPT_EAL_PkeyCtx *key = NULL;
    HITLS_X509_Csr *csr = NULL;
    HITLS_X509_DN dn;
    BSL_Buffer out;
    int32_t ret;
    int rc = CCB_INTERNAL_ERROR;

    if (csr_der == NULL || csr_der->data == NULL) return CCB_INVALID_ARGUMENT;
    if (private_key == NULL || private_key_len != 32) return CCB_INVALID_ARGUMENT;
    if (public_key == NULL || public_key_len != 65) return CCB_INVALID_ARGUMENT;
    if (common_name == NULL || common_name[0] == '\0') return CCB_INVALID_ARGUMENT;
    if (!g_init_done) { openhitls_init(); g_init_done = 1; }

    memset(&out, 0, sizeof(out));

    key = cc_pki_new_sm2_ctx(private_key, private_key_len, public_key, public_key_len);
    if (key == NULL) { rc = CCB_INVALID_ARGUMENT; goto DONE; }

    csr = HITLS_X509_CsrNew();
    if (csr == NULL) { rc = CCB_MEMORY_FAILED; goto DONE; }

    ret = HITLS_X509_CsrCtrl(csr, HITLS_X509_SET_PUBKEY, key,
                             (uint32_t)sizeof(CRYPT_EAL_PkeyCtx *));
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CsrCtrl(SET_PUBKEY)", ret); goto DONE; }

    /* ADD_SUBJECT_NAME 的 valLen 是元素个数，不是字节数 */
    dn.cid = BSL_CID_AT_COMMONNAME;
    dn.data = (uint8_t *)common_name;
    dn.dataLen = (uint32_t)strlen(common_name);
    ret = HITLS_X509_CsrCtrl(csr, HITLS_X509_ADD_SUBJECT_NAME, &dn, 1);
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CsrCtrl(ADD_SUBJECT_NAME)", ret); goto DONE; }

    ret = HITLS_X509_CsrSign(CRYPT_MD_SM3, key, NULL, csr);
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CsrSign", ret); goto DONE; }

    ret = HITLS_X509_CsrGenBuff(BSL_FORMAT_ASN1, csr, &out);
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CsrGenBuff", ret); goto DONE; }

    rc = cc_pki_copy_out(&out, csr_der);

DONE:
    if (out.data != NULL) BSL_SAL_Free(out.data);
    if (csr != NULL) HITLS_X509_CsrFree(csr);
    if (key != NULL) CRYPT_EAL_PkeyFreeCtx(key);
    return rc;
}

int cc_bridge_cert_sign(const uint8_t *csr_der, size_t csr_der_len,
                        const uint8_t *ca_certificate_der, size_t ca_certificate_der_len,
                        const uint8_t *ca_private_key, size_t ca_private_key_len,
                        int64_t not_before, int64_t not_after,
                        uint32_t key_usage,
                        cc_bridge_buffer *cert_der,
                        cc_bridge_buffer *serial_out) {
    BSL_Buffer csr_enc;
    BSL_Buffer ca_enc;
    BSL_Buffer out;
    HITLS_X509_Csr *csr = NULL;
    HITLS_X509_Cert *ca = NULL;
    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *ca_key = NULL;
    CRYPT_EAL_PkeyCtx *pub_key = NULL;
    BslList *subject = NULL;
    BslList *issuer = NULL;
    HITLS_X509_ExtKeyUsage ku;
    HITLS_X509_ExtBCons bc;
    BSL_TIME before;
    BSL_TIME after;
    uint8_t serial[16];
    int32_t version = HITLS_X509_VERSION_3;
    int32_t ret;
    int rc = CCB_INTERNAL_ERROR;

    if (cert_der == NULL || cert_der->data == NULL) return CCB_INVALID_ARGUMENT;
    if (csr_der == NULL || csr_der_len == 0) return CCB_INVALID_ARGUMENT;
    if (ca_private_key == NULL || ca_private_key_len != 32) return CCB_INVALID_ARGUMENT;
    if (not_before <= 0 || not_after <= not_before) return CCB_INVALID_ARGUMENT;
    if (!g_init_done) { openhitls_init(); g_init_done = 1; }

    memset(&csr_enc, 0, sizeof(csr_enc));
    memset(&ca_enc, 0, sizeof(ca_enc));
    memset(&out, 0, sizeof(out));

    ca_key = cc_pki_new_sm2_ctx(ca_private_key, ca_private_key_len, NULL, 0);
    if (ca_key == NULL) { rc = CCB_INVALID_ARGUMENT; goto DONE; }

    csr_enc.data = (uint8_t *)csr_der;
    csr_enc.dataLen = (uint32_t)csr_der_len;
    ret = HITLS_X509_CsrParseBuff(BSL_FORMAT_ASN1, &csr_enc, &csr);
    if (ret != HITLS_PKI_SUCCESS) {
        cc_report("CsrParseBuff", ret);
        rc = CCB_INVALID_ARGUMENT;
        goto DONE;
    }

    if (ca_certificate_der != NULL && ca_certificate_der_len > 0) {
        ca_enc.data = (uint8_t *)ca_certificate_der;
        ca_enc.dataLen = (uint32_t)ca_certificate_der_len;
        ret = HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &ca_enc, &ca);
        if (ret != HITLS_PKI_SUCCESS) {
            cc_report("CertParseBuff(CA)", ret);
            rc = CCB_INVALID_ARGUMENT;
            goto DONE;
        }
    }

    cert = HITLS_X509_CertNew();
    if (cert == NULL) { rc = CCB_MEMORY_FAILED; goto DONE; }

    /* 1) 公钥必须最先设（后续扩展会用到） */
    ret = HITLS_X509_CsrCtrl(csr, HITLS_X509_GET_PUBKEY, &pub_key, 0);
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CsrCtrl(GET_PUBKEY)", ret); goto DONE; }

    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_PUBKEY, pub_key, 0);
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CertCtrl(SET_PUBKEY)", ret); goto DONE; }

    /* 2) v3 */
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, (uint32_t)sizeof(version));
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CertCtrl(SET_VERSION)", ret); goto DONE; }

    /* 3) keyUsage */
    memset(&ku, 0, sizeof(ku));
    ku.critical = true;
    ku.keyUsage = (key_usage != 0) ? key_usage
                                   : (HITLS_X509_EXT_KU_DIGITAL_SIGN |
                                      HITLS_X509_EXT_KU_KEY_ENCIPHERMENT |
                                      HITLS_X509_EXT_KU_KEY_AGREEMENT);
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_KUSAGE, &ku, (uint32_t)sizeof(ku));
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CertCtrl(EXT_SET_KUSAGE)", ret); goto DONE; }

    /* 4) basicConstraints：带 keyCertSign 的按 CA 处理 */
    memset(&bc, 0, sizeof(bc));
    bc.critical = true;
    bc.isCa = (ku.keyUsage & HITLS_X509_EXT_KU_KEY_CERT_SIGN) != 0;
    bc.maxPathLen = -1;
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_BCONS, &bc, (uint32_t)sizeof(bc));
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CertCtrl(EXT_SET_BCONS)", ret); goto DONE; }

    /* 5) 序列号（16B，最高位清零保证是正整数） */
    if (cc_bridge_random_bytes(serial, sizeof(serial)) != CCB_OK) { rc = CCB_RANDOM_FAILED; goto DONE; }
    serial[0] &= 0x7F;
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SERIALNUM, serial, (uint32_t)sizeof(serial));
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CertCtrl(SET_SERIALNUM)", ret); goto DONE; }

    /* 6) 有效期 */
    if (BSL_SAL_UtcTimeToDateConvert(not_before, &before) != 0 ||
        BSL_SAL_UtcTimeToDateConvert(not_after, &after) != 0) {
        cc_report("UtcTimeToDateConvert", 0);
        rc = CCB_INVALID_ARGUMENT;
        goto DONE;
    }
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_BEFORE_TIME, &before, (uint32_t)sizeof(before));
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CertCtrl(SET_BEFORE_TIME)", ret); goto DONE; }

    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_AFTER_TIME, &after, (uint32_t)sizeof(after));
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CertCtrl(SET_AFTER_TIME)", ret); goto DONE; }

    /* 7) subject 取自 CSR */
    ret = HITLS_X509_CsrCtrl(csr, HITLS_X509_GET_SUBJECT_DN, &subject, (uint32_t)sizeof(BslList *));
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CsrCtrl(GET_SUBJECT_DN)", ret); goto DONE; }

    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SUBJECT_DN, subject, (uint32_t)sizeof(BslList));
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CertCtrl(SET_SUBJECT_DN)", ret); goto DONE; }

    /* 8) issuer：有 CA 证书就取 CA 的 subject，否则自签（issuer = subject） */
    if (ca != NULL) {
        ret = HITLS_X509_CertCtrl(ca, HITLS_X509_GET_SUBJECT_DN, &issuer, (uint32_t)sizeof(BslList *));
        if (ret != HITLS_PKI_SUCCESS) { cc_report("CertCtrl(GET_SUBJECT_DN/CA)", ret); goto DONE; }
    } else {
        issuer = subject;
    }
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_ISSUER_DN, issuer, (uint32_t)sizeof(BslList));
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CertCtrl(SET_ISSUER_DN)", ret); goto DONE; }

    /* 9) 签名 */
    ret = HITLS_X509_CertSign(CRYPT_MD_SM3, ca_key, NULL, cert);
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CertSign", ret); goto DONE; }

    /* 10) 出 DER */
    ret = HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, cert, &out);
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CertGenBuff", ret); goto DONE; }

    rc = cc_pki_copy_out(&out, cert_der);
    if (rc != CCB_OK) goto DONE;

    if (serial_out != NULL) {
        if (serial_out->data == NULL || serial_out->capacity < sizeof(serial)) {
            rc = CCB_BUFFER_TOO_SMALL;
            goto DONE;
        }
        memcpy(serial_out->data, serial, sizeof(serial));
        serial_out->len = sizeof(serial);
    }

DONE:
    if (out.data != NULL) BSL_SAL_Free(out.data);
    if (pub_key != NULL) CRYPT_EAL_PkeyFreeCtx(pub_key);
    if (cert != NULL) HITLS_X509_CertFree(cert);
    if (ca != NULL) HITLS_X509_CertFree(ca);
    if (csr != NULL) HITLS_X509_CsrFree(csr);
    if (ca_key != NULL) CRYPT_EAL_PkeyFreeCtx(ca_key);
    return rc;
}

int cc_bridge_cert_chain_verify(const uint8_t *leaf_certificate_der, size_t leaf_der_len,
                                const uint8_t *chain_der, size_t chain_der_len,
                                const uint8_t *trust_root_der, size_t trust_root_len,
                                int64_t verification_time,
                                uint32_t required_key_usage) {
    HITLS_X509_StoreCtx *store = NULL;
    HITLS_X509_Cert *leaf = NULL;
    HITLS_X509_Cert *root = NULL;
    HITLS_X509_List *chain = NULL;
    HITLS_X509_List *bundle = NULL;
    BSL_Buffer enc;
    BslListNode *node;
    HITLS_X509_ExtBCons root_bc;
    int32_t depth = 20;
    int32_t ref = 0;
    int32_t ret;
    uint32_t ku = 0;
    int rc = CCB_INTERNAL_ERROR;

    if (leaf_certificate_der == NULL || leaf_der_len == 0) return CCB_INVALID_ARGUMENT;
    if (chain_der == NULL && chain_der_len != 0) return CCB_INVALID_ARGUMENT;
    if (trust_root_der == NULL || trust_root_len == 0) return CCB_INVALID_ARGUMENT;
    if (!g_init_done) { openhitls_init(); g_init_done = 1; }

    memset(&enc, 0, sizeof(enc));

    enc.data = (uint8_t *)leaf_certificate_der;
    enc.dataLen = (uint32_t)leaf_der_len;
    ret = HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &enc, &leaf);
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CertParseBuff(leaf)", ret); rc = CCB_CERT_INVALID; goto DONE; }

    enc.data = (uint8_t *)trust_root_der;
    enc.dataLen = (uint32_t)trust_root_len;
    ret = HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &enc, &root);
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CertParseBuff(root)", ret); rc = CCB_CERT_INVALID; goto DONE; }

    /* openHiTLS deliberately treats a configured trust anchor as trusted even
     * when it is the leaf itself.  The bridge must still reject an end-entity
     * certificate supplied as a trust root, otherwise callers could bypass the
     * configured PKI boundary by echoing the leaf certificate here. */
    memset(&root_bc, 0, sizeof(root_bc));
    ret = HITLS_X509_CertCtrl(root, HITLS_X509_EXT_GET_BCONS, &root_bc,
                             (uint32_t)sizeof(root_bc));
    if (ret != HITLS_PKI_SUCCESS || !root_bc.isCa) {
        rc = 0;
        goto DONE;
    }
    ku = 0;
    ret = HITLS_X509_CertCtrl(root, HITLS_X509_EXT_GET_KUSAGE, &ku,
                             (uint32_t)sizeof(ku));
    if (ret != HITLS_PKI_SUCCESS || (ku & HITLS_X509_EXT_KU_KEY_CERT_SIGN) == 0) {
        rc = 0;
        goto DONE;
    }

    store = HITLS_X509_StoreCtxNew();
    if (store == NULL) { rc = CCB_MEMORY_FAILED; goto DONE; }

    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_PARAM_DEPTH, &depth,
                                  (uint32_t)sizeof(depth));
    if (ret != HITLS_PKI_SUCCESS) { cc_report("StoreCtxCtrl(SET_PARAM_DEPTH)", ret); goto DONE; }

    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &verification_time,
                                  (uint32_t)sizeof(verification_time));
    if (ret != HITLS_PKI_SUCCESS) { cc_report("StoreCtxCtrl(SET_TIME)", ret); goto DONE; }

    /* SM2 用户标识不显式设置：签发侧 CertSign(algParam=NULL) 与验证侧都走 openHiTLS 默认值，天然对称 */
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, root,
                                  (uint32_t)sizeof(HITLS_X509_Cert *));
    /* 信任根必须是 CA 证书；非 CA（如终端实体证书）会被 openHiTLS 拒绝，
     * 这属于“链无效”而非内部错误，故返回 0。 */
    if (ret != HITLS_PKI_SUCCESS) { rc = 0; goto DONE; }

    /* 链 = leaf + 中间证书（bundle 为拼接 DER） */
    chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    if (chain == NULL) { rc = CCB_MEMORY_FAILED; goto DONE; }

    ret = HITLS_X509_CertCtrl(leaf, HITLS_X509_REF_UP, &ref, (uint32_t)sizeof(int));
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CertCtrl(REF_UP/leaf)", ret); goto DONE; }
    ret = BSL_LIST_AddElement(chain, leaf, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) { HITLS_X509_CertFree(leaf); cc_report("BSL_LIST_AddElement(leaf)", ret); goto DONE; }

    if (chain_der_len > 0) {
        enc.data = (uint8_t *)chain_der;
        enc.dataLen = (uint32_t)chain_der_len;
        ret = HITLS_X509_CertParseBundleBuff(BSL_FORMAT_ASN1, &enc, &bundle);
        if (ret != HITLS_PKI_SUCCESS) { cc_report("CertParseBundleBuff(chain)", ret); rc = CCB_CERT_INVALID; goto DONE; }
        for (node = BSL_LIST_FirstNode(bundle); node != NULL;
             node = BSL_LIST_GetNextNode(bundle, node)) {
            HITLS_X509_Cert *mid = BSL_LIST_GetData(node);
            ret = HITLS_X509_CertCtrl(mid, HITLS_X509_REF_UP, &ref, (uint32_t)sizeof(int));
            if (ret != HITLS_PKI_SUCCESS) { cc_report("CertCtrl(REF_UP/mid)", ret); goto DONE; }
            ret = BSL_LIST_AddElement(chain, mid, BSL_LIST_POS_END);
            if (ret != BSL_SUCCESS) { HITLS_X509_CertFree(mid); cc_report("BSL_LIST_AddElement(mid)", ret); goto DONE; }
        }
    }

    ret = HITLS_X509_CertVerify(store, chain);
    if (ret != HITLS_PKI_SUCCESS) {
        cc_report("CertVerify", ret);
        rc = 0;   /* 链无效（签名/有效期/用途链等） */
        goto DONE;
    }

    /* 叶子证书用途检查 */
    if (required_key_usage != 0) {
        ku = 0;
        ret = HITLS_X509_CertCtrl(leaf, HITLS_X509_EXT_GET_KUSAGE, &ku, (uint32_t)sizeof(ku));
        if (ret != HITLS_PKI_SUCCESS) { cc_report("CertCtrl(EXT_GET_KUSAGE)", ret); rc = 0; goto DONE; }
        if ((ku & required_key_usage) != required_key_usage) { rc = 0; goto DONE; }
    }
    rc = 1;

DONE:
    if (chain != NULL) BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    if (bundle != NULL) BSL_LIST_FREE(bundle, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    if (leaf != NULL) HITLS_X509_CertFree(leaf);
    if (root != NULL) HITLS_X509_CertFree(root);
    if (store != NULL) HITLS_X509_StoreCtxFree(store);
    return rc;
}

static int cc_pki_hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* 十六进制字符串 → 字节；返回字节数，失败返回 -1 */
static int cc_pki_hex_to_bytes(const uint8_t *hex, size_t hex_len,
                               uint8_t *out, size_t out_cap) {
    size_t i;
    int hi, lo;
    if (hex_len == 0 || hex_len % 2 != 0 || hex_len / 2 > out_cap) return -1;
    for (i = 0; i < hex_len / 2; i++) {
        hi = cc_pki_hexval((char)hex[2 * i]);
        lo = cc_pki_hexval((char)hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(hex_len / 2);
}

int cc_bridge_crl_create(const uint8_t *revoked_serials_hex, size_t revoked_serials_hex_len,
                         const uint8_t *ca_certificate_der, size_t ca_certificate_der_len,
                         const uint8_t *ca_private_key, size_t ca_private_key_len,
                         int64_t this_update, int64_t next_update,
                         cc_bridge_buffer *crl_der) {
    HITLS_X509_Cert *ca = NULL;
    HITLS_X509_Crl *crl = NULL;
    CRYPT_EAL_PkeyCtx *ca_key = NULL;
    BslList *issuer = NULL;
    BSL_Buffer enc;
    BSL_Buffer out;
    BSL_TIME t_this;
    BSL_TIME t_next;
    uint8_t serial[20];
    int32_t version = 1;   /* CRL v2 */
    int32_t ret;
    int rc = CCB_INTERNAL_ERROR;

    if (crl_der == NULL || crl_der->data == NULL) return CCB_INVALID_ARGUMENT;
    if (revoked_serials_hex == NULL && revoked_serials_hex_len != 0) return CCB_INVALID_ARGUMENT;
    if (ca_certificate_der == NULL || ca_certificate_der_len == 0) return CCB_INVALID_ARGUMENT;
    if (ca_private_key == NULL || ca_private_key_len != 32) return CCB_INVALID_ARGUMENT;
    if (this_update <= 0 || next_update <= this_update) return CCB_INVALID_ARGUMENT;
    if (!g_init_done) { openhitls_init(); g_init_done = 1; }

    memset(&enc, 0, sizeof(enc));
    memset(&out, 0, sizeof(out));

    enc.data = (uint8_t *)ca_certificate_der;
    enc.dataLen = (uint32_t)ca_certificate_der_len;
    ret = HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &enc, &ca);
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CertParseBuff(CA)", ret); rc = CCB_INVALID_ARGUMENT; goto DONE; }

    ca_key = cc_pki_new_sm2_ctx(ca_private_key, ca_private_key_len, NULL, 0);
    if (ca_key == NULL) { rc = CCB_INVALID_ARGUMENT; goto DONE; }

    crl = HITLS_X509_CrlNew();
    if (crl == NULL) { rc = CCB_MEMORY_FAILED; goto DONE; }

    ret = HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_VERSION, &version, (uint32_t)sizeof(version));
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CrlCtrl(SET_VERSION)", ret); goto DONE; }

    ret = HITLS_X509_CertCtrl(ca, HITLS_X509_GET_SUBJECT_DN, &issuer, (uint32_t)sizeof(BslList *));
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CertCtrl(GET_SUBJECT_DN/CA)", ret); goto DONE; }

    ret = HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_ISSUER_DN, issuer, (uint32_t)sizeof(BslList));
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CrlCtrl(SET_ISSUER_DN)", ret); goto DONE; }

    if (BSL_SAL_UtcTimeToDateConvert(this_update, &t_this) != 0 ||
        BSL_SAL_UtcTimeToDateConvert(next_update, &t_next) != 0) {
        rc = CCB_INVALID_ARGUMENT;
        goto DONE;
    }
    ret = HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_BEFORE_TIME, &t_this, (uint32_t)sizeof(t_this));
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CrlCtrl(SET_BEFORE_TIME)", ret); goto DONE; }

    ret = HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_AFTER_TIME, &t_next, (uint32_t)sizeof(t_next));
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CrlCtrl(SET_AFTER_TIME)", ret); goto DONE; }

    /* 吊销条目：逗号分隔的十六进制序列号串 */
    if (revoked_serials_hex_len > 0) {
        const uint8_t *cursor = revoked_serials_hex;
        size_t remaining = revoked_serials_hex_len;
        while (remaining > 0) {
            const uint8_t *comma = memchr(cursor, ',', remaining);
            size_t token_len = (comma != NULL) ? (size_t)(comma - cursor) : remaining;
            HITLS_X509_CrlEntry *entry;
            int serial_len;

            if (token_len == 0 || token_len > 40) { rc = CCB_INVALID_ARGUMENT; goto DONE; }
            serial_len = cc_pki_hex_to_bytes(cursor, token_len, serial, sizeof(serial));
            if (serial_len <= 0) { rc = CCB_INVALID_ARGUMENT; goto DONE; }

            entry = HITLS_X509_CrlEntryNew();
            if (entry == NULL) { rc = CCB_MEMORY_FAILED; goto DONE; }
            ret = HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_SERIALNUM,
                                          serial, (uint32_t)serial_len);
            if (ret != HITLS_PKI_SUCCESS) { cc_report("CrlEntryCtrl(SET_REVOKED_SERIALNUM)", ret); goto DONE; }
            ret = HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_REVOKE_TIME,
                                          &t_this, (uint32_t)sizeof(BSL_TIME));
            if (ret != HITLS_PKI_SUCCESS) { cc_report("CrlEntryCtrl(SET_REVOKED_REVOKE_TIME)", ret); goto DONE; }
            ret = HITLS_X509_CrlCtrl(crl, HITLS_X509_CRL_ADD_REVOKED_CERT, entry,
                                     (uint32_t)sizeof(HITLS_X509_CrlEntry *));
            if (ret != HITLS_PKI_SUCCESS) { cc_report("CrlCtrl(ADD_REVOKED_CERT)", ret); goto DONE; }
            /* 注意：此处不释放 entry —— 若 ADD 转移所有权，释放会导致双 free；
             * 若 ADD 为深拷贝，仅泄漏少量内存（吊销条目生命周期与 CRL 相同）。 */

            if (comma == NULL) break;
            cursor = comma + 1;
            remaining -= (token_len + 1);
        }
    }

    ret = HITLS_X509_CrlSign(CRYPT_MD_SM3, ca_key, NULL, crl);
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CrlSign", ret); goto DONE; }

    ret = HITLS_X509_CrlGenBuff(BSL_FORMAT_ASN1, crl, &out);
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CrlGenBuff", ret); goto DONE; }

    rc = cc_pki_copy_out(&out, crl_der);

DONE:
    if (out.data != NULL) BSL_SAL_Free(out.data);
    if (crl != NULL) HITLS_X509_CrlFree(crl);
    if (ca != NULL) HITLS_X509_CertFree(ca);
    if (ca_key != NULL) CRYPT_EAL_PkeyFreeCtx(ca_key);
    return rc;
}

/* 归一化比较两个（可能带前导 0 或 DER TLV 头的）大整数序列号 */
static int cc_pki_serial_equal(const uint8_t *a, uint32_t a_len,
                               const uint8_t *b, uint32_t b_len) {
    uint32_t i = 0, j = 0;
    /* 若像 DER INTEGER TLV（0x02 len），剥离头 */
    if (a_len >= 2 && a[0] == 0x02 && (uint32_t)a[1] == a_len - 2) { a += 2; a_len -= 2; }
    if (b_len >= 2 && b[0] == 0x02 && (uint32_t)b[1] == b_len - 2) { b += 2; b_len -= 2; }
    while (i < a_len && a[i] == 0x00) i++;
    while (j < b_len && b[j] == 0x00) j++;
    if (a_len - i != b_len - j) return 0;
    return memcmp(a + i, b + j, a_len - i) == 0;
}

int cc_bridge_crl_verify(const uint8_t *certificate_der, size_t certificate_len,
                         const uint8_t *crl_der, size_t crl_len,
                         int64_t verification_time) {
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Crl *crl = NULL;
    BSL_Buffer enc;
    BSL_Buffer cert_serial;
    BSL_TIME t_this;
    BSL_TIME t_next;
    int64_t this_unix = 0;
    int64_t next_unix = 0;
    BslList *revoked = NULL;
    BslListNode *node;
    int32_t ret;
    int rc = CCB_INTERNAL_ERROR;

    if (certificate_der == NULL || certificate_len == 0) return CCB_INVALID_ARGUMENT;
    if (crl_der == NULL || crl_len == 0) return CCB_INVALID_ARGUMENT;
    if (!g_init_done) { openhitls_init(); g_init_done = 1; }

    memset(&enc, 0, sizeof(enc));
    memset(&cert_serial, 0, sizeof(cert_serial));

    enc.data = (uint8_t *)certificate_der;
    enc.dataLen = (uint32_t)certificate_len;
    ret = HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &enc, &cert);
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CertParseBuff", ret); rc = 0; goto DONE; }

    enc.data = (uint8_t *)crl_der;
    enc.dataLen = (uint32_t)crl_len;
    ret = HITLS_X509_CrlParseBuff(BSL_FORMAT_ASN1, &enc, &crl);
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CrlParseBuff", ret); rc = 0; goto DONE; }

    /* CRL 时间窗口必须覆盖验证时刻，否则无法给出"未吊销"结论（fail-closed → 0） */
    ret = HITLS_X509_CrlCtrl(crl, HITLS_X509_GET_BEFORE_TIME, &t_this, (uint32_t)sizeof(BSL_TIME));
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CrlCtrl(GET_BEFORE_TIME)", ret); rc = 0; goto DONE; }

    ret = HITLS_X509_CrlCtrl(crl, HITLS_X509_GET_AFTER_TIME, &t_next, (uint32_t)sizeof(BSL_TIME));
    if (ret == HITLS_X509_ERR_CRL_NEXTUPDATE_UNEXIST) {
        next_unix = INT64_MAX;
    } else if (ret != HITLS_PKI_SUCCESS) {
        cc_report("CrlCtrl(GET_AFTER_TIME)", ret);
        rc = 0;
        goto DONE;
    } else if (BSL_SAL_DateToUtcTimeConvert(&t_next, &next_unix) != 0) {
        rc = 0;
        goto DONE;
    }
    if (BSL_SAL_DateToUtcTimeConvert(&t_this, &this_unix) != 0) { rc = 0; goto DONE; }
    if (verification_time < this_unix || verification_time > next_unix) { rc = 0; goto DONE; }

    /* 证书序列号（浅拷贝，勿释放） */
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SERIALNUM, &cert_serial,
                              (uint32_t)sizeof(BSL_Buffer));
    if (ret != HITLS_PKI_SUCCESS) { cc_report("CertCtrl(GET_SERIALNUM)", ret); rc = 0; goto DONE; }

    /* 吊销列表：匹配则返回 0（已吊销） */
    ret = HITLS_X509_CrlCtrl(crl, HITLS_X509_GET_REVOKELIST, &revoked, (uint32_t)sizeof(BslList *));
    if (ret != HITLS_PKI_SUCCESS) {
        /* 空 CRL（无吊销条目）按"未吊销"处理 */
        rc = 1;
        goto DONE;
    }
    rc = 1;
    for (node = BSL_LIST_FirstNode(revoked); node != NULL;
         node = BSL_LIST_GetNextNode(revoked, node)) {
        HITLS_X509_CrlEntry *entry = BSL_LIST_GetData(node);
        BSL_Buffer entry_serial;
        memset(&entry_serial, 0, sizeof(entry_serial));
        ret = HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_GET_REVOKED_SERIALNUM,
                                      &entry_serial, (uint32_t)sizeof(BSL_Buffer));
        if (ret != HITLS_PKI_SUCCESS) {
            cc_report("CrlEntryCtrl(GET_REVOKED_SERIALNUM)", ret);
            rc = 0;
            goto DONE;
        }
        if (cc_pki_serial_equal(cert_serial.data, cert_serial.dataLen,
                                entry_serial.data, entry_serial.dataLen)) {
            rc = 0;
            goto DONE;
        }
    }

DONE:
    if (cert != NULL) HITLS_X509_CertFree(cert);
    if (crl != NULL) HITLS_X509_CrlFree(crl);
    return rc;
}
/* ==========================================================================
 * SM2 盲签名：两轮 EC-Schnorr 盲签名（SM2 曲线 + SM3）
 *
 * 公开 EAL 层没有椭圆曲线点运算，所以这里直接调用 openHiTLS 内部
 * crypto/ecc 与 crypto/bn 原语。调用姿势与 openHiTLS 自己的 SM2 实现
 * （crypto/sm2/src/sm2_sign.c、crypto/sm2/src/sm2_exch.c）逐条对齐：
 *
 *   ECC_PointMul(para, r, k, NULL)            r = [k]G
 *                                             （sm2_sign.c: pt = k * G）
 *   ECC_PointMulAdd(para, r, k1, k2, pt)      r = [k1]G + [k2]pt
 *                                             （sm2_sign.c 验签 + sm2_exch.c 都用）
 *   ECC_PointAddAffine(para, r, a, b)         r = a + b
 *                                             （sm2_exch.c: ECC_PointAddAffine(para, uorv, uorv, pubkey)
 *                                               即 a 是 Jacobian、b 是仿射、且允许 r == a）
 *   ECC_EncodePoint(..., CRYPT_POINT_UNCOMPRESSED)  0x04||X||Y，顺带转仿射
 *   ECC_GetPointDataX(para, pt, x)            取 x，顺带转仿射（验签里同款）
 *   ECC_PointCheck(pt)                        校验点合法且非无穷远
 *   ECC_GetParaRawN(para)                     只读引用，绝不能释放
 *   BN_OptimizerCreate()/Destroy()            直接创建即可，无需 OptimizerStart
 *                                             （sm2_sign.c 的 Sm2SignCore 就是这样）
 *
 * 正确性：[s]G - [c]P = [s'+α]G - [c]P
 *                     = [k + (c+β)d]G + [α]G - [c]P
 *                     = [k]G + [α]G + [β]P = R'
 *
 * 盲性：签名方本次会话只看到 (k, c')，c' = (c + β) mod n 且 β 均匀随机，
 *       故 c' 不泄露 c，签名方无法把 (M, R', s) 关联回本次会话。
 *       β 不可省：若 β = 0 则 c' = c，签名方用 H(R'||M) 一比对就能完成关联。
 *
 * 安全要求（调用方职责，本层不做持久化）：
 *   k 是一次性随机数，必须绑定会话并在用后立即从服务端删除；
 *   同一个 R 绝不可用于两个会话（盲 Schnorr 的 ROS 风险）。
 * ========================================================================== */

#define CC_BLIND_POINT_LEN  65
#define CC_BLIND_SCALAR_LEN 32
#define CC_BLIND_STATE_LEN  64
#define CC_BLIND_TRY_CNT    16

static BN_BigNum *cc_blind_bn_from(const uint8_t *bin, uint32_t len) {
    BN_BigNum *bn = BN_Create(256);
    if (bn == NULL) return NULL;
    if (BN_Bin2Bn(bn, bin, len) != CRYPT_SUCCESS) { BN_Destroy(bn); return NULL; }
    return bn;
}

/* 均匀取 [1, n-1] 标量：用桥自身的 CSPRNG + 拒绝采样。
   不用 BN_RandRange，避免依赖 HITLS_CRYPTO_BN_RAND 这个子开关。返回 0 成功。 */
static int cc_blind_rand_scalar(BN_BigNum *out, const BN_BigNum *n) {
    uint8_t buf[CC_BLIND_SCALAR_LEN];
    int i, rc = -1;
    for (i = 0; i < CC_BLIND_TRY_CNT; i++) {
        if (cc_bridge_random_bytes(buf, (size_t)sizeof(buf)) != CCB_OK) goto DONE;
        if (BN_Bin2Bn(out, buf, (uint32_t)sizeof(buf)) != CRYPT_SUCCESS) goto DONE;
        if (!BN_IsZero(out) && BN_Cmp(out, n) < 0) { rc = 0; goto DONE; }
    }
DONE:
    memset(buf, 0, sizeof(buf));
    return rc;
}

/* 编码成 65 字节未压缩点 0x04||X||Y；顺带把点归一到仿射坐标 */
static int cc_blind_encode_point(const ECC_Para *para, ECC_Point *pt, uint8_t *out, uint32_t cap) {
    uint32_t len = cap;
    if (ECC_EncodePoint(para, pt, out, &len, CRYPT_POINT_UNCOMPRESSED) != CRYPT_SUCCESS) return -1;
    if (len != cap) return -1;
    return 0;
}

/* 解码 65 字节未压缩点，并校验它在曲线上且不是无穷远点 */
static ECC_Point *cc_blind_decode_point(const ECC_Para *para, const uint8_t *data) {
    ECC_Point *pt = ECC_NewPoint(para);
    if (pt == NULL) return NULL;
    if (ECC_DecodePoint(para, pt, data, (uint32_t)CC_BLIND_POINT_LEN) != CRYPT_SUCCESS) {
        ECC_FreePoint(pt);
        return NULL;
    }
    if (ECC_PointCheck(pt) != CRYPT_SUCCESS) { ECC_FreePoint(pt); return NULL; }
    return pt;
}

/* 判断两点是否相同：都按未压缩格式规范化后做常数时间比较。
   未压缩编码与点一一对应，所以比编码等价于比点，且不依赖 ECC_PointCmp
   对 Jacobian / 仿射输入的隐含要求。返回 1/0/-1(出错)。 */
static int cc_blind_point_equal(const ECC_Para *para, ECC_Point *a, ECC_Point *b) {
    uint8_t ea[CC_BLIND_POINT_LEN];
    uint8_t eb[CC_BLIND_POINT_LEN];
    int rc;
    if (cc_blind_encode_point(para, a, ea, (uint32_t)sizeof(ea)) != 0) return -1;
    if (cc_blind_encode_point(para, b, eb, (uint32_t)sizeof(eb)) != 0) return -1;
    rc = cc_bridge_constant_time_equal(ea, sizeof(ea), eb, sizeof(eb));
    memset(ea, 0, sizeof(ea));
    memset(eb, 0, sizeof(eb));
    return rc;
}

/* c = SM3(R'_x(32B) || M) mod n；pt 会被 ECC_GetPointDataX 归一为仿射 */
static int cc_blind_challenge(const ECC_Para *para, ECC_Point *pt,
                              const uint8_t *message, size_t message_len,
                              BN_BigNum *c_out, const BN_BigNum *n, BN_Optimizer *opt) {
    uint8_t x[CC_BLIND_SCALAR_LEN];
    uint8_t digest[32];
    cc_bridge_buffer dg;
    BN_BigNum *xbn = NULL;
    BN_BigNum *raw = NULL;
    uint8_t *buf = NULL;
    size_t total = (size_t)CC_BLIND_SCALAR_LEN + message_len;
    int rc = -1;

    dg.data = digest;
    dg.capacity = sizeof(digest);
    dg.len = 0;
    xbn = BN_Create(256);
    raw = BN_Create(256);
    buf = (uint8_t *)malloc(total);
    if (xbn == NULL || raw == NULL || buf == NULL) goto DONE;

    if (ECC_GetPointDataX(para, pt, xbn) != CRYPT_SUCCESS) goto DONE;
    if (BN_Bn2BinFixZero(xbn, x, (uint32_t)sizeof(x)) != CRYPT_SUCCESS) goto DONE;

    memcpy(buf, x, sizeof(x));
    if (message_len > 0) memcpy(buf + sizeof(x), message, message_len);
    if (cc_bridge_sm3_digest(buf, total, &dg) != CCB_OK) goto DONE;

    if (BN_Bin2Bn(raw, digest, (uint32_t)sizeof(digest)) != CRYPT_SUCCESS) goto DONE;
    if (BN_Mod(c_out, raw, n, opt) != CRYPT_SUCCESS) goto DONE;
    rc = 0;

DONE:
    memset(x, 0, sizeof(x));
    memset(digest, 0, sizeof(digest));
    if (buf != NULL) { memset(buf, 0, total); free(buf); }
    if (xbn != NULL) BN_Destroy(xbn);
    if (raw != NULL) BN_Destroy(raw);
    return rc;
}

/* 第 1 轮：签名方生成一次性承诺 (k, R = [k]G) */
int cc_bridge_sm2_blind_commit(cc_bridge_buffer *k_out, cc_bridge_buffer *R_out) {
    ECC_Para *para = NULL;
    ECC_Point *R = NULL;
    BN_BigNum *k = NULL;
    BN_BigNum *n = NULL;
    BN_Optimizer *opt = NULL;
    int rc = CCB_INTERNAL_ERROR;

    if (k_out == NULL || R_out == NULL) return CCB_INVALID_ARGUMENT;
    if (k_out->data == NULL || k_out->capacity < CC_BLIND_SCALAR_LEN) return CCB_BUFFER_TOO_SMALL;
    if (R_out->data == NULL || R_out->capacity < CC_BLIND_POINT_LEN) return CCB_BUFFER_TOO_SMALL;
    k_out->len = 0;
    R_out->len = 0;
    if (!g_init_done) { openhitls_init(); g_init_done = 1; }

    para = ECC_NewPara(CRYPT_ECC_SM2);
    if (para == NULL) { cc_report("ECC_NewPara(SM2)", -1); return CCB_INTERNAL_ERROR; }
    n = ECC_GetParaRawN(para);
    opt = BN_OptimizerCreate();
    k = BN_Create(256);
    R = ECC_NewPoint(para);
    if (n == NULL || opt == NULL || k == NULL || R == NULL) { rc = CCB_MEMORY_FAILED; goto DONE; }

    if (cc_blind_rand_scalar(k, n) != 0) { cc_report("rand scalar(k)", -1); goto DONE; }
    if (ECC_PointMul(para, R, k, NULL) != CRYPT_SUCCESS) { cc_report("ECC_PointMul(kG)", -1); goto DONE; }
    if (cc_blind_encode_point(para, R, R_out->data, (uint32_t)CC_BLIND_POINT_LEN) != 0) {
        cc_report("encode(R)", -1);
        goto DONE;
    }
    if (BN_Bn2BinFixZero(k, k_out->data, (uint32_t)CC_BLIND_SCALAR_LEN) != CRYPT_SUCCESS) {
        cc_report("encode(k)", -1);
        goto DONE;
    }
    R_out->len = CC_BLIND_POINT_LEN;
    k_out->len = CC_BLIND_SCALAR_LEN;
    rc = CCB_OK;

DONE:
    if (rc != CCB_OK) { k_out->len = 0; R_out->len = 0; }
    if (R != NULL) ECC_FreePoint(R);
    if (k != NULL) BN_Destroy(k);
    if (opt != NULL) BN_OptimizerDestroy(opt);
    /* 注意：n 来自 ECC_GetParaRawN，是 para 内部引用，不能 BN_Destroy */
    ECC_FreePara(para);
    return rc;
}

/* 第 2 轮（客户端）：盲化，产出 c' 与本地状态 α||β */
int cc_bridge_sm2_blind_blind(const uint8_t *R, const uint8_t *signer_public_key,
                              const uint8_t *message, size_t message_len,
                              cc_bridge_buffer *c_prime_out,
                              cc_bridge_buffer *state_out,
                              cc_bridge_buffer *R_prime_out) {
    ECC_Para *para = NULL;
    ECC_Point *Rs = NULL;
    ECC_Point *P = NULL;
    ECC_Point *S = NULL;
    ECC_Point *Rp = NULL;
    BN_BigNum *n = NULL;
    BN_BigNum *alpha = NULL;
    BN_BigNum *beta = NULL;
    BN_BigNum *c = NULL;
    BN_BigNum *cp = NULL;
    BN_Optimizer *opt = NULL;
    int rc = CCB_INTERNAL_ERROR;

    if (R == NULL || signer_public_key == NULL) return CCB_INVALID_ARGUMENT;
    if (message == NULL && message_len > 0) return CCB_INVALID_ARGUMENT;
    if (c_prime_out == NULL || state_out == NULL || R_prime_out == NULL) return CCB_INVALID_ARGUMENT;
    if (c_prime_out->data == NULL || c_prime_out->capacity < CC_BLIND_SCALAR_LEN) return CCB_BUFFER_TOO_SMALL;
    if (state_out->data == NULL || state_out->capacity < CC_BLIND_STATE_LEN) return CCB_BUFFER_TOO_SMALL;
    if (R_prime_out->data == NULL || R_prime_out->capacity < CC_BLIND_POINT_LEN) return CCB_BUFFER_TOO_SMALL;
    c_prime_out->len = 0;
    state_out->len = 0;
    R_prime_out->len = 0;
    if (!g_init_done) { openhitls_init(); g_init_done = 1; }

    para = ECC_NewPara(CRYPT_ECC_SM2);
    if (para == NULL) { cc_report("ECC_NewPara(SM2)", -1); return CCB_INTERNAL_ERROR; }
    n = ECC_GetParaRawN(para);
    opt = BN_OptimizerCreate();
    S = ECC_NewPoint(para);
    Rp = ECC_NewPoint(para);
    alpha = BN_Create(256);
    beta = BN_Create(256);
    c = BN_Create(256);
    cp = BN_Create(256);
    if (n == NULL || opt == NULL || S == NULL || Rp == NULL ||
        alpha == NULL || beta == NULL || c == NULL || cp == NULL) {
        rc = CCB_MEMORY_FAILED;
        goto DONE;
    }
    Rs = cc_blind_decode_point(para, R);
    P = cc_blind_decode_point(para, signer_public_key);
    if (Rs == NULL || P == NULL) { cc_report("decode point(R or P)", -1); rc = CCB_INVALID_ARGUMENT; goto DONE; }

    if (cc_blind_rand_scalar(alpha, n) != 0 || cc_blind_rand_scalar(beta, n) != 0) {
        cc_report("rand scalar(alpha/beta)", -1);
        goto DONE;
    }
    /* S = [α]G + [β]P */
    if (ECC_PointMulAdd(para, S, alpha, beta, P) != CRYPT_SUCCESS) {
        cc_report("ECC_PointMulAdd(alphaG+betaP)", -1);
        goto DONE;
    }
    /* R' = R + S（Rs 是仿射、S 是 Jacobian，ECC_PointAddAffine 支持混合） */
    if (ECC_PointAddAffine(para, Rp, Rs, S) != CRYPT_SUCCESS) {
        cc_report("ECC_PointAddAffine(R')", -1);
        goto DONE;
    }
    if (cc_blind_challenge(para, Rp, message, message_len, c, n, opt) != 0) {
        cc_report("challenge", -1);
        goto DONE;
    }
    /* c' = (c + β) mod n */
    if (BN_ModAdd(cp, c, beta, n, opt) != CRYPT_SUCCESS) { cc_report("BN_ModAdd(c')", -1); goto DONE; }
    if (BN_Bn2BinFixZero(cp, c_prime_out->data, (uint32_t)CC_BLIND_SCALAR_LEN) != CRYPT_SUCCESS) {
        cc_report("encode(c')", -1);
        goto DONE;
    }
    /* state = α || β，必须留在客户端手里 */
    if (BN_Bn2BinFixZero(alpha, state_out->data, (uint32_t)CC_BLIND_SCALAR_LEN) != CRYPT_SUCCESS) {
        cc_report("encode(alpha)", -1);
        goto DONE;
    }
    if (BN_Bn2BinFixZero(beta, state_out->data + CC_BLIND_SCALAR_LEN,
                         (uint32_t)CC_BLIND_SCALAR_LEN) != CRYPT_SUCCESS) {
        cc_report("encode(beta)", -1);
        goto DONE;
    }
    if (cc_blind_encode_point(para, Rp, R_prime_out->data, (uint32_t)CC_BLIND_POINT_LEN) != 0) {
        cc_report("encode(R')", -1);
        goto DONE;
    }
    c_prime_out->len = CC_BLIND_SCALAR_LEN;
    state_out->len = CC_BLIND_STATE_LEN;
    R_prime_out->len = CC_BLIND_POINT_LEN;
    rc = CCB_OK;

DONE:
    if (rc != CCB_OK) {
        c_prime_out->len = 0;
        if (state_out->data != NULL) memset(state_out->data, 0, state_out->capacity);
        state_out->len = 0;
        R_prime_out->len = 0;
    }
    if (Rs != NULL) ECC_FreePoint(Rs);
    if (P != NULL) ECC_FreePoint(P);
    if (S != NULL) ECC_FreePoint(S);
    if (Rp != NULL) ECC_FreePoint(Rp);
    if (alpha != NULL) BN_Destroy(alpha);
    if (beta != NULL) BN_Destroy(beta);
    if (c != NULL) BN_Destroy(c);
    if (cp != NULL) BN_Destroy(cp);
    if (opt != NULL) BN_OptimizerDestroy(opt);
    ECC_FreePara(para);
    return rc;
}

/* 第 3 轮（签名方）：s' = (k + c'·d) mod n */
int cc_bridge_sm2_blind_sign(const uint8_t *k, const uint8_t *c_prime,
                             const uint8_t *signer_private_key,
                             cc_bridge_buffer *s_prime_out) {
    ECC_Para *para = NULL;
    BN_BigNum *n = NULL;
    BN_BigNum *kb = NULL;
    BN_BigNum *cpb = NULL;
    BN_BigNum *d = NULL;
    BN_BigNum *prod = NULL;
    BN_BigNum *sp = NULL;
    BN_Optimizer *opt = NULL;
    int rc = CCB_INTERNAL_ERROR;

    if (k == NULL || c_prime == NULL || signer_private_key == NULL) return CCB_INVALID_ARGUMENT;
    if (s_prime_out == NULL || s_prime_out->data == NULL ||
        s_prime_out->capacity < CC_BLIND_SCALAR_LEN) return CCB_BUFFER_TOO_SMALL;
    s_prime_out->len = 0;
    if (!g_init_done) { openhitls_init(); g_init_done = 1; }

    para = ECC_NewPara(CRYPT_ECC_SM2);
    if (para == NULL) { cc_report("ECC_NewPara(SM2)", -1); return CCB_INTERNAL_ERROR; }
    n = ECC_GetParaRawN(para);
    opt = BN_OptimizerCreate();
    kb = cc_blind_bn_from(k, (uint32_t)CC_BLIND_SCALAR_LEN);
    cpb = cc_blind_bn_from(c_prime, (uint32_t)CC_BLIND_SCALAR_LEN);
    d = cc_blind_bn_from(signer_private_key, (uint32_t)CC_BLIND_SCALAR_LEN);
    prod = BN_Create(256);
    sp = BN_Create(256);
    if (n == NULL || opt == NULL || kb == NULL || cpb == NULL || d == NULL ||
        prod == NULL || sp == NULL) {
        rc = CCB_MEMORY_FAILED;
        goto DONE;
    }
    /* k 与私钥都必须是 [1, n-1] 内的合法标量 */
    if (BN_IsZero(kb) || BN_Cmp(kb, n) >= 0) { rc = CCB_INVALID_ARGUMENT; goto DONE; }
    if (BN_IsZero(d) || BN_Cmp(d, n) >= 0) { rc = CCB_INVALID_ARGUMENT; goto DONE; }

    if (BN_ModMul(prod, cpb, d, n, opt) != CRYPT_SUCCESS) { cc_report("BN_ModMul(c'd)", -1); goto DONE; }
    if (BN_ModAdd(sp, kb, prod, n, opt) != CRYPT_SUCCESS) { cc_report("BN_ModAdd(s')", -1); goto DONE; }
    if (BN_Bn2BinFixZero(sp, s_prime_out->data, (uint32_t)CC_BLIND_SCALAR_LEN) != CRYPT_SUCCESS) {
        cc_report("encode(s')", -1);
        goto DONE;
    }
    s_prime_out->len = CC_BLIND_SCALAR_LEN;
    rc = CCB_OK;

DONE:
    if (rc != CCB_OK) s_prime_out->len = 0;
    if (kb != NULL) BN_Destroy(kb);
    if (cpb != NULL) BN_Destroy(cpb);
    if (d != NULL) BN_Destroy(d);
    if (prod != NULL) BN_Destroy(prod);
    if (sp != NULL) BN_Destroy(sp);
    if (opt != NULL) BN_OptimizerDestroy(opt);
    ECC_FreePara(para);
    return rc;
}

/* 第 4 轮（客户端）：s = (s' + α) mod n */
int cc_bridge_sm2_blind_unblind(const uint8_t *s_prime, const uint8_t *state,
                                cc_bridge_buffer *s_out) {
    ECC_Para *para = NULL;
    BN_BigNum *n = NULL;
    BN_BigNum *spb = NULL;
    BN_BigNum *alpha = NULL;
    BN_BigNum *s = NULL;
    BN_Optimizer *opt = NULL;
    int rc = CCB_INTERNAL_ERROR;

    if (s_prime == NULL || state == NULL) return CCB_INVALID_ARGUMENT;
    if (s_out == NULL || s_out->data == NULL ||
        s_out->capacity < CC_BLIND_SCALAR_LEN) return CCB_BUFFER_TOO_SMALL;
    s_out->len = 0;
    if (!g_init_done) { openhitls_init(); g_init_done = 1; }

    para = ECC_NewPara(CRYPT_ECC_SM2);
    if (para == NULL) { cc_report("ECC_NewPara(SM2)", -1); return CCB_INTERNAL_ERROR; }
    n = ECC_GetParaRawN(para);
    opt = BN_OptimizerCreate();
    spb = cc_blind_bn_from(s_prime, (uint32_t)CC_BLIND_SCALAR_LEN);
    alpha = cc_blind_bn_from(state, (uint32_t)CC_BLIND_SCALAR_LEN); /* state = α || β */
    s = BN_Create(256);
    if (n == NULL || opt == NULL || spb == NULL || alpha == NULL || s == NULL) {
        rc = CCB_MEMORY_FAILED;
        goto DONE;
    }

    if (BN_ModAdd(s, spb, alpha, n, opt) != CRYPT_SUCCESS) { cc_report("BN_ModAdd(s)", -1); goto DONE; }
    if (BN_Bn2BinFixZero(s, s_out->data, (uint32_t)CC_BLIND_SCALAR_LEN) != CRYPT_SUCCESS) {
        cc_report("encode(s)", -1);
        goto DONE;
    }
    s_out->len = CC_BLIND_SCALAR_LEN;
    rc = CCB_OK;

DONE:
    if (rc != CCB_OK) s_out->len = 0;
    if (spb != NULL) BN_Destroy(spb);
    if (alpha != NULL) BN_Destroy(alpha);
    if (s != NULL) BN_Destroy(s);
    if (opt != NULL) BN_OptimizerDestroy(opt);
    ECC_FreePara(para);
    return rc;
}

/* 第 5 轮（任意验签方）：c = SM3(R'_x || M) mod n，验证 [s]G + [n-c]P == R'
   返回 1 = 通过 / 0 = 无效 / <0 = CCB_* 错误。 */
int cc_bridge_sm2_blind_verify(const uint8_t *R_prime,
                               const uint8_t *message, size_t message_len,
                               const uint8_t *s, const uint8_t *signer_public_key) {
    ECC_Para *para = NULL;
    ECC_Point *Rp = NULL;
    ECC_Point *P = NULL;
    ECC_Point *Q = NULL;
    BN_BigNum *n = NULL;
    BN_BigNum *sb = NULL;
    BN_BigNum *c = NULL;
    BN_BigNum *nc = NULL;
    BN_BigNum *zero = NULL;
    BN_Optimizer *opt = NULL;
    int eq;
    int rc = CCB_INTERNAL_ERROR;

    if (R_prime == NULL || s == NULL || signer_public_key == NULL) return CCB_INVALID_ARGUMENT;
    if (message == NULL && message_len > 0) return CCB_INVALID_ARGUMENT;
    if (!g_init_done) { openhitls_init(); g_init_done = 1; }

    para = ECC_NewPara(CRYPT_ECC_SM2);
    if (para == NULL) { cc_report("ECC_NewPara(SM2)", -1); return CCB_INTERNAL_ERROR; }
    n = ECC_GetParaRawN(para);
    opt = BN_OptimizerCreate();
    Q = ECC_NewPoint(para);
    sb = cc_blind_bn_from(s, (uint32_t)CC_BLIND_SCALAR_LEN);
    c = BN_Create(256);
    nc = BN_Create(256);
    zero = BN_Create(256);
    if (n == NULL || opt == NULL || Q == NULL || sb == NULL ||
        c == NULL || nc == NULL || zero == NULL) {
        rc = CCB_MEMORY_FAILED;
        goto DONE;
    }
    if (BN_Zeroize(zero) != CRYPT_SUCCESS) { cc_report("BN_Zeroize", -1); goto DONE; }

    Rp = cc_blind_decode_point(para, R_prime);
    P = cc_blind_decode_point(para, signer_public_key);
    /* 非法点 => 验签不通过（返回 0，不是错误码） */
    if (Rp == NULL || P == NULL) { rc = 0; goto DONE; }
    /* s 必须落在 [1, n-1] */
    if (BN_IsZero(sb) || BN_Cmp(sb, n) >= 0) { rc = 0; goto DONE; }

    if (cc_blind_challenge(para, Rp, message, message_len, c, n, opt) != 0) {
        cc_report("challenge(verify)", -1);
        goto DONE;
    }
    /* nc = (0 - c) mod n；c == 0 时得 0，此时 [s]G + [0]P = [s]G，仍然正确 */
    if (BN_ModSub(nc, zero, c, n, opt) != CRYPT_SUCCESS) { cc_report("BN_ModSub(-c)", -1); goto DONE; }
    /* Q = [s]G + [n-c]P = [s]G - [c]P */
    if (ECC_PointMulAdd(para, Q, sb, nc, P) != CRYPT_SUCCESS) {
        cc_report("ECC_PointMulAdd(verify)", -1);
        rc = 0;
        goto DONE;
    }
    eq = cc_blind_point_equal(para, Q, Rp);
    rc = (eq == 1) ? 1 : 0;

DONE:
    if (Rp != NULL) ECC_FreePoint(Rp);
    if (P != NULL) ECC_FreePoint(P);
    if (Q != NULL) ECC_FreePoint(Q);
    if (sb != NULL) BN_Destroy(sb);
    if (c != NULL) BN_Destroy(c);
    if (nc != NULL) BN_Destroy(nc);
    if (zero != NULL) BN_Destroy(zero);
    if (opt != NULL) BN_OptimizerDestroy(opt);
    ECC_FreePara(para);
    return rc;
}