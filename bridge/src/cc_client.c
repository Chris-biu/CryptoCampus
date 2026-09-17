/* ===========================================================================
 * cc_client.c —— 盲签名客户端模块（浏览器 WASM 用）
 *
 * 只实现客户端两步 + 打包凭证 + x-only 验签；不含任何私钥输入，不含签名能力。
 * 数学部分与服务端 bridge/src/cc_bridge.c 完全同构（同一套 openHiTLS 内部
 * ECC/BN 原语），两边由 tests/kat/test_blind_signature_openhitls.py 做跨端互通核对，
 * 一旦发散就会被测出来。
 *
 * 与服务端的两点差异，都是为 WASM 刻意做的：
 *   1. 不用 EAL / provider：SM3 直接调 crypto/sm3 的 CRYPT_SM3_*，
 *      于是构建只需要 crypto/sm3 + crypto/bn + crypto/ecc。
 *   2. 不自己取随机数：α、β 由 JS 的 crypto.getRandomValues() 传入，
 *      C 侧只做合法性校验（非 0 且 < n），不合法就返回错误让 JS 重新取。
 *      WASM 里因此不需要 entropy/DRBG，也不用访问 /dev/urandom。
 * =========================================================================== */

#include "cc_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bsl_err.h"
#include "bsl_sal.h"
#include "crypt_bn.h"
#include "crypt_ecc.h"
#include "crypt_errno.h"
#include "crypt_sm3.h"

static const char *g_cc_client_version = "cryptocampus-client-0.1.0";
static char g_cc_client_error[160];
static int g_cc_client_init_done = 0;

const char *cc_client_version(void) { return g_cc_client_version; }

const char *cc_client_last_error(void) { return g_cc_client_error; }

static void cc_client_note(const char *op, int32_t ret) {
    const char *file = NULL;
    uint32_t line = 0;
    (void)BSL_ERR_GetLastErrorFileLine(&file, &line);
    (void)snprintf(g_cc_client_error, sizeof(g_cc_client_error),
                   "%s failed ret=0x%08x at %s:%u",
                   op, (unsigned)ret, file != NULL ? file : "?", (unsigned)line);
}

static void *cc_client_malloc(uint32_t len) { return malloc((size_t)len); }

static void cc_client_init(void) {
    if (g_cc_client_init_done) return;
    BSL_ERR_Init();
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, cc_client_malloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free);
    g_cc_client_init_done = 1;
}

/* 常数时间比较，避免凭证校验分支泄露信息 */
static int cc_client_ct_equal(const uint8_t *a, const uint8_t *b, uint32_t len) {
    uint8_t diff = 0;
    uint32_t i;
    for (i = 0; i < len; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0 ? 1 : 0;
}

static BN_BigNum *cc_client_bn_from(const uint8_t *bin, uint32_t len) {
    BN_BigNum *bn = BN_Create(256);
    if (bn == NULL) return NULL;
    if (BN_Bin2Bn(bn, bin, len) != CRYPT_SUCCESS) { BN_Destroy(bn); return NULL; }
    return bn;
}

/* 编码成 65 字节未压缩点 0x04||X||Y；顺带把点归一到仿射坐标 */
static int cc_client_encode_point(const ECC_Para *para, ECC_Point *pt, uint8_t *out) {
    uint32_t len = CC_CLIENT_POINT_LEN;
    if (ECC_EncodePoint(para, pt, out, &len, CRYPT_POINT_UNCOMPRESSED) != CRYPT_SUCCESS) return -1;
    if (len != CC_CLIENT_POINT_LEN) return -1;
    return 0;
}

/* 解码 65 字节未压缩点，并校验在曲线上且非无穷远 */
static ECC_Point *cc_client_decode_point(const ECC_Para *para, const uint8_t *data) {
    ECC_Point *pt = ECC_NewPoint(para);
    if (pt == NULL) return NULL;
    if (ECC_DecodePoint(para, pt, data, CC_CLIENT_POINT_LEN) != CRYPT_SUCCESS) {
        ECC_FreePoint(pt);
        return NULL;
    }
    if (ECC_PointCheck(pt) != CRYPT_SUCCESS) { ECC_FreePoint(pt); return NULL; }
    return pt;
}

/* c = SM3(x32 || M) mod n；M 用流式 SM3 喂入，不需要拼缓冲区。
   x32 是 R'_x，验签时直接来自凭证，盲化时由 ECC_GetPointDataX 取。 */
static int cc_client_challenge_x(const uint8_t *x32,
                                 const uint8_t *message, uint32_t message_len,
                                 BN_BigNum *c_out, const BN_BigNum *n, BN_Optimizer *opt) {
    CRYPT_SM3_Ctx ctx;
    uint8_t digest[CC_CLIENT_DIGEST_LEN];
    uint32_t out_len = (uint32_t)sizeof(digest);
    BN_BigNum *raw = NULL;
    int rc = CC_CLIENT_INTERNAL_ERROR;

    if (CRYPT_SM3_Init(&ctx) != CRYPT_SUCCESS) {
        cc_client_note("CRYPT_SM3_Init", -1);
        return CC_CLIENT_INTERNAL_ERROR;
    }
    if (CRYPT_SM3_Update(&ctx, x32, CC_CLIENT_SCALAR_LEN) != CRYPT_SUCCESS) {
        cc_client_note("CRYPT_SM3_Update(x)", -1);
        goto DONE;
    }
    if (message_len > 0 && CRYPT_SM3_Update(&ctx, message, message_len) != CRYPT_SUCCESS) {
        cc_client_note("CRYPT_SM3_Update(M)", -1);
        goto DONE;
    }
    if (CRYPT_SM3_Final(&ctx, digest, &out_len) != CRYPT_SUCCESS) {
        cc_client_note("CRYPT_SM3_Final", -1);
        goto DONE;
    }
    raw = cc_client_bn_from(digest, (uint32_t)sizeof(digest));
    if (raw == NULL) { rc = CC_CLIENT_MEMORY_FAILED; goto DONE; }
    if (BN_Mod(c_out, raw, n, opt) != CRYPT_SUCCESS) {
        cc_client_note("BN_Mod(c)", -1);
        goto DONE;
    }
    rc = CC_CLIENT_OK;

DONE:
    (void)CRYPT_SM3_Deinit(&ctx);
    memset(digest, 0, sizeof(digest));
    if (raw != NULL) BN_Destroy(raw);
    return rc;
}

int cc_client_sm3(const uint8_t *data, uint32_t data_len, uint8_t *digest_out) {
    CRYPT_SM3_Ctx ctx;
    uint32_t out_len = CC_CLIENT_DIGEST_LEN;

    if (digest_out == NULL) return CC_CLIENT_INVALID_ARGUMENT;
    if (data == NULL && data_len > 0) return CC_CLIENT_INVALID_ARGUMENT;
    cc_client_init();
    if (CRYPT_SM3_Init(&ctx) != CRYPT_SUCCESS) {
        cc_client_note("CRYPT_SM3_Init", -1);
        return CC_CLIENT_INTERNAL_ERROR;
    }
    if (data_len > 0 && CRYPT_SM3_Update(&ctx, data, data_len) != CRYPT_SUCCESS) {
        cc_client_note("CRYPT_SM3_Update", -1);
        (void)CRYPT_SM3_Deinit(&ctx);
        return CC_CLIENT_INTERNAL_ERROR;
    }
    if (CRYPT_SM3_Final(&ctx, digest_out, &out_len) != CRYPT_SUCCESS) {
        cc_client_note("CRYPT_SM3_Final", -1);
        (void)CRYPT_SM3_Deinit(&ctx);
        return CC_CLIENT_INTERNAL_ERROR;
    }
    (void)CRYPT_SM3_Deinit(&ctx);
    return out_len == CC_CLIENT_DIGEST_LEN ? CC_CLIENT_OK : CC_CLIENT_INTERNAL_ERROR;
}

int cc_client_scalar_is_valid(const uint8_t *scalar32) {
    ECC_Para *para = NULL;
    BN_BigNum *n = NULL;
    BN_BigNum *value = NULL;
    int ok = 0;

    if (scalar32 == NULL) return 0;
    cc_client_init();
    para = ECC_NewPara(CRYPT_ECC_SM2);
    if (para == NULL) return 0;
    n = ECC_GetParaRawN(para);
    value = cc_client_bn_from(scalar32, CC_CLIENT_SCALAR_LEN);
    if (n != NULL && value != NULL && !BN_IsZero(value) && BN_Cmp(value, n) < 0) ok = 1;
    if (value != NULL) BN_Destroy(value);
    ECC_FreePara(para);
    return ok;
}

int cc_client_encode_message(const uint8_t *sn, uint32_t sn_len,
                             const uint8_t *service, uint32_t service_len,
                             const uint8_t *period, uint32_t period_len,
                             uint8_t *out, uint32_t out_capacity, uint32_t *out_len) {
    uint32_t total;

    if (out == NULL || out_len == NULL) return CC_CLIENT_INVALID_ARGUMENT;
    if ((sn == NULL && sn_len > 0) || (service == NULL && service_len > 0) ||
        (period == NULL && period_len > 0)) return CC_CLIENT_INVALID_ARGUMENT;
    total = sn_len + service_len;
    if (total < sn_len) return CC_CLIENT_INVALID_ARGUMENT;   /* 溢出保护 */
    total += period_len;
    if (total < period_len) return CC_CLIENT_INVALID_ARGUMENT;
    if (out_capacity < total) return CC_CLIENT_BUFFER_TOO_SMALL;
    if (sn_len > 0) memcpy(out, sn, sn_len);
    if (service_len > 0) memcpy(out + sn_len, service, service_len);
    if (period_len > 0) memcpy(out + sn_len + service_len, period, period_len);
    *out_len = total;
    return CC_CLIENT_OK;
}

int cc_client_blind(const uint8_t *signer_public_key,
                    const uint8_t *commitment,
                    const uint8_t *message, uint32_t message_len,
                    const uint8_t *alpha, const uint8_t *beta,
                    uint8_t *c_prime_out,
                    uint8_t *state_out,
                    uint8_t *R_prime_out) {
    ECC_Para *para = NULL;
    ECC_Point *Rs = NULL;
    ECC_Point *P = NULL;
    ECC_Point *S = NULL;
    ECC_Point *Rp = NULL;
    BN_BigNum *n = NULL;
    BN_BigNum *alpha_bn = NULL;
    BN_BigNum *beta_bn = NULL;
    BN_BigNum *c = NULL;
    BN_BigNum *cp = NULL;
    BN_BigNum *xbn = NULL;
    BN_Optimizer *opt = NULL;
    uint8_t x[CC_CLIENT_SCALAR_LEN];
    int rc = CC_CLIENT_INTERNAL_ERROR;

    if (signer_public_key == NULL || commitment == NULL || alpha == NULL || beta == NULL ||
        c_prime_out == NULL || state_out == NULL || R_prime_out == NULL) {
        return CC_CLIENT_INVALID_ARGUMENT;
    }
    if (message == NULL && message_len > 0) return CC_CLIENT_INVALID_ARGUMENT;
    cc_client_init();

    para = ECC_NewPara(CRYPT_ECC_SM2);
    if (para == NULL) { cc_client_note("ECC_NewPara(SM2)", -1); return CC_CLIENT_INTERNAL_ERROR; }
    n = ECC_GetParaRawN(para);
    opt = BN_OptimizerCreate();
    S = ECC_NewPoint(para);
    Rp = ECC_NewPoint(para);
    alpha_bn = BN_Create(256);
    beta_bn = BN_Create(256);
    c = BN_Create(256);
    cp = BN_Create(256);
    xbn = BN_Create(256);
    if (n == NULL || opt == NULL || S == NULL || Rp == NULL || alpha_bn == NULL ||
        beta_bn == NULL || c == NULL || cp == NULL || xbn == NULL) {
        rc = CC_CLIENT_MEMORY_FAILED;
        goto DONE;
    }
    if (BN_Bin2Bn(alpha_bn, alpha, CC_CLIENT_SCALAR_LEN) != CRYPT_SUCCESS ||
        BN_Bin2Bn(beta_bn, beta, CC_CLIENT_SCALAR_LEN) != CRYPT_SUCCESS) {
        cc_client_note("BN_Bin2Bn(alpha/beta)", -1);
        rc = CC_CLIENT_INVALID_ARGUMENT;
        goto DONE;
    }
    /* α、β 必须是 [1, n-1]；不合法就让 JS 重新取随机数 */
    if (BN_IsZero(alpha_bn) || BN_Cmp(alpha_bn, n) >= 0 ||
        BN_IsZero(beta_bn) || BN_Cmp(beta_bn, n) >= 0) {
        rc = CC_CLIENT_INVALID_ARGUMENT;
        goto DONE;
    }
    Rs = cc_client_decode_point(para, commitment);
    P = cc_client_decode_point(para, signer_public_key);
    if (Rs == NULL || P == NULL) {
        cc_client_note("decode point(commitment/P)", -1);
        rc = CC_CLIENT_INVALID_ARGUMENT;
        goto DONE;
    }

    /* S = [α]G + [β]P */
    if (ECC_PointMulAdd(para, S, alpha_bn, beta_bn, P) != CRYPT_SUCCESS) {
        cc_client_note("ECC_PointMulAdd(alphaG+betaP)", -1);
        goto DONE;
    }
    /* R' = R + S（Rs 仿射、S Jacobian，ECC_PointAddAffine 支持混合） */
    if (ECC_PointAddAffine(para, Rp, Rs, S) != CRYPT_SUCCESS) {
        cc_client_note("ECC_PointAddAffine(R')", -1);
        goto DONE;
    }
    if (ECC_GetPointDataX(para, Rp, xbn) != CRYPT_SUCCESS) {
        cc_client_note("ECC_GetPointDataX(R')", -1);
        goto DONE;
    }
    if (BN_Bn2BinFixZero(xbn, x, (uint32_t)sizeof(x)) != CRYPT_SUCCESS) {
        cc_client_note("encode(R'_x)", -1);
        goto DONE;
    }
    rc = cc_client_challenge_x(x, message, message_len, c, n, opt);
    if (rc != CC_CLIENT_OK) goto DONE;
    /* c' = (c + β) mod n */
    if (BN_ModAdd(cp, c, beta_bn, n, opt) != CRYPT_SUCCESS) {
        cc_client_note("BN_ModAdd(c')", -1);
        rc = CC_CLIENT_INTERNAL_ERROR;
        goto DONE;
    }
    if (BN_Bn2BinFixZero(cp, c_prime_out, CC_CLIENT_SCALAR_LEN) != CRYPT_SUCCESS ||
        BN_Bn2BinFixZero(alpha_bn, state_out, CC_CLIENT_SCALAR_LEN) != CRYPT_SUCCESS ||
        BN_Bn2BinFixZero(beta_bn, state_out + CC_CLIENT_SCALAR_LEN, CC_CLIENT_SCALAR_LEN) != CRYPT_SUCCESS) {
        cc_client_note("encode(c'/state)", -1);
        rc = CC_CLIENT_INTERNAL_ERROR;
        goto DONE;
    }
    if (cc_client_encode_point(para, Rp, R_prime_out) != 0) {
        cc_client_note("ECC_EncodePoint(R')", -1);
        rc = CC_CLIENT_INTERNAL_ERROR;
        goto DONE;
    }
    rc = CC_CLIENT_OK;

DONE:
    if (rc != CC_CLIENT_OK) {
        memset(c_prime_out, 0, CC_CLIENT_SCALAR_LEN);
        memset(state_out, 0, CC_CLIENT_STATE_LEN);
        memset(R_prime_out, 0, CC_CLIENT_POINT_LEN);
    }
    memset(x, 0, sizeof(x));
    if (Rs != NULL) ECC_FreePoint(Rs);
    if (P != NULL) ECC_FreePoint(P);
    if (S != NULL) ECC_FreePoint(S);
    if (Rp != NULL) ECC_FreePoint(Rp);
    if (alpha_bn != NULL) BN_Destroy(alpha_bn);
    if (beta_bn != NULL) BN_Destroy(beta_bn);
    if (c != NULL) BN_Destroy(c);
    if (cp != NULL) BN_Destroy(cp);
    if (xbn != NULL) BN_Destroy(xbn);
    if (opt != NULL) BN_OptimizerDestroy(opt);
    ECC_FreePara(para);
    return rc;
}

int cc_client_unblind(const uint8_t *s_prime, const uint8_t *state, uint8_t *s_out) {
    ECC_Para *para = NULL;
    BN_BigNum *n = NULL;
    BN_BigNum *sp = NULL;
    BN_BigNum *alpha = NULL;
    BN_BigNum *s = NULL;
    BN_Optimizer *opt = NULL;
    int rc = CC_CLIENT_INTERNAL_ERROR;

    if (s_prime == NULL || state == NULL || s_out == NULL) return CC_CLIENT_INVALID_ARGUMENT;
    cc_client_init();

    para = ECC_NewPara(CRYPT_ECC_SM2);
    if (para == NULL) { cc_client_note("ECC_NewPara(SM2)", -1); return CC_CLIENT_INTERNAL_ERROR; }
    n = ECC_GetParaRawN(para);
    opt = BN_OptimizerCreate();
    sp = cc_client_bn_from(s_prime, CC_CLIENT_SCALAR_LEN);
    alpha = cc_client_bn_from(state, CC_CLIENT_SCALAR_LEN);   /* state = α || β */
    s = BN_Create(256);
    if (n == NULL || opt == NULL || sp == NULL || alpha == NULL || s == NULL) {
        rc = CC_CLIENT_MEMORY_FAILED;
        goto DONE;
    }
    if (BN_ModAdd(s, sp, alpha, n, opt) != CRYPT_SUCCESS) {
        cc_client_note("BN_ModAdd(s)", -1);
        goto DONE;
    }
    if (BN_Bn2BinFixZero(s, s_out, CC_CLIENT_SCALAR_LEN) != CRYPT_SUCCESS) {
        cc_client_note("encode(s)", -1);
        goto DONE;
    }
    rc = CC_CLIENT_OK;

DONE:
    if (rc != CC_CLIENT_OK) memset(s_out, 0, CC_CLIENT_SCALAR_LEN);
    if (sp != NULL) BN_Destroy(sp);
    if (alpha != NULL) BN_Destroy(alpha);
    if (s != NULL) BN_Destroy(s);
    if (opt != NULL) BN_OptimizerDestroy(opt);
    ECC_FreePara(para);
    return rc;
}

int cc_client_credential(const uint8_t *R_prime, const uint8_t *s, uint8_t *credential_out) {
    if (R_prime == NULL || s == NULL || credential_out == NULL) return CC_CLIENT_INVALID_ARGUMENT;
    if (R_prime[0] != 0x04) return CC_CLIENT_INVALID_ARGUMENT;
    memcpy(credential_out, R_prime + 1, CC_CLIENT_SCALAR_LEN);
    memcpy(credential_out + CC_CLIENT_SCALAR_LEN, s, CC_CLIENT_SCALAR_LEN);
    return CC_CLIENT_OK;
}

int cc_client_verify(const uint8_t *credential,
                     const uint8_t *message, uint32_t message_len,
                     const uint8_t *signer_public_key) {
    ECC_Para *para = NULL;
    ECC_Point *P = NULL;
    ECC_Point *Q = NULL;
    BN_BigNum *n = NULL;
    BN_BigNum *sbn = NULL;
    BN_BigNum *c = NULL;
    BN_BigNum *nc = NULL;
    BN_BigNum *zero = NULL;
    BN_BigNum *xbn = NULL;
    BN_Optimizer *opt = NULL;
    uint8_t xq[CC_CLIENT_SCALAR_LEN];
    int rc = CC_CLIENT_INTERNAL_ERROR;

    if (credential == NULL || signer_public_key == NULL) return CC_CLIENT_INVALID_ARGUMENT;
    if (message == NULL && message_len > 0) return CC_CLIENT_INVALID_ARGUMENT;
    cc_client_init();

    para = ECC_NewPara(CRYPT_ECC_SM2);
    if (para == NULL) { cc_client_note("ECC_NewPara(SM2)", -1); return CC_CLIENT_INTERNAL_ERROR; }
    n = ECC_GetParaRawN(para);
    opt = BN_OptimizerCreate();
    Q = ECC_NewPoint(para);
    c = BN_Create(256);
    nc = BN_Create(256);
    zero = BN_Create(256);
    xbn = BN_Create(256);
    sbn = cc_client_bn_from(credential + CC_CLIENT_SCALAR_LEN, CC_CLIENT_SCALAR_LEN);
    if (n == NULL || opt == NULL || Q == NULL || c == NULL || nc == NULL ||
        zero == NULL || xbn == NULL || sbn == NULL) {
        rc = CC_CLIENT_MEMORY_FAILED;
        goto DONE;
    }
    if (BN_Zeroize(zero) != CRYPT_SUCCESS) { cc_client_note("BN_Zeroize", -1); goto DONE; }

    P = cc_client_decode_point(para, signer_public_key);
    if (P == NULL) { rc = 0; goto DONE; }              /* 非法公钥 => 验签不通过 */
    if (BN_IsZero(sbn) || BN_Cmp(sbn, n) >= 0) { rc = 0; goto DONE; }   /* s 必须落在 [1,n-1] */

    rc = cc_client_challenge_x(credential, message, message_len, c, n, opt);
    if (rc != CC_CLIENT_OK) goto DONE;
    /* nc = (0 - c) mod n；c == 0 时得 0，此时 [s]G + [0]P = [s]G，仍然正确 */
    if (BN_ModSub(nc, zero, c, n, opt) != CRYPT_SUCCESS) {
        cc_client_note("BN_ModSub(-c)", -1);
        rc = CC_CLIENT_INTERNAL_ERROR;
        goto DONE;
    }
    /* Q = [s]G + [n-c]P = [s]G - [c]P */
    if (ECC_PointMulAdd(para, Q, sbn, nc, P) != CRYPT_SUCCESS) {
        cc_client_note("ECC_PointMulAdd(verify)", -1);
        rc = 0;
        goto DONE;
    }
    if (ECC_GetPointDataX(para, Q, xbn) != CRYPT_SUCCESS) { rc = 0; goto DONE; }
    if (BN_Bn2BinFixZero(xbn, xq, (uint32_t)sizeof(xq)) != CRYPT_SUCCESS) { rc = 0; goto DONE; }
    /* x-only 比较：凭证只带 R'_x，与 c = SM3(R'_x || M) 的取法一致 */
    rc = cc_client_ct_equal(xq, credential, CC_CLIENT_SCALAR_LEN) ? 1 : 0;

DONE:
    memset(xq, 0, sizeof(xq));
    if (P != NULL) ECC_FreePoint(P);
    if (Q != NULL) ECC_FreePoint(Q);
    if (sbn != NULL) BN_Destroy(sbn);
    if (c != NULL) BN_Destroy(c);
    if (nc != NULL) BN_Destroy(nc);
    if (zero != NULL) BN_Destroy(zero);
    if (xbn != NULL) BN_Destroy(xbn);
    if (opt != NULL) BN_OptimizerDestroy(opt);
    ECC_FreePara(para);
    return rc;
}