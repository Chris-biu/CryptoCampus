/* ===========================================================================
 * cc_client.h —— 客户端密码模块（浏览器 WASM）对外 ABI
 *
 * 定位：只做盲签名的「客户端两步」，不含任何私钥输入、不含签名能力。
 *       浏览器无法加载 .so，所以把这一份 C 代码单独交叉编译成 WASM，
 *       由 web/src/security/ 下的适配器挂到 window.cryptoCampusCredentialProvider。
 *
 * 与服务端 ABI（cc_bridge.h）的分工：
 *   cc_bridge_sm2_blind_commit / blind_sign  = 签名方（服务端），持有私钥与一次性 k
 *   cc_client_blind / cc_client_unblind      = 客户端（浏览器），持有 α、β
 *   cc_client_verify                          = 任意验签方（x-only）
 *
 * 设计约束（故意的，别改成 malloc/返回值）：
 *   - 全部输出都是调用方提供的定长缓冲区，长度在编译期确定，方便 JS 侧
 *     用 _malloc + HEAPU8 直接读写，不需要理解结构体布局。
 *   - 随机数不从 C 侧取。α、β、SN 由 JS 用 crypto.getRandomValues() 生成后传入，
 *     这样 WASM 里不需要 entropy/DRBG，也不用访问 /dev/urandom。
 *   - 不使用 openHiTLS 的 EAL / provider / PKI 层，只用 crypto/sm3 + bn + ecc，
 *     这样 WASM 构建可以裁到最小（见 bridge/wasm/build.sh）。
 *
 * 凭证布局（关键）：
 *   credential[64] = R'_x(32) || s(32)
 *   验签只需比较 x 坐标（c = SM3(R'_x || M) mod n 本来就只用 x），
 *   因此凭证恰好 64 字节，与现有 CredentialProof.signature 的 64 字节校验一致，
 *   openapi / schemas / 前端类型都不用改。
 * =========================================================================== */

#ifndef CC_CLIENT_H
#define CC_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CC_CLIENT_SCALAR_LEN 32
#define CC_CLIENT_POINT_LEN  65   /* 0x04 || X(32) || Y(32) */
#define CC_CLIENT_STATE_LEN  64   /* α(32) || β(32) */
#define CC_CLIENT_CRED_LEN   64   /* R'_x(32) || s(32) */
#define CC_CLIENT_DIGEST_LEN 32

/* 与 cc_bridge.h 保持同一套错误码语义 */
#define CC_CLIENT_OK                 0
#define CC_CLIENT_INVALID_ARGUMENT (-1001)
#define CC_CLIENT_BUFFER_TOO_SMALL (-1002)
#define CC_CLIENT_UNSUPPORTED      (-1009)
#define CC_CLIENT_MEMORY_FAILED    (-1012)
#define CC_CLIENT_INTERNAL_ERROR   (-1099)

/* 模块自检用；返回非 NULL 的版本字符串 */
const char *cc_client_version(void);

/* 最近一次失败的原因（含 openHiTLS 内部文件行号），供浏览器 console 打印 */
const char *cc_client_last_error(void);

/* 第 2 步（客户端本地）：盲化。
 *   signer_public_key 65 字节（0x04||X||Y），签名方公钥 P
 *   commitment        65 字节（0x04||X||Y），签名方本轮一次性承诺 R = [k]G
 *   message           M 的字节（服务端编码为 SN || service || period）
 *   alpha / beta      各 32 字节，必须来自 JS 的 crypto.getRandomValues()，
 *                     且必须是 [1, n-1] 内的合法标量，否则返回 CC_CLIENT_INVALID_ARGUMENT
 *   c_prime_out       32 字节，c' = (c + β) mod n，发给服务端
 *   state_out         64 字节，α||β，只留在客户端，回传给 cc_client_unblind
 *   R_prime_out       65 字节，R' = R + [α]G + [β]P
 * 返回 CC_CLIENT_OK 或错误码。 */
int cc_client_blind(const uint8_t *signer_public_key,
                    const uint8_t *commitment,
                    const uint8_t *message, uint32_t message_len,
                    const uint8_t *alpha, const uint8_t *beta,
                    uint8_t *c_prime_out,
                    uint8_t *state_out,
                    uint8_t *R_prime_out);

/* 第 4 步（客户端本地）：去盲。
 *   s_prime 32 字节（服务端返回的 s'）
 *   state   64 字节（α||β）
 *   s_out   32 字节，s = (s' + α) mod n */
int cc_client_unblind(const uint8_t *s_prime, const uint8_t *state, uint8_t *s_out);

/* 把 (R', s) 打包成凭证：credential_out[64] = R'_x || s */
int cc_client_credential(const uint8_t *R_prime, const uint8_t *s, uint8_t *credential_out);

/* M = SN || service || period，必须与服务端 app/schemas/credential.py 的
 * encode_credential_message 完全一致（纯字节拼接，service/period 为 ASCII）。
 * out 容量需 >= sn_len + service_len + period_len；写回 *out_len。 */
int cc_client_encode_message(const uint8_t *sn, uint32_t sn_len,
                             const uint8_t *service, uint32_t service_len,
                             const uint8_t *period, uint32_t period_len,
                             uint8_t *out, uint32_t out_capacity, uint32_t *out_len);

/* x-only 验签：c = SM3(R'_x || M) mod n，检查 x([s]G - [c]P) == R'_x
 * 返回 1 通过 / 0 无效 / <0 错误码。 */
int cc_client_verify(const uint8_t *credential,
                     const uint8_t *message, uint32_t message_len,
                     const uint8_t *signer_public_key);

/* SM3，供前端/KAT 自测交叉核对（与服务端 cc_bridge_sm3_digest 必须一致） */
int cc_client_sm3(const uint8_t *data, uint32_t data_len, uint8_t *digest_out);

/* 从 32 字节随机源推导合法标量：非 0 且 < n 时返回 1，否则返回 0（调用方重新取随机数）。
 * 目的是让 JS 侧能做拒绝采样，而不是在 C 里引入 RNG。 */
int cc_client_scalar_is_valid(const uint8_t *scalar32);

#ifdef __cplusplus
}
#endif

#endif /* CC_CLIENT_H */