#ifndef CC_BRIDGE_H
#define CC_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Bridge ABI error codes (contract: docs/api/bridge-contract.md) */
enum {
    CCB_OK = 0,
    CCB_INVALID_ARGUMENT = -1001,
    CCB_BUFFER_TOO_SMALL = -1002,
    CCB_AUTH_FAILED = -1003,
    CCB_INTEGRITY_FAILED = -1004,
    CCB_CERT_INVALID = -1005,
    CCB_CERT_REVOKED = -1006,
    CCB_REPLAYED = -1007,
    CCB_QUOTA_REJECTED = -1008,
    CCB_UNSUPPORTED = -1009,
    CCB_PROVIDER_UNAVAILABLE = -1010,
    CCB_RANDOM_FAILED = -1011,
    CCB_MEMORY_FAILED = -1012,
    CCB_INTERNAL_ERROR = -1099
};

typedef struct {
    uint8_t *data;
    size_t capacity;
    size_t len;
} cc_bridge_buffer;

int cc_bridge_init(const char *provider_dir);
const char *cc_bridge_version(void);
int cc_bridge_random_bytes(uint8_t *out, size_t out_len);

int cc_bridge_sm3_digest(const uint8_t *message, size_t message_len,
                         cc_bridge_buffer *digest);

/* 口令认证哈希：SM3(salt_a || password) */
int cc_bridge_sm3_hash_password(const uint8_t *password_utf8, size_t password_len,
                                const uint8_t *salt_a, size_t salt_a_len,
                                cc_bridge_buffer *auth_hash);

/* HKDF-SM3。out->capacity 即请求的派生长度（16~64 字节）。 */
int cc_bridge_hkdf_sm3(const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len,
                       cc_bridge_buffer *out);

int cc_bridge_sm4_gcm_encrypt(const uint8_t *key, const uint8_t *plaintext, size_t plaintext_len,
                              const uint8_t *aad, size_t aad_len,
                              cc_bridge_buffer *ciphertext, cc_bridge_buffer *nonce, cc_bridge_buffer *tag);

int cc_bridge_sm4_gcm_decrypt(const uint8_t *key, const uint8_t *nonce,
                              const uint8_t *ciphertext, size_t ciphertext_len,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *tag, size_t tag_len,
                              cc_bridge_buffer *plaintext);

int cc_bridge_sm2_generate_keypair(cc_bridge_buffer *private_key, cc_bridge_buffer *public_key);
int cc_bridge_sm2_sign(const uint8_t *private_key, const uint8_t *digest,
                       cc_bridge_buffer *signature);
int cc_bridge_sm2_verify(const uint8_t *public_key, const uint8_t *digest,
                         const uint8_t *signature, size_t signature_len);
int cc_bridge_sm2_encrypt(const uint8_t *public_key, const uint8_t *plaintext, size_t plaintext_len,
                          cc_bridge_buffer *ciphertext);
int cc_bridge_sm2_decrypt(const uint8_t *private_key, const uint8_t *ciphertext, size_t ciphertext_len,
                          cc_bridge_buffer *plaintext);
int cc_bridge_sm2_ecdh(const uint8_t *private_key, const uint8_t *peer_public_key,
                       cc_bridge_buffer *shared_secret);

/* ---------------------------------------------------------------------------
 * 数字信封 v2（密信快传，对齐 server/app/crypto/engine.py 与 types.py 契约）
 *
 *   seal:  plaintext + recipient_sm2_public_key + sender_private_key
 *          + sender_certificate_der + access_factor -> EnvelopeArtifact
 *   open:  EnvelopeArtifact + recipient_sm2_private_key + access_factor -> plaintext
 *
 * 语义（与 drop.py 严格一致）：
 *   - 会话种子 16B 由 /dev/urandom 生成；
 *   - 内容密钥 K = HKDF-SM3(ikm=seed, salt=access_factor(缺省为空), info="drop-access-factor", L=16)；
 *   - SM4-GCM(K)，AAD 恒为 "CryptoCampus-Drop-v1"，nonce 12B / tag 16B；
 *   - enc_key_sm2 = SM2 加密(recipient 公钥, seed)；
 *   - sender_signature = SM2 签名(sender 私钥, SM3(ciphertext))；
 *   - sender_certificate 原样回填（供 EnvelopeArtifact.sender_certificate）。
 *
 * pqc_mode 非 0 时当前实现返回 CCB_UNSUPPORTED（ML-KEM 封装分量待接）。
 * access_factor 为 NULL 或 16~32 字节。
 * ------------------------------------------------------------------------- */

typedef struct {
    cc_bridge_buffer ciphertext;        /* seal 输出：与明文等长 */
    cc_bridge_buffer nonce;             /* seal 输出：12 字节 */
    cc_bridge_buffer tag;               /* seal 输出：16 字节 */
    cc_bridge_buffer enc_key_sm2;       /* seal 输出：SM2 封装后的会话种子（<=512） */
    cc_bridge_buffer enc_key_mlkem;     /* 预留（PQC）：当前恒为空 */
    cc_bridge_buffer sender_signature;  /* seal 输出：64 字节 r||s */
    cc_bridge_buffer sender_certificate;/* seal 输出：原样回填的发送者证书 DER */
} cc_bridge_envelope;

int cc_bridge_envelope_seal(const uint8_t *plaintext, size_t plaintext_len,
                            const uint8_t *recipient_sm2_public_key,
                            int pqc_mode,
                            const uint8_t *recipient_mlkem_public_key,
                            const uint8_t *sender_private_key,
                            const uint8_t *sender_certificate_der, size_t sender_certificate_len,
                            const uint8_t *access_factor, size_t access_factor_len,
                            cc_bridge_envelope *out);

int cc_bridge_envelope_open(const cc_bridge_envelope *env,
                            const uint8_t *recipient_sm2_private_key,
                            int pqc_mode,
                            const uint8_t *recipient_mlkem_private_key,
                            const uint8_t *access_factor, size_t access_factor_len,
                            cc_bridge_buffer *plaintext);

int cc_bridge_csr_create(const uint8_t *private_key, size_t private_key_len,
                         const uint8_t *public_key, size_t public_key_len,
                         const char *common_name,
                         cc_bridge_buffer *csr_der);

int cc_bridge_cert_sign(const uint8_t *csr_der, size_t csr_der_len,
                        const uint8_t *ca_certificate_der, size_t ca_certificate_der_len,
                        const uint8_t *ca_private_key, size_t ca_private_key_len,
                        int64_t not_before, int64_t not_after,
                        uint32_t key_usage,
                        cc_bridge_buffer *cert_der,
                        cc_bridge_buffer *serial_out);

int cc_bridge_cert_chain_verify(const uint8_t *leaf_certificate_der, size_t leaf_der_len,
                                const uint8_t *chain_der, size_t chain_der_len,
                                const uint8_t *trust_root_der, size_t trust_root_len,
                                int64_t verification_time,
                                uint32_t required_key_usage);

int cc_bridge_crl_create(const uint8_t *revoked_serials_hex, size_t revoked_serials_hex_len,
                         const uint8_t *ca_certificate_der, size_t ca_certificate_der_len,
                         const uint8_t *ca_private_key, size_t ca_private_key_len,
                         int64_t this_update, int64_t next_update,
                         cc_bridge_buffer *crl_der);

int cc_bridge_crl_verify(const uint8_t *certificate_der, size_t certificate_len,
                         const uint8_t *crl_der, size_t crl_len,
                         int64_t verification_time);
int cc_bridge_sm2_blind_commit(cc_bridge_buffer *k_out /*>=32*/,
                               cc_bridge_buffer *R_out /*>=65*/);

int cc_bridge_sm2_blind_blind(const uint8_t *R, const uint8_t *signer_public_key,
                              const uint8_t *message, size_t message_len,
                              cc_bridge_buffer *c_prime_out /*>=32*/,
                              cc_bridge_buffer *state_out   /*>=64, α||β*/,
                              cc_bridge_buffer *R_prime_out /*>=65*/);

int cc_bridge_sm2_blind_sign(const uint8_t *k, const uint8_t *c_prime,
                             const uint8_t *signer_private_key,
                             cc_bridge_buffer *s_prime_out /*>=32*/);

int cc_bridge_sm2_blind_unblind(const uint8_t *s_prime, const uint8_t *state,
                                cc_bridge_buffer *s_out /*>=32*/);

int cc_bridge_sm2_blind_verify(const uint8_t *R_prime,
                               const uint8_t *message, size_t message_len,
                               const uint8_t *s, const uint8_t *signer_public_key);

int cc_bridge_constant_time_equal(const uint8_t *a, size_t a_len,
                                  const uint8_t *b, size_t b_len);

void cc_bridge_buffer_free(void *ptr, size_t len, int sensitive);

#ifdef __cplusplus
}
#endif

#endif /* CC_BRIDGE_H */