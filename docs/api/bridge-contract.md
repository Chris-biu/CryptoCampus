# CryptoCampus 密码桥接层契约

> 版本：1.0.0  
> 范围：FastAPI 后端与 openHiTLS 密码桥接层之间的调用边界  
> 对应 HTTP/WebSocket 契约：`docs/api/openapi.yaml`

## 1. 契约定位

本文件只定义后端可调用的密码能力、输入输出、错误、内存所有权和敏感数据边界，不包含 C 实现、Python 业务实现或密码算法实现。

文中的 `cc_bridge_*` 名称是 **CryptoCampus 项目桥接层的逻辑接口名**，不是对 openHiTLS 原始导出符号的声明。密码引擎负责人必须依据实际版本的 openHiTLS 头文件，把每个逻辑接口映射到真实能力并在 MR 中评审确认；不得把 AI 推测的 `HITLS_*`、`CRYPT_*` 等名称直接写入绑定。

后端只能进行参数校验、权限、额度、事务、持久化和调用编排，不得自行实现 SM2、SM3、SM4、盲签名、ML-KEM、ML-DSA、证书或 TLCP 原语。

## 2. 课程范围与优先级

| 级别 | 能力 |
|---|---|
| 课程核心 | SM3、HKDF/PBKDF2-SM3、SM4-GCM、SM2 密钥/加解密/签名/验签/ECDH、数字信封、普通盲签名协议、CSR/证书链/CRL、Provider/TLCP 状态 |
| 课程选做/进阶 | ML-KEM-768、ML-DSA-65、安全聊天混合协商、公平盲签名双管理员揭示、PDF 签章页所需签名材料 |
| 后期时间充裕再实施 | HSM、远程 KMS、多节点 Provider 热切换、正式 OCSP/TSA 服务、硬件安全区和高并发池化 |

生产级扩展不得改变本契约中的安全边界，也不得阻塞课程核心能力。

## 3. 通用 ABI 约定

### 3.1 数据类型

| 类型 | 定义 | 所有权 |
|---|---|---|
| `cc_bridge_bytes` | `{const uint8_t *data; size_t len;}`，只读输入 | 调用方拥有；桥接层不得保存或释放 |
| `cc_bridge_buffer` | `{uint8_t *data; size_t capacity; size_t len;}`，可写输出 | 调用方分配和释放；桥接层只写入并更新 `len` |
| `cc_bridge_string` | UTF-8 字节串，不含结尾 NUL，长度显式传递 | 与 `cc_bridge_bytes` 相同 |
| `cc_bridge_bool` | 仅允许 `0` 或 `1` | 值类型 |
| `cc_bridge_time` | Unix 秒数 `int64_t`，对外 API 转 RFC 3339 | 值类型 |
| `cc_bridge_error` | `{int32_t code; char message[160]; size_t required_capacity;}` | 调用方提供 |

所有长度使用 `size_t`。禁止使用隐式 NUL 终止推断二进制长度，禁止把指针地址写入日志或响应。

### 3.2 输出缓冲区

1. 调用方先按本契约给出的固定长度或上限分配输出缓冲区。
2. 容量不足时返回 `CCB_BUFFER_TOO_SMALL`，并在 `required_capacity` 写入所需容量；不得截断输出。
3. 桥接层不得返回由自身堆分配且要求 Python 直接 `free()` 的内存，避免跨运行库释放。
4. 输出失败时，桥接层将 `buffer.len` 置零；含敏感材料的输出缓冲区必须先清零。

### 3.3 编码

| 对象 | 桥接层表示 | HTTP 层表示 |
|---|---|---|
| 任意二进制 | 原始字节 + 显式长度 | Base64；URL/令牌类使用 Base64URL |
| SM3 摘要 | 32 字节 | Base64 或脱敏十六进制前缀 |
| SM2 私钥 | 32 字节标量，仅桥接层/受控内存可见 | 禁止返回 |
| SM2 公钥 | 65 字节未压缩点 `0x04 || X || Y` | Base64 |
| SM2 签名 | 64 字节 `r || s` | Base64 |
| CSR/证书/CRL | DER | Base64；下载时允许 PEM 包装 |
| 时间 | Unix 秒 | RFC 3339，必须带时区 |

若实际 openHiTLS API 使用 DER 签名或其他点编码，映射层负责在桥接边界内转换；后端不得解析曲线点或签名整数。

## 4. 返回值与错误码

所有逻辑接口返回 `int32_t`。`0` 表示成功，负值表示失败。

| 错误码 | 值 | 含义 | 推荐 HTTP 映射 |
|---|---:|---|---|
| `CCB_OK` | 0 | 成功 | 2xx |
| `CCB_INVALID_ARGUMENT` | -1001 | 空指针、长度、枚举或编码不合法 | 400/422 |
| `CCB_BUFFER_TOO_SMALL` | -1002 | 输出容量不足，`required_capacity` 有效 | 后端重试；不得直接对外返回 |
| `CCB_AUTH_FAILED` | -1003 | 口令验证或密钥解锁失败 | 401 或统一凭据错误 |
| `CCB_INTEGRITY_FAILED` | -1004 | GCM Tag、签名或信封完整性失败 | 409；不得输出明文 |
| `CCB_CERT_INVALID` | -1005 | 证书链、用途或时间校验失败 | 409 |
| `CCB_CERT_REVOKED` | -1006 | CRL 判定已吊销 | 409 |
| `CCB_REPLAYED` | -1007 | 盲凭证或消息序号已消费/重放 | 409 |
| `CCB_QUOTA_REJECTED` | -1008 | 协议签发前的额度/重复签发拒绝 | 429/409；通常由后端事务层产生 |
| `CCB_UNSUPPORTED` | -1009 | 当前构建或 Provider 不支持能力 | 503 |
| `CCB_PROVIDER_UNAVAILABLE` | -1010 | Provider 未加载或状态异常 | 503 |
| `CCB_RANDOM_FAILED` | -1011 | 密码安全随机数失败 | 500 |
| `CCB_MEMORY_FAILED` | -1012 | 内存分配或安全缓冲失败 | 500 |
| `CCB_INTERNAL_ERROR` | -1099 | 其他已脱敏内部错误 | 500 |

`message` 只能使用固定、脱敏的中文错误描述，不得包含 openHiTLS 原始堆栈、指针、私钥、口令、KEK、会话密钥、业务明文或完整密码中间值。

## 5. 通用安全规则

- 随机密钥、Nonce、SN 和临时密钥必须来自 openHiTLS 可用的密码安全随机源；禁止时间种子、固定值或普通伪随机数。
- 私钥、KEK、会话密钥、共享秘密、盲化因子和口令只存在于受控内存；使用后立即安全清零。
- 管理员操作不得绕过密码边界。管理员可以销毁密文、吊销证书或凭证、查询状态，但不能调用“解密任意用户内容”的接口。
- 普通盲签名的签发登记与凭证消费数据分离；签发接口只接收盲化消息，不接收 SN 或去盲签名。
- 选票和树洞匿名消费接口不得同时接收 JWT 身份与匿名凭证明文。
- 聊天服务端只存储和转发密文、签名、序号及路由信息，不调用消息解密接口。
- 密码透视只记录算法名、输入长度、结果状态和脱敏前缀，不记录完整输入输出。

## 6. SM3 与口令派生

### 6.1 `cc_bridge_sm3_digest`

用途：文件摘要、审计链、撤销链、指纹和 SM3 雪崩实验。

| 输入 | 类型 | 长度/约束 |
|---|---|---|
| `message` | `cc_bridge_bytes` | 0～100 MiB；更大文件由调用方分块流式调用上下文接口 |
| `digest` | `cc_bridge_buffer` | 容量至少 32 字节 |

输出：`digest.len = 32`。输入不是敏感内容时可记录长度；任何消息内容都不得记录。

### 6.2 `cc_bridge_sm3_hash_password`

用途：计算课程定义的 `SM3(salt_a || password)` 认证哈希。

| 输入 | 类型 | 长度/约束 |
|---|---|---|
| `password_utf8` | `cc_bridge_bytes` | 1～512 字节；API 已限制 10～128 字符 |
| `salt_a` | `cc_bridge_bytes` | 16～64 字节，每用户独立随机 |
| `auth_hash` | `cc_bridge_buffer` | 容量至少 32 字节 |

输出：32 字节。桥接层同时提供恒定时间比较能力 `cc_bridge_constant_time_equal(a, b)`；两个输入必须等长且不超过 4096 字节。

### 6.3 `cc_bridge_hkdf_sm3`

用途：用户 KEK、提取口令附加因子、聊天双向会话密钥派生。

| 输入 | 类型 | 长度/约束 |
|---|---|---|
| `ikm` | `cc_bridge_bytes` | 1～4096 字节，敏感 |
| `salt` | `cc_bridge_bytes` | 0～64 字节 |
| `info` | `cc_bridge_bytes` | 1～128 字节；固定业务域分离字符串 |
| `output` | `cc_bridge_buffer` | 请求 16～64 字节 |

允许的 `info`：`user-kek`、`keyring-backup-kek-v1`、`drop-access-factor`、`chat-session-send`、`chat-session-recv`。禁止用同一 `info` 跨业务复用密钥。

### 6.4 `cc_bridge_pbkdf2_hmac_sm3`

用途：课程允许的 PBKDF2-SM3 口令派生方案。项目选定 HKDF-SM3 后可返回 `CCB_UNSUPPORTED`，但不得静默改用其他摘要。

输入：口令 1～512 字节、盐 16～64 字节、迭代次数 10,000～10,000,000、输出 16～64 字节。

## 7. SM4-GCM 与教学模式试验

### 7.1 固定参数

| 参数 | 长度 |
|---|---:|
| SM4 密钥 | 16 字节 |
| GCM Nonce | 12 字节 |
| GCM Tag | 16 字节 |
| AAD | 0～64 KiB |
| 单次业务明文/密文 | 0～100 MiB |

### 7.2 `cc_bridge_sm4_gcm_encrypt`

输入：16 字节密钥、12 字节随机 Nonce、明文、可选 AAD。输出：与明文等长的密文和 16 字节 Tag。

Nonce 必须由引擎生成或由调用方提供并保证同一密钥下不重复。生产业务禁止固定 Nonce。输出失败时密文与 Tag 均清零。

### 7.3 `cc_bridge_sm4_gcm_decrypt`

输入：密钥、Nonce、密文、AAD、Tag。只有 Tag 验证成功才写出明文；Tag 失败返回 `CCB_INTEGRITY_FAILED`，明文长度必须为 0。

### 7.4 `cc_bridge_sm4_mode_experiment`

用途：FR-09 教学试验台中的 ECB/CBC/CTR/GCM 对比。仅允许显式标记为 `experiment=true` 的脱敏试验数据，禁止被快传、密钥托管、聊天或签章业务调用。

支持模式：`ECB`、`CBC`、`CTR`、`GCM`。ECB 结果必须携带 `unsafe_for_business=true`。CBC IV 为 16 字节；CTR Counter 为 16 字节；GCM 使用上述固定参数。

## 8. SM2 基础能力

### 8.1 `cc_bridge_sm2_generate_keypair`

输出：32 字节私钥和 65 字节未压缩公钥。随机源失败必须整体失败，不得返回部分密钥。私钥输出由调用方立即加密托管或放入 15 分钟受控缓存。

### 8.2 `cc_bridge_sm2_encrypt` / `cc_bridge_sm2_decrypt`

用途：课程 SM2 加解密与数字信封分量。公钥固定 65 字节，私钥固定 32 字节；密文为 DER/引擎格式的可变长字节，最大 `plaintext_len + 512`。解密失败不得输出部分明文。

### 8.3 `cc_bridge_sm2_sign` / `cc_bridge_sm2_verify`

输入摘要固定 32 字节；签名输出固定 64 字节 `r || s`。验签只返回布尔结果和错误码，不返回私钥或完整中间点。

### 8.4 `cc_bridge_sm2_ecdh`

输入：本方 32 字节私钥、对方 65 字节公钥。输出：32 字节共享秘密，必须立即交给 HKDF-SM3，禁止直接作为 SM4 密钥。共享秘密在派生后立即清零。

## 9. 数字信封

### 9.1 `cc_bridge_envelope_seal`

用途：`POST /drops/text`、`POST /drops/file`。

输入：

- 明文 1～100 MiB；
- 收件人 SM2 公钥 65 字节；
- `pqc_mode`；
- `pqc_mode=true` 时必须提供 ML-KEM-768 公钥 1184 字节；
- 发送者 SM2 私钥 32 字节和证书 DER；
- 可选提取口令派生因子 16～32 字节。

输出结构：

| 字段 | 长度/说明 |
|---|---|
| `ciphertext` | 与明文等长 |
| `nonce` | 12 字节 |
| `tag` | 16 字节 |
| `enc_key_sm2` | 可变长，最多 512 字节 |
| `enc_key_mlkem` | 关闭 PQC 时为空；开启时 1088 字节 |
| `sender_signature` | 64 字节 |
| `sender_certificate` | DER，最大 64 KiB |

### 9.2 `cc_bridge_envelope_open`

用途：`POST /drops/{code}/extract`。

验证顺序固定为：信封结构和长度 → GCM Tag → 发送者证书链/CRL → 发送者签名 → SM2/ML-KEM 解封与 KDF → 明文输出。任一步失败都不得继续输出明文。

阅后即焚和到期删除由后端事务层执行；桥接层只返回解密结果和 SM3 审计摘要。

## 10. 盲签名协议层

### 10.1 普通盲签名

| 逻辑接口 | 调用方 | 输入 | 输出 |
|---|---|---|---|
| `cc_bridge_blind_prepare` | 客户端密码能力 | `M = SN || service || period`，SN 至少 16 随机字节 | 盲化消息、盲化因子 |
| `cc_bridge_blind_sign` | 服务端签发器 | 盲化消息、签发私钥 | 盲签名 |
| `cc_bridge_blind_unblind` | 客户端密码能力 | 盲签名、盲化因子 | 64 字节凭证签名 |
| `cc_bridge_blind_verify` | 服务端/公开验证 | M、64 字节签名、平台公钥 | 有效/无效 |

`blind_prepare` 和 `blind_unblind` 属于协议的客户端步骤。Web 前端不得手写算法；若课程运行形态暂时没有经真实 openHiTLS 验证的客户端密码模块，后端 API 仍只接受 `blinded_message`，不得为“跑通流程”而让签发器同时看到 SN、盲化因子和去盲凭证。

树洞绑定 `service` 与 `period`；投票额外绑定 `vote_id`。消费表的“验签 + 未消费检查 + 标记已消费”必须由后端在同一事务完成。

### 10.2 公平盲签名（课程进阶）

逻辑接口：`cc_bridge_fair_blind_reveal_share` 和 `cc_bridge_fair_blind_combine_shares`。单个管理员份额不得揭示身份；合并必须验证两个不同管理员的批准记录。份额、托管私钥和完整揭示证明禁止进入日志或普通 API 响应。

如果课程提供的参考实现或实际 openHiTLS 组合原语未通过密码引擎负责人确认，接口返回 `CCB_UNSUPPORTED`，普通盲签名课程核心流程不受影响。

## 11. CSR、证书与吊销

| 逻辑接口 | 输入 | 输出/约束 |
|---|---|---|
| `cc_bridge_csr_create` | SM2 私钥、公钥、主题字段 | DER CSR，最大 64 KiB |
| `cc_bridge_cert_sign` | CSR、CA 证书、CA 私钥、有效期、keyUsage | DER 用户/口径章证书，最大 64 KiB |
| `cc_bridge_cert_chain_verify` | 叶证书、证书链、信任根、验证时间 | 链有效、用途有效、时间有效 |
| `cc_bridge_crl_create` | 已吊销序列号集合、CA 材料、更新时间 | DER CRL，最大 4 MiB |
| `cc_bridge_crl_verify` | 证书、CRL、验证时间 | 未吊销/已吊销 |

主题字段仅允许课程所需的 `CN=user_id` 和角色扩展；后端负责授权，证书角色不能单独替代当前 JWT 角色检查。CA、计票台和口径章私钥必须加密托管，操作全部进入审计日志。

## 12. ML-KEM 与 ML-DSA（课程进阶）

### 12.1 ML-KEM-768

| 对象 | 固定长度 |
|---|---:|
| 公钥 | 1184 字节 |
| 私钥 | 2400 字节 |
| KEM 密文 | 1088 字节 |
| 共享秘密 | 32 字节 |

逻辑接口：`cc_bridge_ml_kem_generate_keypair`、`cc_bridge_ml_kem_encapsulate`、`cc_bridge_ml_kem_decapsulate`。

解封失败必须返回 `CCB_INTEGRITY_FAILED` 或 Provider 定义的等价失败，不得使用失败输出继续派生业务密钥。混合信封必须同时具备 SM2 与 ML-KEM 分量；缺一返回失败。

### 12.2 ML-DSA-65

| 对象 | 固定长度 |
|---|---:|
| 公钥 | 1952 字节 |
| 私钥 | 4032 字节 |
| 签名 | 3309 字节 |

逻辑接口：`cc_bridge_ml_dsa_generate_keypair`、`cc_bridge_ml_dsa_sign`、`cc_bridge_ml_dsa_verify`。私钥不得返回到 HTTP 层；文件签章 API 只返回公钥/证书材料与签名。

所有固定长度必须由密码引擎负责人用实际 Provider 的算法参数再次核对。课程 UI 中的展示文本不是 ABI 长度依据。

## 13. 安全聊天能力（课程进阶）

后端可调用：

- `cc_bridge_sm2_ecdh`；
- `cc_bridge_ml_kem_encapsulate` / `decapsulate`；
- `cc_bridge_hkdf_sm3`；
- `cc_bridge_sm4_gcm_encrypt` / `decrypt`；
- `cc_bridge_sm2_sign` / `verify`。

WebSocket 服务只转发公开协商材料、KEM 密文、消息密文、Nonce、Tag、签名和递增序号。消息验签、防重放和明文加解密在客户端密码能力边界完成；服务端不得提供“查看聊天明文”或“管理员解密”逻辑接口。

## 14. Provider 与 TLCP

### 14.1 `cc_bridge_provider_status`

输出：引擎版本、Provider 名称、加载状态、SM2/SM3/SM4/ML-KEM/ML-DSA 能力布尔值。不得返回动态库绝对路径、加载凭据或内部地址。

### 14.2 `cc_bridge_provider_reload`

仅管理员/教师经后端授权后调用。重载期间使用独占锁；新调用返回 `CCB_PROVIDER_UNAVAILABLE` 或等待有界超时，不得在正在执行的密码调用中卸载 Provider。

### 14.3 `cc_bridge_tlcp_status`

输出：TLCP 在线状态、协议版本、套件名、握手耗时、签名证书和加密证书的脱敏指纹。

### 14.4 `cc_bridge_tlcp_handshake_trace`

用途：FR-09 教学抓包时序。只返回报文类型、方向、时间和允许展示的头字段；预主密钥、会话密钥、私钥、Cookie/Token 和完整业务载荷必须移除。

## 15. API 到桥接能力映射

| OpenAPI 模块 | 主要桥接能力 |
|---|---|
| `/system/status` | Provider 状态、TLCP 状态 |
| `/auth/*` | SM3 认证哈希、恒定时间比较、HKDF/PBKDF2、SM2 密钥生成、CSR、证书签发 |
| `/me/password` | SM3、HKDF-SM3、SM4-GCM 私钥重加密 |
| `/me/keyring/*` | SM2/ML-KEM 密钥、证书、CRL、口令加密备份 |
| `/drops/*` | 数字信封 seal/open、SM3 审计摘要 |
| `/hole/*` | 盲签名签发/验签、SM3 撤销链 |
| `/votes/*` | 盲签名签发/验签、计票台 SM2 签名/验签 |
| `/seals`、`/verifications` | SM3、SM2/ML-DSA 签名验签、证书链、CRL |
| `/chat/*` | ECDH、ML-KEM、HKDF-SM3、SM4-GCM、SM2 签名验签 |
| `/inspect/*` | 教学专用算法调用、KAT、TLCP 脱敏时序 |
| `/admin/*` | Provider 状态/重载、基准、SM3 审计链；无任意解密能力 |

## 16. 内存、并发与清理

1. 每个调用必须可重入；共享 Provider 状态采用读写锁，重载使用写锁。
2. 私钥解锁缓存由后端受控内存管理，TTL 固定 15 分钟；桥接层不得建立无期限全局私钥缓存。
3. 桥接层所有临时密钥、共享秘密、派生材料和明文缓冲在返回前清零。
4. 调用方在完成持久化加密或发送响应后立即清零敏感输出。
5. Python `ctypes` 必须为每个参数声明准确 `argtypes`/`restype`，长度用 `size_t`，禁止依赖默认整数转换。
6. 任何异常路径都必须释放上下文并清零已写敏感缓冲区；禁止内存泄漏、双重释放和跨运行库释放。

## 17. 日志与透视禁止项

以下内容不得进入日志、HTTP 响应、WebSocket 控制帧、审计详情或密码透视记录：

- 口令、验证码、Refresh Token、Access Token；
- 明文私钥、KEK、SM4 会话密钥、ECDH/ML-KEM 共享秘密；
- 完整业务明文、聊天明文、未加密文件；
- 盲化因子、普通盲签名的身份关联数据；
- 公平盲签名托管份额；
- 完整密码中间值、原始堆栈、指针和内存地址。

允许记录：操作 ID、算法名、输入/输出长度、耗时、结果类别、证书序列号、脱敏指纹前缀和后端请求关联标识。

## 18. 验收与评审清单

- [ ] 每个逻辑接口已由密码引擎负责人映射到真实 openHiTLS 头文件/API 或已确认的项目组合实现。
- [ ] 不存在声称为 openHiTLS 原始符号的 AI 推测名称。
- [ ] SM3、SM4、SM2、证书、盲签名和 PQC 均有 KAT 或官方向量测试。
- [ ] SM4-GCM Tag 篡改、签名篡改、证书吊销、ML-KEM 密文篡改均明确失败且不输出明文。
- [ ] Buffer 容量不足、空输入、超长输入和 Provider 不可用场景可测试。
- [ ] 私钥、KEK、共享秘密和业务明文在正常及异常路径均清零且不进入日志。
- [ ] 后端错误映射与 `openapi.yaml` 的 400、401、403、413、429、500/503 契约一致。
- [ ] 前端工程师确认不要求浏览器手写密码原语。
- [ ] 测试工程师确认正常、边界、权限、篡改、重放和引擎故障场景可自动化验证。
