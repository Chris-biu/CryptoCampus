# 安全聊天 WebSocket 协议

本文冻结 `/api/v1/chat/ws` 的版本 1 协议。服务端仅认证、授权、保存和转发密文或公开协商材料，不执行 ECDH、KEM 解封装、HKDF、解密、验签或明文重放判断。

## 身份认证与子协议

客户端必须通过 `Sec-WebSocket-Protocol` 按顺序提供两个值：

1. `cryptocampus.chat.v1`；
2. `auth.b64u.<encoded-token>`，其中 `<encoded-token>` 是 JWT UTF-8 字节的无填充 Base64URL 编码。

解码后的 JWT 长度必须在 1 至 8192 字节内并通过现有 `TokenVerifier` 验证。URL 查询字符串中出现 `token`、`access_token` 或 `jwt` 即拒绝连接。握手成功时服务器只返回 `cryptocampus.chat.v1`，绝不回显认证子协议或 Token。无效 Token、非 active 账号、角色不一致或非 student/admin/teacher 以 1008 拒绝；close reason 使用固定短语，不含 Token 或异常文本。

## 密钥和标识所有权

会话 ID 由服务端生成。同一有序成员对和 `pqc_mode` 只存在一个会话。临时私钥和会话密钥由客户端生成并保存；客户端生成公开临时公钥或 KEM 密文握手材料。服务端不得生成或保存临时私钥、共享秘密、会话密钥和消息明文。

## 连接订阅

认证成功后，连接订阅该用户当前参与的全部会话。每个上行帧仍须重新校验成员关系；接收者固定为该会话的另一成员。后创建的会话可在重新连接后订阅。

## 上行帧

单个 UTF-8 JSON 文本帧最多 131072 字节，拒绝二进制帧、未知字段和未知类型。

握手帧为 `{"type":"handshake","session_id":"<uuid>","payload":"<base64>"}`。`payload` 只能是公开临时公钥或 KEM 密文，严格 Base64 解码后最多 8192 字节且不能为空。服务端不持久化握手帧，只向在线对端转发，并覆盖 `sender_id`。

密文帧为 `{"type":"encrypted_message","session_id":"<uuid>","sequence":1,"ciphertext":"<base64>","nonce":"<base64>","tag":"<base64>","signature":"<base64>"}`。上行不得携带 `id`、`sender_id` 或 `created_at`。服务端严格 Base64 解码并限制：密文 1 至 65536 字节、nonce 12 字节、tag 16 字节、签名 1 至 4096 字节。服务端不验证签名。

## 下行帧与顺序

握手下行增加服务器认定的 `sender_id`。密文下行增加服务器生成的 `id`、`sender_id`、UTC `created_at`。密文必须成功提交数据库后才可广播。历史消息稳定按 `created_at ASC, id ASC` 排序。

`sequence` 必须不小于 1，并由数据库唯一约束保证同一 `(session_id, sender_id, sequence)` 仅保存一次。重复序号返回 `DUPLICATE_SEQUENCE` 错误帧并关闭 1008；该约束仅防重复落库和转发风暴，客户端仍负责验签与严格递增的密码学重放判断。

## 错误与关闭

可解析的策略错误先发送固定错误帧，再关闭：畸形、超限或未知帧使用 `INVALID_FRAME`/1008；越权使用 `FORBIDDEN`/1008；重复序号使用 `DUPLICATE_SEQUENCE`/1008。正常关闭使用 1000，服务端内部或数据库故障使用固定 `INTERNAL_ERROR`/1011。错误帧和 close reason 不含请求内容、Token 或异常详情。
