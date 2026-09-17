# CryptoCampus Compose 与离线交付

本目录提供桌面 Web 演示环境的 Compose 编排、离线镜像包脚本和启停/升级/回滚说明。Server 镜像以多阶段构建固定 openHiTLS 提交并编译仓库当前 `bridge`，运行镜像内置所需动态库与 ctypes wrapper；构建失败不会产生缺少密码引擎的发布镜像。

## 在线构建与启动

```powershell
Copy-Item .env.example .env
docker compose --env-file .env config --quiet
docker compose --env-file .env build
docker compose --env-file .env up -d --wait
Invoke-RestMethod http://127.0.0.1:8080/api/v1/system/status
```

默认仅暴露桌面 Web 入口 `http://127.0.0.1:8080`。FastAPI 不直接暴露到宿主机，由 Web 容器同源反向代理 `/api`。SQLite 数据保存在命名卷 `cryptocampus_server_data` 中。

### 本地答辩演示初始化

仓库提供显式受控的本地演示初始化器。它只允许在非生产环境运行，并使用镜像内真实 openHiTLS bridge 生成 CA、证书和各业务独立密钥；不会启用 Mock。先在本机 `.env` 设置 `CRYPTOCAMPUS_ENV=development`、`CRYPTOCAMPUS_ALLOW_DEMO_BOOTSTRAP=1` 以及四个 `CRYPTOCAMPUS_DEMO_*_PASSWORD`，再执行：

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\scripts\bootstrap-demo.ps1
docker compose --env-file .env up -d --force-recreate --wait
```

脚本输出与所有秘密材料位于 Git 忽略的 `deploy/secrets/`，登录邮件地址写入 `demo-accounts.json`，口令仍只保留在本机 `.env`。生产部署不得开启演示初始化或固定验证码。

真实 bridge 动态库已构建进 Server 镜像的 `/opt/cryptocampus/lib`，Compose 不再用默认空目录遮蔽它。构建固定校验 openHiTLS Commit，且 bridge CTest 必须在镜像构建阶段通过；不得放入 Mock 库冒充真实引擎。证书和秘密材料仍放入 `CRYPTOCAMPUS_SECRETS_DIR` 指定目录并只读挂载，仓库默认忽略其中内容。

部门章与教务章材料分别放入 secrets 目录下的 `seal_materials` 子目录，文件名为 `department.{json,der,key}` 与 `academic.{json,der,key}`。JSON 只包含数据库中对应签章主体的 `user_id`；DER 文件为有效用户证书；KEY 文件为恰好 32 字节的原始 SM2 私钥。两类主体不得复用私钥，未知主体或任一文件无效时失败关闭。

平台 CA 运行时材料由部署人员放入 secrets 目录，容器仅以只读方式加载：

- `platform_ca.der`：DER 编码的平台 CA 证书；
- `platform_ca.key`：恰好 32 字节的原始 SM2 私钥；
- `platform_ca.json`：只允许包含 `system_user_id`、`certificate_serial`、`not_before`、`not_after` 四个字段，其中时间为 Unix 秒。

`system_user_id` 必须对应数据库中 `role=system` 的用户，证书序列号和有效期必须与 DER 证书一致。文件缺失、过大或格式错误时，注册、证书轮换、账户注销、密信及签章操作均失败关闭；不得用示例或 Mock 材料代替。

经典 SM2 密信需要部署一个专用的 active 收件人账号：将其 UUID 写入 `CRYPTOCAMPUS_DROP_RECIPIENT_USER_ID`，并把与该账号数据库公钥配对的 32 字节原始 SM2 私钥写入 secrets 目录的 `drop_recipient_sm2.key`。创建时按数据库公钥封装，提取时同时核对收件人 UUID 与公钥指纹后才读取私钥。账号、指纹、文件长度或密钥配对不一致时失败关闭。PQC 密信仍要求密码引擎提供 ML-KEM。

首次启动前必须在 secrets 目录生成独立 JWT 密钥；文件内容至少包含 32 个随机字节，且不得复用口令、验证码或示例值。下面的 PowerShell 示例生成 48 个随机字节并以 Base64 文本保存：

```powershell
New-Item -ItemType Directory -Force .\deploy\secrets | Out-Null
[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(48)) |
  Set-Content -NoNewline -Encoding ascii .\deploy\secrets\jwt_secret
```

容器只读加载 `/run/secrets/cryptocampus/jwt_secret`。文件缺失、超过 4 KiB 或有效内容短于 32 字节时，JWT 签发与受保护路由会失败关闭。

注册验证码通过 SMTP STARTTLS 发送。部署时在 `.env` 配置 `CRYPTOCAMPUS_SMTP_HOST`、`CRYPTOCAMPUS_SMTP_PORT`、`CRYPTOCAMPUS_SMTP_USERNAME` 和 `CRYPTOCAMPUS_SMTP_FROM`，并将 SMTP 密码单独写入 secrets 目录的 `smtp_password` 文件。密码不得写入 `.env`、镜像或日志。配置缺失、TLS 升级、认证或发送失败时，请求统一返回服务不可用，已生成的验证码同步失效。

匿名树洞签发密钥放入 secrets 目录下的 `hole_signers` 子目录。`hole_post`、`hole_comment`、`hole_like` 各自使用隔离的 `<service>.sk`（32 字节原始 SM2 私钥）和 `<service>.pk`（65 字节、以 `0x04` 开头的 SM2 公钥）。未知服务、文件缺失或长度错误均失败关闭；不得复用用户私钥或测试密钥。真实签发还要求密码引擎提供 SM2 盲签协议能力。

## 生成离线包

在有镜像构建能力的机器上运行：

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\scripts\build-offline.ps1 -Version 0.1.0-dev
```

脚本先校验 Compose、构建镜像，再生成 `artifacts/offline/cryptocampus-<版本>.zip`。包内包括镜像归档、SHA-256 校验、Compose 文件、环境模板和启动脚本。离线包属于构建产物，不提交 Git。

## 离线启停

将 ZIP 复制到目标 Windows 机器并解压，进入包目录：

```powershell
# 启动前可编辑 .env；不要把真实秘密写回仓库。
powershell -ExecutionPolicy Bypass -File .\scripts\start-offline.ps1 -Action start
powershell -ExecutionPolicy Bypass -File .\scripts\start-offline.ps1 -Action status
powershell -ExecutionPolicy Bypass -File .\scripts\start-offline.ps1 -Action stop
```

启动脚本会先校验 `images.tar` 的 SHA-256，再加载镜像并等待两个容器健康。`stop` 只停止并删除容器和网络，不删除持久化数据卷。

## 升级与回滚

1. 升级前记录当前 `VERSION`，并备份 Docker 命名卷 `cryptocampus_server_data`。
2. 解压新版本到独立目录，核对 `.env` 与 secrets 目录后执行新包的 `start`。
3. 若健康检查或桌面端回归失败，在新包执行 `stop`，回到旧版本目录再次执行 `start`。
4. 数据库结构不向后兼容时，不得直接复用已升级的数据卷；须恢复升级前备份。

当前脚本没有自动删除旧镜像、旧包或数据卷，避免误删和保留可回滚证据。

计票台材料放在 `CRYPTOCAMPUS_VOTE_TALLY_MATERIAL_DIR` 指定目录：`tally.json` 只包含 `system_user_id` 与 `certificate_serial`，另有 `tally.der`、65 字节未压缩 SM2 公钥 `tally.pub` 和 32 字节私钥 `tally.key`。系统用户、证书记录和文件必须由部署管理员成套创建；任一文件缺失、格式错误或数据库身份不匹配时，匿名计票与结果签名会以 503 安全失败。真实材料不得提交到仓库，也不得复用平台 CA、用户或签章私钥。

## 验收边界

- 健康检查只证明 Web、API 进程和同源代理可达。
- 镜像状态 `engine=online` 只证明内置 SM2/SM3/SM4-GCM/PKI bridge 已装载；盲签、PQC、TLCP、部署证书材料及完整业务 E2E 仍按各自门禁验收。
- 当前范围只验收桌面 Web，不包含手机端或移动端适配。
