# 真实经典密码业务回归

关联：Refs #53。本目录测试业务层与真实 openHiTLS 的组合，不属于官方 KAT；官方已知答案测试继续保留在 `tests/kat`。

## 运行

先按照 `bridge` 构建说明生成动态库并配置 `CC_BRIDGE_LIBRARY`、`LD_LIBRARY_PATH`。从检出根目录运行：

```sh
PYTHONPATH="$PWD/server" python -m pytest tests/kat tests/real_crypto -v
```

该套件不提供 Mock fallback 或“找不到库就跳过”。CI 的 `crypto_verify` 在原有构建和 KAT 后运行它，共用已编译的库，无需新增镜像构建任务。

## 验证范围

- 通过 bridge 的既有自签 API 临时创建 SM2 根 CA，并在测试数据库注册。
- 真实注册、用户证书签发与验证、SM3 口令校验、HKDF-SM3 派生、SM4-GCM 私钥加密与登录解锁。
- 真正签发和验证 JWT；验证学生越权及冻结后的访问拒绝。
- 密信文本/文件加密、带口令解封、阅后即焚；密文、Tag、签名篡改拒绝。
- 真实 CRL 生成、吊销用户拒绝、其他有效用户不受影响。
- HTTP 登录、学生权限检查、密信创建、匿名元数据查询和公开提取。
- 个人签章侧车及五步验真；文件或签名篡改后失败。

## 隔离及证据边界

每个测试使用独立临时 SQLite 数据库、随机密钥、测试账号和测试根证书。私钥不写入测试输出或仓库。收件人适配器只读取该测试账号通过真实登录解锁的内存私钥。

HTTP 用例使用 FastAPI TestClient，注入隔离的数据库和真实业务服务对象；密码实现、JWT 验签和权限判断不替换。它验证路由至业务/引擎的衔接，但不证明 Compose 环境变量装配、部署机 secret 挂载或真实网络链路已验收。

验证码通过真实摘要存储预置测试值，不发送邮件；SMTP 投递与多进程持久化另由对应测试和运行时 MR 验证。部门/教务章生产材料、盲签客户端、PQC、TLCP 和生产证书仍需单独验收。

## 真实桌面浏览器回归

依赖：Python 3.11、Node.js（版本要求见 `web/package.json`）、Docker、已安装的 Google Chrome，以及包含真实 bridge 的本地 server 镜像。安装测试依赖：

```sh
python -m pip install -r tests/e2e/requirements-real-crypto.txt
npm --prefix web ci
```

从仓库根目录运行（替换镜像名与产物目录）：

```sh
python tests/e2e/run_real_crypto.py --image YOUR_LOCAL_SERVER_IMAGE --output YOUR_ARTIFACT_DIR
```

镜像须包含 `server/requirements.txt` 中的运行依赖，并配置可用的 `CC_BRIDGE_LIBRARY` 和动态库搜索路径。库须由本次待验收的 bridge 源码构建，不能用旧镜像的历史通过记录代替。脚本以只读方式挂载当前源码，并强制工作目录为 `/src`，避免 Python 优先导入镜像中的旧版应用。

脚本创建随机端口、临时数据库、临时 CA、随机测试登录口令和两个独立桌面浏览器上下文；结束后只停止自己启动的 Vite 进程和临时容器，不操作现有部署容器。测试应用必须显式启用 `CC_RUN_REAL_E2E=1`，严禁作为生产入口。此变量及临时登录口令由 runner 管理，不应写入生产 `.env`。

5 个桌面检查点：真实登录；创建并公开提取阅后即焚密信（含已消费状态、禁止再次提交和刷新不返回正文）；个人签章与下载 Sidecar 后五步验真；篡改文件拒绝；登出与浏览器存储无残留。浏览器不拦截或伪造网络响应，也不替换密码运算。产物为 `junit.xml` 和桌面截图，所有内容均为一次性测试材料。

该浏览器回归验证真实服务组合，但隔离数据库、CA 材料、收件人解锁提供器由测试夹具注入，不证明生产 secret 挂载、SMTP、TLCP 或完整 Compose 装配成功。普通 MR 仍保留原有受控 E2E；这套需要本地 Docker/Chrome 的回归不静默添加到每次快速流水线中，不能把本地结果写成 CI 已执行结果。

当前分支基于数字信封修复 !99。请先合入 !99，再将本 MR 的目标分支改为 `main` 并重新核对差异与流水线。禁止把含其他开放 MR 的本地集成树整体推入此分支。
