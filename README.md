<p align="center">
  <img src="assets/cryptocampus-logo.png" alt="CryptoCampus 标志" width="180">
</p>

# CryptoCampus

CryptoCampus 是面向桌面浏览器的校园密码应用课程项目。项目将身份与证书、密信快传、匿名树洞、匿名投票、文件验真、密码透视及管理治理串成一套可演示的 Web 应用；前端、FastAPI 服务端、密码引擎桥接层和部署脚本均在本仓库中。它是教学与验收项目，不应未经安全评估直接用于生产业务。

> 当前交付以经典国密能力为主。SM2+ML-KEM 混合密信、PQC Provider 重载和抗量子性能开销对比尚未完成真实业务验收，不能视为已上线功能。详见[抗量子能力验收状态](docs/release/PQC-ACCEPTANCE-STATUS-2026-09-17.md)。

## 功能概览

| 模块 | 项目中的能力 | 边界 |
| --- | --- | --- |
| 身份与密钥环 | 校园邮箱注册登录、角色与会话、SM2 身份密钥、证书链与吊销状态 | 私钥明文不通过公开接口返回 |
| 密信快传 | 经典国密数字信封、SM4-GCM 密文、提取码、可选提取口令、阅后即焚 | 混合 PQC 信封未通过验收 |
| 匿名树洞 | 浏览器端盲签凭证、发布、评论、点赞、凭证防重放与治理 | 匿名操作与用户身份分离 |
| 匿名投票 | 范围资格、选票凭证、一人一票、匿名计票和签名结果验证 | 需要独立的计票材料 |
| 文件验真 | PDF/PNG/JPEG 的侧车签章、摘要/签名/证书链/时间戳/吊销五步校验 | 原文件篡改应明确失败 |
| 密码透视与管理 | 脱敏业务事件、经典国密基准、权限管理、审计与治理 | 管理权限不等于读取用户明文的权限 |

安全聊天属于进阶范围；当前项目不宣称提供已验收的端到端加密聊天。更细的演示步骤和逐项结论见[验收与演示指南](docs/deliverables/验收与演示指南.md)。

## 技术组成

- Web：Vue 3、TypeScript、Vite、Element Plus、Pinia、Vue Router；通过 OpenAPI 生成接口类型。
- API：Python、FastAPI、SQLAlchemy、SQLite；统一使用 `/api/v1` 路径。
- 密码层：openHiTLS 与仓库内 C bridge；服务端通过适配层调用，浏览器端匿名凭证使用 WASM。Mock 只用于受控测试/开发，不代表真实密码能力。
- 交付：Docker Compose 双容器（Web 与 API），Web 同源代理 `/api`；SQLite 使用命名卷持久化，秘密材料以只读目录挂载。

## 仓库结构

```text
bridge/          C bridge 与密码能力接口
hitls-bridge/    openHiTLS 相关桥接实现
server/          FastAPI、数据模型、业务服务和后端测试
web/             桌面 Web 应用及前端测试
tests/           集成、安全、KAT、真实密码和浏览器端到端测试
deploy/          Dockerfile、部署/离线交付脚本与说明
docs/api/        OpenAPI 契约
docs/deliverables/ 验收、演示与交付说明
compose.yaml     本地/演示环境容器编排
.gitlab-ci.yml   GitLab CI 流水线定义
```

## 快速运行：Docker Compose

需要 Docker Desktop（含 Compose）和能够获取构建依赖的网络。以下命令在仓库根目录、PowerShell 中运行；第一次构建会编译固定版本的 openHiTLS 与 bridge，耗时取决于机器与网络。

```powershell
Copy-Item .env.example .env
docker compose --env-file .env config --quiet
docker compose --env-file .env up -d --build --wait
docker compose --env-file .env ps
Invoke-RestMethod http://127.0.0.1:8080/api/v1/system/status
```

浏览器入口为 `http://127.0.0.1:8080`；如修改 `.env` 中的 `CRYPTOCAMPUS_HTTP_PORT`，请同步修改访问地址。API 不直接向宿主机开放端口。`/api/v1/system/status` 只证明服务和代理可达，**不等于**注册、盲签、投票、签章或 PQC 全部可用。

初次启动的 `.env.example` 只是配置模板，不含真实 JWT 密钥、平台 CA、SMTP 口令、树洞签发者、计票材料等。缺少某种材料时相应业务会安全失败，而不是自动回退到假数据。完整的生产/演示材料清单及离线交付方式见[部署说明](deploy/README.md)。

### 本地演示数据初始化

仅在**非生产**环境需要演示账号与配套密钥时使用。先在本机 `.env` 中设置 `CRYPTOCAMPUS_ENV=development`、`CRYPTOCAMPUS_ALLOW_DEMO_BOOTSTRAP=1`，并填写 `CRYPTOCAMPUS_DEMO_STUDENT_PASSWORD`、`CRYPTOCAMPUS_DEMO_ADMIN_PASSWORD`、`CRYPTOCAMPUS_DEMO_TEACHER_PASSWORD`、`CRYPTOCAMPUS_DEMO_RECIPIENT_PASSWORD` 四个不同的本地演示口令；然后运行：

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\scripts\bootstrap-demo.ps1
docker compose --env-file .env up -d --force-recreate --wait
```

演示账号邮箱写入本机 `deploy/secrets/demo-accounts.json`；口令仅存放在本机 `.env`，不应发到仓库。初始化器禁止在生产环境执行。停止服务可运行 `docker compose --env-file .env down`；该命令默认保留数据卷，不要随意使用 `down -v`。

## 分开开发前后端

本地开发可分别启动 API 和 Web。需要 Python 3.11+、Node.js 22.12+；纯 Python 启动并不自动提供 Compose 中构建的真实 openHiTLS 动态库和业务密钥，相关接口会按实际能力状态失败关闭。不要将教学 Mock 或固定演示材料用于真实部署和安全验收。

```powershell
cd server
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

另开终端：

```powershell
cd web
npm ci
npm run dev
```

前端开发地址通常为 `http://localhost:5173`，`/api` 默认代理到 `http://127.0.0.1:8000`。后端交互文档位于 `http://127.0.0.1:8000/docs`；接口定义以[OpenAPI 契约](docs/api/openapi.yaml)为准。

## 测试与质量检查

仓库的 GitLab CI 定义在 [`.gitlab-ci.yml`](.gitlab-ci.yml)，包含应用检查、密码测试、构建/交付等作业。公开到 GitHub 不会自动获得等价的 GitHub Actions 流水线；请不要将“仓库已推送”理解成“CI 已通过”。

常用的本地检查：

```powershell
cd web
npm ci
npm run lint
npm run test:ci
npm run check:api
npm run build
```

```powershell
cd server
python -m pip install -r requirements.txt
python -m pytest -v
```

集成、安全、真实密码、KAT 和浏览器端到端测试需要各自的依赖与环境，运行方法见[测试说明](tests/README.md)及相应子目录。是否“通过验收”应以当前提交的新一次测试结果为准，不以 README 中的历史数字代替。

## 安全与能力边界

- `.env`、`deploy/secrets/`、数据库、构建产物和测试报告均不应提交；仓库的 `.gitignore` 已排除常见本机材料。复制或发布前仍应人工检查实际内容。
- 生产部署必须使用独立生成的 JWT 密钥、证书与业务密钥，配置真实 SMTP，并关闭演示开关；不能复用教学口令、Mock 或示例密钥。
- 动态库、签发者、计票台或证书材料缺失时，相应业务应安全失败。引擎在线状态不代表所有算法和业务链路均通过测试。
- PQC 主线缺口包括真实 ML-KEM 混合信封、Provider 重载和同负载开销对比；当前不能把经典模式的成功展示为抗量子成功。见[状态与解除条件](docs/release/PQC-ACCEPTANCE-STATUS-2026-09-17.md)。
- 本交付范围为桌面 Web，未承诺移动端适配；若要用于真实用户与真实数据，需另行完成部署、安全、隐私和合规评估。

## 进一步阅读

- [验收与演示指南](docs/deliverables/验收与演示指南.md)
- [部署与离线交付](deploy/README.md)
- [OpenAPI 接口契约](docs/api/openapi.yaml)
- [测试说明](tests/README.md)
- [抗量子能力验收状态](docs/release/PQC-ACCEPTANCE-STATUS-2026-09-17.md)
- [更新记录](CHANGELOG.md)
