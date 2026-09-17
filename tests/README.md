# tests

跨模块测试与质量门禁，由 E（郭晨阳）统筹、全员共同维护。

```text
tests/
├─ integration/     # server + bridge 集成测试
├─ e2e/             # 浏览器核心业务流程
└─ kat/             # 教师/官方已知答案测试向量
```

AI 生成的自洽测试向量不能替代官方或教师提供的 KAT。

## 安全回归测试

`security/` 放置篡改、重放、越权和敏感产物扫描回归。当前容器完整性测试使用明确标注的认证测试替身，只证明应用在单字节篡改时失败关闭，不作为 SM4-GCM 正确性或官方 KAT 证据。CI 会扫描 JUnit、覆盖率、日志、Playwright Trace 等文本产物和 ZIP 内文本，发现私钥、Bearer/refresh token 或敏感字段值时阻止合并。

## 契约与权限集成测试

`integration/` 会验证 OpenAPI 语法、引用、`operationId`、运行时路由覆盖、统一错误结构和角色负向矩阵。契约中尚未由业务负责人实现的操作会注册为显式 `501 NOT_IMPLEMENTED` 占位；受保护操作仍先执行 401/403 权限校验，不能用 404 或伪造成功掩盖实现缺口。

```powershell
python -m pip install -r tests/requirements.txt
$env:PYTHONPATH = "$PWD/server"
python -m pytest tests/integration -v
```

## Playwright 桌面端 E2E

`e2e/` 在 1440×1000 Chromium 中运行两层门禁。第一层启动确定性的 FastAPI
测试应用，覆盖登录、锁定与路由守卫；第二层直接启动仓库的 `app.main`，不注册
依赖覆盖，确认生产运行时在 bridge 缺失和业务未实现时明确失败关闭。浏览器请求均
经 Vite 代理进入 FastAPI 路由，不使用 Playwright 网络拦截伪造成功响应。

```powershell
cd tests/e2e
npm ci
npx playwright install chromium
npm test
# 只运行无依赖覆盖的生产运行时失败关闭门禁：
npm run test:runtime
```

认证用例关闭 Trace，避免口令进入 Trace 的请求体；失败时仍保存已遮罩口令输入的
截图。公开、无凭据用例保留失败 Trace。当前主线缺少可运行的邮件、CA、令牌签发和
完整密码 bridge，因此 E2E 测试应用通过 FastAPI 依赖覆盖提供可复现服务边界；密信、
树洞、投票和验真链路必须等待真实后端与 bridge 后再启用，不能以网络 Mock 代替。

## CI 接入约定

`.gitlab-ci.yml` 会按以下可执行入口自动启用跨模块门禁：

- `bridge/CMakeLists.txt`：构建 bridge 并执行 CTest；
- `tests/integration/test_*.py`：执行 server + bridge 集成测试；
- `tests/kat/test_*.py`：执行官方或教师 KAT；
- `tests/security/test_*.py`：执行篡改、重放与敏感信息泄漏回归；
- `tests/e2e/package-lock.json`：安装锁定依赖、Chromium 并执行 E2E 的 `npm test`。

入口尚不存在时，对应验证 Job 不进入流水线；`test_surface_audit` 会在产物中明确记录为 `deferred`，不能把“未配置”伪装成测试通过。
