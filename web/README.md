# CryptoCampus Web

Vue 3 + TypeScript + Vite 前端工程。UI 组件使用 Element Plus，状态管理使用 Pinia，测试使用 Vitest 与 Vue Test Utils。

## 本地运行

```powershell
cd web
npm ci
npm run dev
```

开发服务器默认监听 `http://localhost:5173`，并将 `/api` 代理到 `http://127.0.0.1:8000`。如需修改本地后端地址，复制 `.env.example` 为 `.env.local` 并修改代理目标；不得在环境文件中保存口令、令牌或密钥。

## 质量检查

```powershell
npm run lint
npm run typecheck
npm run test
npm run test:coverage
npm run test:ci
npm run build
npm run format:check
```

OpenAPI 类型的唯一来源是 `../docs/api/openapi.yaml`：

```powershell
npm run generate:api
npm run check:api
```

## 目录边界

```text
src/
├─ api/          # 唯一允许发起 HTTP 请求的目录、错误映射与生成类型
├─ components/   # 不绑定单一页面的共享 UI
├─ router/       # 路由表与集中权限守卫
├─ stores/       # 会话、PQC 与引擎状态
└─ views/        # 按 auth/home/drop 等领域组织的页面级组件
tests/           # 组件与前端逻辑测试
```

页面和组件禁止直接调用裸 `fetch`/`axios`，前端禁止实现任何密码原语，也不得记录口令、令牌、私钥或会话密钥。

## 前端测试约定

- `npm run test` 是本地非交互检查，`npm run test:watch` 用于开发期监听。
- `npm run test:coverage` 生成 `coverage/` 下的 HTML、LCOV 与 JSON 汇总；`npm run test:ci` 额外生成 JUnit 报告。
- `tests/setup.ts` 默认拒绝所有未声明的 API 请求，测试必须通过 `tests/support/api.ts` 显式提供响应，禁止连接真实后端。
- 契约 Mock 放在 `tests/support/fixtures.ts`，并使用 `src/api/schema.d.ts` 中的 OpenAPI 类型做编译期校验。
- 页面级用例优先使用 `tests/support/mount-app.ts` 统一挂载 Pinia 与内存路由。
- 后续每个前端功能 MR 都必须同步补充对应组件或逻辑测试，并确保日志、快照和夹具不包含真实口令、令牌、私钥或完整凭证。

## 认证边界

- 登录与注册页面只通过 `src/api/auth.ts` 调用 `/auth/*` 契约接口。
- access token 仅保存在 Pinia 内存状态；refresh token 由后端通过 HttpOnly Cookie 管理。
- 应用首次导航时尝试通过 refresh cookie 恢复会话，失败后按游客状态继续。
- 页面逻辑只依据 OpenAPI 中的 HTTP 状态和稳定错误码，不解析后端 `message`。
- `/system/status` 不可用时显示未知/不可用状态，不使用固定版本或伪造在线状态。

## 服务大厅边界

- 服务大厅只通过 `src/api/me.ts` 和 `src/api/system.ts` 读取系统状态、脱敏密钥环摘要与 PQC 偏好。
- PQC 开关的初值来自后端认证会话，更新失败时回滚界面状态，不在浏览器本地持久化。
- 密钥环只展示契约允许的算法、脱敏指纹、证书状态和有效期，不展示私钥或密钥材料。
- 后端接口尚未实装时展示加载、空数据或不可用状态，不使用演示数据替代真实响应。
