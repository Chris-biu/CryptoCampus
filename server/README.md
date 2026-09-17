# CryptoCampus 后端

本目录当前只提供 FastAPI 后端基础工程：统一 `/api/v1` 路由、公共错误响应和系统状态接口。数据库、注册、登录、权限、业务接口和密码算法均不在本 Issue 范围内。

## 安装

建议使用 Python 3.11 及以上版本：

```powershell
cd server
python -m pip install -r requirements.txt
```

## 测试

```powershell
cd server
python -m pytest -v
```

## 启动

```powershell
cd server
python -m uvicorn app.main:app --reload
```

启动后可访问：

- `http://127.0.0.1:8000/api/v1/system/status`
- `http://127.0.0.1:8000/docs`

密码引擎尚未接入时，状态接口固定返回 `api=degraded`、`engine=offline` 与 `tlcp=unknown`。不得把该状态改成虚假的 `online`。

后续业务和密码引擎适配必须通过独立 GitLab Issue 开发；后端不得直接调用 openHiTLS 动态库。
