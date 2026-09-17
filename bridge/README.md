# bridge

openHiTLS FFI 绑定层，由 C（唐尚俊）主责。

bridge/
├─ include/cc_bridge.h   # 团队稳定 C ABI（仅暴露 cc_bridge_*）
├─ src/cc_bridge.c       # 桥接实现（init/version/random/SM3/cte）
├─ src/sm3.c, sm3.h      # SM3 参考实现（bootstrap，待换 openHiTLS）
├─ wrapper/              # Python ctypes 类型安全包装（未开始）
└─ tests/test_cc_bridge.c# CTest/KAT：官方 SM3 向量 + 边界/错误码

## 当前状态（bootstrap）
- include/cc_bridge.h：稳定 C ABI 头 + 错误码（与 docs/api/bridge-contract.md 一致）。
- CMakeLists.txt：构建 libcc_bridge.so，触发 CI bridge_verify。
- src/sm3.c：参考实现的标准 SM3（GM/T 0004-2012），带官方 KAT。
- tests/test_cc_bridge.c：CTest，覆盖 KAT、缓冲区不足、恒定时间比较、错误码。
- cc_bridge_random_bytes / cc_bridge_sm3_digest 待替换为 openHiTLS（见代码 TODO）。
- SM4-GCM、SM2、信封、盲签名、ML-KEM/ML-DSA、证书/CRL：后续按契约映射 openHiTLS。

## 重要约定
- 禁止把 openHiTLS 原生结构体或指针暴露给 Python；输出内存必须用 cc_bridge_buffer_free 释放。
- 所有 cc_bridge_* 必须映射到真实 openHiTLS 头文件/API；禁止用 AI 推测的 HITLS_*/CRYPT_* 名称。
- src/sm3.c 是临时参考实现，接入 openHiTLS 后应删除或替换。
- 密码/权限代码不得由作者本人单独批准；本目录变更至少需引擎、后端、测试三方确认。