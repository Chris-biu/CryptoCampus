# 抗量子能力验收状态（2026-09-17）

## 课程范围

《01-课程总体设计》将 openHiTLS Provider（含 PQC）、SM2+ML-KEM 混合密信、管理台 Provider 重载和抗量子性能开销对比列入主线；《02-Web应用UI设计规范》也把这些列为 P2、P3、P10 的要求。文件验真的 ML-DSA 抗量子章、PDF 附加签章页、安全聊天被明确标为选做或进阶。不能把整个 PQC 范围一概归为选做。

## 当前真实运行结果

| 检查点 | 结果 | 证据 |
| --- | --- | --- |
| 经典国密 SM3/SM4/SM2 与盲签 | 可用 | `/api/v1/system/status` 的能力状态、真实业务回归 |
| openHiTLS 底层 ML-KEM/ML-DSA 源码/符号 | 存在 | 固定源码 `a6b28e09f186dd0402b1236d8b4455842694fce4` 与本机 `libhitls_crypto.so` |
| PQC 业务 bridge 与 Provider 重载 ABI | 未接入 | `server/app/crypto/hitls.py` 返回 `pqc=false`；`reload_pqc_provider()` 返回 `UNSUPPORTED`；`bridge/src/cc_bridge.c` 的 PQC 信封返回 `CCB_UNSUPPORTED` |
| SM2+ML-KEM 混合密信与抗量子开销对比 | 未通过 | `hybrid_envelope` 能力未开放；不能构造真实配对样本，基准结果中 `pqc_overhead_percent=null` |
| ML-DSA 文件章 | 未实现的选做增强 | `server/app/services/seals.py` 对 `pqc_mode=true` 返回 503，未伪装成 SM2 成功 |

现有经典国密基准显示“无对照样本”是准确的：均值/P99 来自真实执行，但没有运行混合信封，无法计算百分比。不得填入教学示意值或把开关打开后仍执行经典模式称为抗量子验收。

## 解除条件

1. 通过 openHiTLS Provider 的真实 ML-KEM-768 密钥生成、封装、解封装及负向 KAT；不要在 Python/TypeScript 重写密码原语。
2. 桥接层提供受测 ABI，服务端注册/密钥环、密信创建与提取接入 SM2+ML-KEM 混合信封；错误与材料缺失时失败关闭。
3. 仅在真实混合信封可加解密且 provider 状态可检测时设置 `pqc`/`hybrid_envelope` 为可用，并开放基准的“包含抗量子对比”。
4. 使用有效的临时 ML-KEM 密钥对做同负载经典/混合配对压测，验证解封后的明文一致、篡改失败、均值/P99 与开销计算正确。
5. 在 Linux CI、Compose 部署及桌面浏览器完成正负向验收后，才可将 FR-03/P10 的 PQC 验收勾选为完成。

这是一项尚未完成的课程主线缺口，不是前端显示故障，也不能靠重新加载页面解决。
