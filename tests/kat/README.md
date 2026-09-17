# 官方/教师 KAT 接入区

本目录只接收可追溯的官方或教师已知答案测试（KAT）。当前已接入 openHiTLS 官方仓库 SDV 中的 3 组 SM3 向量、标注为 GBT 32918.5-2017 的 SM2 验签向量，以及 RFC 8998 附录 A.1 的 SM4-GCM 向量，并通过 `ctypes` 直接调用由 openHiTLS 构建的真实 `cc_bridge` 动态库。未具备真实 ABI 的算法不得以 Mock 或项目内参考实现替代。

## 接入前置条件

1. 引擎负责人提交对应算法的稳定 `cc_*` ABI、真实 openHiTLS 映射与 CTest，并说明 openHiTLS 版本/提交、Provider 和构建选项。
2. 教师或算法标准发布方提供原始向量包；记录发布方、文档/数据集名称、下载或接收日期及原包 SHA-256。
3. 向量解包到 `tests/kat/vectors/`，创建 `manifest.json`，每个文件记录相对路径、SHA-256、覆盖算法和来源说明。
4. 运行清单校验，再由测试工程师编写数据驱动的 `test_*.py` 调用真实 bridge。测试不得导入 `MockCryptoEngine` 或 `AuthenticatedTestEngine`。

清单中的 JSON SHA-256 统一按 Git 的 LF 规范形式计算；仓库通过 `.gitattributes` 固定 KAT JSON 的行尾，校验器同时兼容既有 Windows 工作树中的 CRLF，不忽略除此之外的任何字节差异。

```powershell
python tests/kat/verify_manifest.py tests/kat/vectors/manifest.json
cmake -S bridge -B bridge/build -DBUILD_TESTING=ON
cmake --build bridge/build --parallel
ctest --test-dir bridge/build --output-on-failure
$env:CC_BRIDGE_LIBRARY = (Resolve-Path bridge/build/cc_bridge.dll).Path # Windows 构建示意；Linux 为 libcc_bridge.so
$env:PYTHONPATH = (Resolve-Path server).Path
python -m pytest tests/kat -v
```

## 最低覆盖矩阵

| 能力 | 正向 KAT | 必须失败的负向项 |
| --- | --- | --- |
| SM3 | 空消息、短消息、分块长消息 | 输入/输出长度错误 |
| HKDF/PBKDF2-SM3 | 多组 salt/info/迭代次数 | 越界长度和迭代次数 |
| SM4-GCM | 明文、AAD、Nonce、Tag、密文全字段比对 | Tag/密文/AAD 单字节篡改，不输出明文 |
| SM2 | 密钥、签名验签、加解密 | 签名/公钥/密文篡改 |
| 证书/CRL | 合法链、有效期、用途 | 过期、吊销、错误用途、错误根 |
| ML-KEM/ML-DSA | 仅实际 Provider 支持时启用官方向量 | 密文/签名篡改和错误长度 |

随机化算法必须使用标准指定的确定性测试入口或官方中间值；“自己生成再自己验证”不是 KAT。测试报告必须包含数据集标识与清单 SHA-256，但不得输出私钥或其他敏感中间材料。

## 明确禁止

- 不得使用项目内参考实现冒充 openHiTLS KAT；测试必须加载 CI 中由 openHiTLS 链接生成的 `cc_bridge` 动态库。
- 不得从 UI 示例、AI 生成值或在线计算器拼出所谓官方答案。
- 不得为了让流水线出现绿灯而添加永远跳过、只断言长度或调用 Mock 的 `test_*.py`。
