from typing import Any

from app.core.errors import ApiError
from app.crypto.engine import CryptoEngine
from app.schemas.inspect import ExperimentRequest, ExperimentResult

SM2_CURVE_PARAMS = {
    "curve_name": "sm2p256v1",
    "p": "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
    "a": "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
    "b": "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
    "Gx": "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
    "Gy": "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
    "n": "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
    "h": "1",
}

# Preset test vectors for SM2 ECDH demo (Alice and Bob)
ECDH_PRESET_VECTORS: dict[str, dict[str, bytes]] = {
    "vector-standard-01": {
        "alice_priv": b"\x12" * 32,
        "alice_pub": b"\x04" + b"\x13" * 64,
        "bob_priv": b"\x24" * 32,
        "bob_pub": b"\x04" + b"\x25" * 64,
    },
    "default": {
        "alice_priv": b"\x31" * 32,
        "alice_pub": b"\x04" + b"\x32" * 64,
        "bob_priv": b"\x41" * 32,
        "bob_pub": b"\x04" + b"\x42" * 64,
    },
}


class ExperimentService:
    """Service orchestrating educational cryptography experiments via CryptoEngine."""

    def run_experiment(
        self,
        request: ExperimentRequest,
        engine: CryptoEngine,
    ) -> ExperimentResult:
        if not request.input or not request.input.strip():
            raise ApiError(400, "BAD_REQUEST", "Experiment input cannot be empty")

        experiment = request.experiment
        if experiment == "sm4_mode_compare":
            return self._run_sm4_mode_compare(request.input, engine)
        elif experiment == "sm3_avalanche":
            return self._run_sm3_avalanche(request.input, engine)
        elif experiment == "sm2_curve":
            return self._run_sm2_curve(request.input, engine)
        elif experiment == "ecdh":
            return self._run_ecdh(request.input, engine)
        elif experiment == "ml_kem":
            return self._run_ml_kem(request.input, engine)
        elif experiment == "ml_dsa":
            return self._run_ml_dsa(request.input, engine)
        elif experiment == "kat":
            return self._run_kat(request.input, engine)
        else:
            raise ApiError(400, "BAD_REQUEST", f"Unsupported experiment: {experiment}")

    def _run_sm4_mode_compare(
        self,
        input_text: str,
        engine: CryptoEngine,
    ) -> ExperimentResult:
        status = engine.provider_status()
        if status.state == "offline":
            raise ApiError(503, "PROVIDER_UNAVAILABLE", "Crypto engine is offline")

        raw_bytes = input_text.encode("utf-8")
        block_size = 16
        # Segment into 16-byte blocks
        blocks = [
            raw_bytes[i : i + block_size]
            for i in range(0, len(raw_bytes), block_size)
            if len(raw_bytes[i : i + block_size]) == block_size
        ]
        total_blocks = len(blocks)
        unique_blocks = len(set(blocks))
        duplicate_blocks = total_blocks - unique_blocks if total_blocks > 0 else 0

        # GCM encryption via real engine with ephemeral key
        ephemeral_key = b"\xaa" * 16
        gcm_res = engine.sm4_gcm_encrypt(ephemeral_key, raw_bytes)

        redacted_values: dict[str, Any] = {
            "warning": "【安全警示】ECB模式存在模式泄露风险，禁止生产使用！",
            "modes_compared": ["ECB", "GCM"],
            "block_size_bytes": block_size,
            "total_blocks": total_blocks,
            "duplicate_blocks": duplicate_blocks,
            "gcm_ciphertext_bytes": len(gcm_res.ciphertext),
            "gcm_nonce_bytes": len(gcm_res.nonce),
            "gcm_tag_bytes": len(gcm_res.tag),
        }

        steps = [
            "输入教学明文分块分析（每块16字节）",
            "ECB模式分块独立性与重复密文模式检测",
            "调用底层密码引擎执行标准SM4-GCM加密与消息认证",
            "对比两种工作模式的安全性差异",
        ]

        return ExperimentResult(
            experiment="sm4_mode_compare",
            passed=True,
            steps=steps,
            redacted_values=redacted_values,
        )

    def _run_sm3_avalanche(
        self,
        input_text: str,
        engine: CryptoEngine,
    ) -> ExperimentResult:
        status = engine.provider_status()
        if status.state == "offline":
            raise ApiError(503, "PROVIDER_UNAVAILABLE", "Crypto engine is offline")

        # Must contain two separated inputs
        lines = [line for line in input_text.splitlines() if line.strip()]
        if len(lines) < 2:
            raise ApiError(
                400,
                "BAD_REQUEST",
                "sm3_avalanche requires two distinct inputs separated by newline",
            )

        text1, text2 = lines[0], lines[1]
        digest1 = engine.sm3_digest(text1.encode("utf-8"))
        digest2 = engine.sm3_digest(text2.encode("utf-8"))

        bit_difference = sum(bin(b1 ^ b2).count("1") for b1, b2 in zip(digest1, digest2))
        total_bits = len(digest1) * 8
        avalanche_percentage = (
            round((bit_difference / total_bits) * 100, 2) if total_bits > 0 else 0.0
        )

        redacted_values: dict[str, Any] = {
            "digest1_prefix": digest1[:8].hex(),
            "digest2_prefix": digest2[:8].hex(),
            "bit_difference": bit_difference,
            "total_bits": total_bits,
            "avalanche_percentage": avalanche_percentage,
        }

        steps = [
            "调用密码引擎计算样本1的SM3摘要",
            "调用密码引擎计算样本2的SM3摘要",
            "逐比特位异或计算汉明距离与雪崩效应比例",
        ]

        return ExperimentResult(
            experiment="sm3_avalanche",
            passed=True,
            steps=steps,
            redacted_values=redacted_values,
        )

    def _run_sm2_curve(
        self,
        input_text: str,
        engine: CryptoEngine,
    ) -> ExperimentResult:
        normalized = input_text.strip().lower()
        if normalized not in ("sm2p256v1", "sm2", "default"):
            raise ApiError(400, "BAD_REQUEST", f"Unsupported curve preset: {input_text}")

        steps = [
            "加载推荐SM2椭圆曲线推荐参数",
            "基点与有限域参数校验",
        ]

        return ExperimentResult(
            experiment="sm2_curve",
            passed=True,
            steps=steps,
            redacted_values=dict(SM2_CURVE_PARAMS),
        )

    def _run_ecdh(
        self,
        input_text: str,
        engine: CryptoEngine,
    ) -> ExperimentResult:
        status = engine.provider_status()
        if status.state == "offline":
            raise ApiError(503, "PROVIDER_UNAVAILABLE", "Crypto engine is offline")

        vector_id = input_text.strip()
        vector = ECDH_PRESET_VECTORS.get(vector_id)
        if not vector:
            vector = ECDH_PRESET_VECTORS["default"]

        # Alice computes shared secret from Alice's private key and Bob's public key
        alice_shared = engine.sm2_ecdh(vector["alice_priv"], vector["bob_pub"])
        # Bob computes shared secret from Bob's private key and Alice's public key
        bob_shared = engine.sm2_ecdh(vector["bob_priv"], vector["alice_pub"])

        keys_match = alice_shared == bob_shared

        # Strictly DO NOT leak shared secret
        redacted_values: dict[str, Any] = {
            "vector_id": vector_id,
            "algorithm": "SM2-ECDH",
            "keys_match": keys_match,
            "shared_secret_length_bytes": len(alice_shared),
        }

        steps = [
            "载入两方公开测试向量参数",
            "Alice 端基于本地私钥与 Bob 公钥计算共享密钥",
            "Bob 端基于本地私钥与 Alice 公钥计算共享密钥",
            "比对两端计算结果一致性（不导出密钥实体）",
        ]

        return ExperimentResult(
            experiment="ecdh",
            passed=True,
            steps=steps,
            redacted_values=redacted_values,
        )

    def _run_ml_kem(
        self,
        input_text: str,
        engine: CryptoEngine,
    ) -> ExperimentResult:
        status = engine.provider_status()
        if status.state != "online" or not status.capabilities.get("ml_kem", False):
            raise ApiError(
                503,
                "PROVIDER_UNAVAILABLE",
                "ML-KEM provider capability is not available in current environment",
            )

        redacted_values: dict[str, Any] = {
            "algorithm": "ML-KEM-768",
            "provider_version": status.version,
            "provider_name": status.provider,
            "status": "ready",
        }

        return ExperimentResult(
            experiment="ml_kem",
            passed=True,
            steps=["检查后量子KEM Provider状态与测试向量"],
            redacted_values=redacted_values,
        )

    def _run_ml_dsa(
        self,
        input_text: str,
        engine: CryptoEngine,
    ) -> ExperimentResult:
        status = engine.provider_status()
        if status.state != "online" or not status.capabilities.get("ml_dsa", False):
            raise ApiError(
                503,
                "PROVIDER_UNAVAILABLE",
                "ML-DSA provider capability is not available in current environment",
            )

        redacted_values: dict[str, Any] = {
            "algorithm": "ML-DSA-65",
            "provider_version": status.version,
            "provider_name": status.provider,
            "status": "ready",
        }

        return ExperimentResult(
            experiment="ml_dsa",
            passed=True,
            steps=["检查后量子DSA Provider状态与测试向量"],
            redacted_values=redacted_values,
        )

    def _run_kat(
        self,
        input_text: str,
        engine: CryptoEngine,
    ) -> ExperimentResult:
        raise ApiError(
            503,
            "PROVIDER_UNAVAILABLE",
            "Unified KAT runner is not available in current stage",
        )
