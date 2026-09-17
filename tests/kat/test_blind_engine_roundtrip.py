"""盲签名引擎层端到端（真密码）—— 走 HitlsCryptoEngine + 真 libcc_bridge.so。

补的是什么：仓库里 `blind_*` 的测试一直只有两种 ——
打 `MockCryptoEngine` 的编排测试，和直接打 C bridge 的 KAT。
**没有任何一条测试驱动 Python 引擎适配层**（`HitlsCryptoEngine`），
也**没有任何一条测试同时覆盖 commitment_store + 引擎**。

而这两层历史上各出过一次"形状对、密码学是空转的"缺陷：

  * `commitment_store.create()` 曾经用
        point_x = secrets.token_bytes(32); point_y = secrets.token_bytes(32)
    拼出一个 65 字节的假点当承诺 R（注释还写着 "In real SM2 this is k * G"）；
  * `hitls.py` 的 `blind_sign` / `blind_verify` 曾经一直
    `raise CryptoBridgeError(UNSUPPORTED)`。

形状断言 `len == 65` 对这两者都成立，所以测试全绿。

本用例把整条链在真密码上跑通（对着现网实现的实际签名写，不是对着设计稿）：

    commitment_store.create(crypto_engine=engine)  →  真 R = [k]G
    引擎 blind_commit()                            →  (secret_k, commitment_point)
    客户端 blind                                   →  R' = R + [α]G + [β]P，c' = (c+β) mod n
    store.consume()                                →  取回带 secret_k 的记录
    引擎 blind_sign(secret_k=…)                    →  s' = (k + c'·d) mod n
    客户端 unblind                                  →  s = (s' + α) mod n
    引擎 blind_verify(signature=R'_x‖s)            →  x([s]G − [c]P) == R'_x

只在 crypto_verify 里跑（需要真 .so）；CI 已设 PYTHONPATH=server、CC_BRIDGE_LIBRARY。

本用例**不改任何共享文件**：现网 wrapper 没绑 `cc_client_credential` /
`cc_client_encode_message`（只有服务端验签用的 `cc_client_verify`），
就在用例里就地声明这两个 argtypes，见 `_bind_client_helpers`。
"""

from __future__ import annotations

import ctypes
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import sys

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WRAPPER_PATH = REPOSITORY_ROOT / "bridge" / "wrapper" / "cc_bridge.py"
SERVER_ROOT = REPOSITORY_ROOT / "server"

CCB_OK = 0
CCB_INVALID_ARGUMENT = -1001

SCALAR = 32
POINT = 65
STATE = 64
C_PRIME = 32
CREDENTIAL = 64
COMMITMENT_ID = 16
BLINDED_MESSAGE = COMMITMENT_ID + C_PRIME  # 48

SN = bytes(range(16))
SERVICE = b"hole_post"
PERIOD = b"2026-09-17"
MESSAGE = SN + SERVICE + PERIOD
OTHER_MESSAGE = SN + SERVICE + b"2026-09-18"
KAT_USER = "u-kat-blind-engine"


@pytest.fixture(scope="session")
def bridge():
    spec = importlib.util.spec_from_file_location("cc_bridge_wrapper", WRAPPER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        lib = module.load()
    except (FileNotFoundError, OSError) as error:  # pragma: no cover - 环境缺失
        pytest.fail(
            "真实 cc_bridge 动态库不可用（本用例不允许退化成 mock）："
            f"先 cmake --build bridge/build 或设置 CC_BRIDGE_LIBRARY。原始错误：{error}"
        )
    assert lib.cc_bridge_init(None) == CCB_OK
    _bind_client_helpers(lib)
    return module, lib


def _bind_client_helpers(lib) -> None:
    """就地声明两个客户端 ABI 的签名。

    现网 `bridge/wrapper/cc_bridge.py` 只绑了服务端验签要用的 `cc_client_verify`；
    `cc_client_credential` 与 `cc_client_encode_message` 目前只有本用例用得到。
    符号本来就在 `libcc_bridge.so` 里（`bridge/CMakeLists.txt` 把 `src/cc_client.c`
    一起链进去了），缺的只是 ctypes 的 argtypes —— 不声明的话 ctypes 会按 `int`
    传指针，必然报错。

    为什么不去改共享的 wrapper：那是别人也在动的文件，为了两个只有测试用到的绑定
    去改它，只会制造冲突。就地声明一次更干净。

    两套 ABI 的输出形参不一样，这里也是最容易写错的地方：
      - `cc_bridge_*`（服务端）：输出是 `cc_bridge_buffer *` → 传 `byref(buf.struct)`；
      - `cc_client_*`（客户端）：输出是调用方给的**定长裸 `uint8_t *`**，没有长度入参、
        也不回写长度 → 只能传 `buf.struct.data`。
    """
    u8 = ctypes.POINTER(ctypes.c_uint8)
    lib.cc_client_credential.argtypes = [u8, u8, u8]
    lib.cc_client_credential.restype = ctypes.c_int
    lib.cc_client_encode_message.argtypes = [
        u8,
        ctypes.c_uint32,
        u8,
        ctypes.c_uint32,
        u8,
        ctypes.c_uint32,
        u8,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    lib.cc_client_encode_message.restype = ctypes.c_int


@pytest.fixture(scope="session")
def engine():
    if str(SERVER_ROOT) not in sys.path:
        sys.path.insert(0, str(SERVER_ROOT))
    from app.crypto.hitls import HitlsCryptoEngine

    try:
        return HitlsCryptoEngine()
    except Exception as error:  # pragma: no cover - 环境缺失
        pytest.fail(f"真实密码引擎不可用（本用例不允许退化成 mock）：{error}")


# ------------------------------------------------------------------ 客户端动作


def _client_blind(module, lib, commitment_point, signer_public_key, message):
    """客户端盲化：只需要公开信息（R、P、M）。"""
    c_prime = module.allocate(C_PRIME)
    state = module.allocate(STATE)
    r_prime = module.allocate(POINT)
    commitment_ro = module.ro(commitment_point)
    public_ro = module.ro(signer_public_key)
    message_ro = module.ro(message)
    result = lib.cc_bridge_sm2_blind_blind(
        commitment_ro.struct.data,
        public_ro.struct.data,
        message_ro.struct.data,
        len(message),
        ctypes.byref(c_prime.struct),
        ctypes.byref(state.struct),
        ctypes.byref(r_prime.struct),
    )
    assert result == CCB_OK, f"客户端盲化失败 ret={result}"
    return c_prime.data, state.data, r_prime.data


def _client_unblind(module, lib, s_prime, state):
    s = module.allocate(SCALAR)
    s_prime_ro = module.ro(s_prime)
    state_ro = module.ro(state)
    result = lib.cc_bridge_sm2_blind_unblind(
        s_prime_ro.struct.data, state_ro.struct.data, ctypes.byref(s.struct)
    )
    assert result == CCB_OK, f"客户端去盲失败 ret={result}"
    return s.data


def _pack_credential(module, lib, r_prime, s):
    """凭证 = R'_x(32) ‖ s(32)，恰好 64 字节（对齐 CredentialProof.signature）。

    ⚠️ 这里是两套 ABI 的交界处，别再写错：
      - 服务端 ABI（cc_bridge_*）的输出是 cc_bridge_buffer*，要传 byref(buf.struct)，
        长度由 C 回写，再读 buf.data；
      - 客户端 ABI（cc_client_*）的输出是**调用方给的定长裸 uint8_t***，
        既没有长度入参也不回写长度（长度由 CC_CLIENT_CRED_LEN 在编译期定死），
        所以只能传 buf.struct.data，读完自己按定长读。
    见 bridge/include/cc_client.h 顶部的设计约束。
    """
    credential = module.allocate(CREDENTIAL)
    r_prime_ro = module.ro(r_prime)
    s_ro = module.ro(s)
    result = lib.cc_client_credential(
        r_prime_ro.struct.data, s_ro.struct.data, credential.struct.data
    )
    assert result == CCB_OK, f"打包凭证失败 ret={result}"
    credential.struct.len = CREDENTIAL  # cc_client_* 不回写 len，这里按定长补上
    assert len(credential.data) == CREDENTIAL
    # 布局断言：C 的打包结果必须正好是 R'_x(32) ‖ s(32)
    assert credential.data == r_prime[1 : SCALAR + 1] + s
    return credential.data


def _verify_client_side(module, lib, credential, message, signer_public_key):
    """客户端模块自己的 x-only 验签（与服务端 blind_verify 同源）。"""
    credential_ro = module.ro(credential)
    message_ro = module.ro(message)
    public_ro = module.ro(signer_public_key)
    return lib.cc_client_verify(
        credential_ro.struct.data,
        message_ro.struct.data,
        len(message),
        public_ro.struct.data,
    )


def _decode_probe(module, lib, candidate_point, signer_public_key):
    """用 blind_blind 的解码路径探测一个点是否合法（不在曲线上会返回 -1001）。"""
    c_prime = module.allocate(C_PRIME)
    state = module.allocate(STATE)
    r_prime = module.allocate(POINT)
    candidate_ro = module.ro(candidate_point)
    public_ro = module.ro(signer_public_key)
    message_ro = module.ro(MESSAGE)
    return lib.cc_bridge_sm2_blind_blind(
        candidate_ro.struct.data,
        public_ro.struct.data,
        message_ro.struct.data,
        len(MESSAGE),
        ctypes.byref(c_prime.struct),
        ctypes.byref(state.struct),
        ctypes.byref(r_prime.struct),
    )


def _keypair(engine):
    keypair = engine.sm2_generate_keypair()
    assert len(keypair.private_key) == SCALAR
    assert len(keypair.public_key) == POINT
    return keypair.private_key, keypair.public_key


# ------------------------------------------------------------------------- 用例


def test_engine_commit_returns_real_curve_point(bridge, engine) -> None:
    """`engine.blind_commit()` 返回的必须是真的 [k]G。

    这条就是"假承诺点"那个漏洞的回归护栏：旧实现返回随机 65 字节，
    形状断言（len == 65）照样过，但它在 SM2 曲线上不成立。
    """
    module, lib = bridge
    _private_key, public_key = _keypair(engine)

    secret_k, commitment_point = engine.blind_commit()
    assert len(secret_k) == SCALAR
    assert len(commitment_point) == POINT
    assert commitment_point[0] == 0x04

    # 能被解码并参与点运算 → 确实在 SM2 曲线上
    assert _decode_probe(module, lib, commitment_point, public_key) == CCB_OK

    # 对照组：随便凑的 65 字节过不了同一个解码
    bogus = b"\x04" + b"\x11" * (POINT - 1)
    assert _decode_probe(module, lib, bogus, public_key) == CCB_INVALID_ARGUMENT


def test_commitment_store_point_is_on_curve_and_k_round_trips(bridge, engine) -> None:
    """再往上一层：`commitment_store.create()` 落到表里的点也必须是真 [k]G，
    而且 `consume()` 必须把同一个 k 交回来（少一个字节都算不出 s'）。

    这条挡的正是当年那个写法：store 自己用 secrets.token_bytes 拼点，
    不经过引擎，于是"形状对、密码学空转"。
    """
    module, lib = bridge
    from app.services.commitment_store import BlindCommitmentStore

    _private_key, public_key = _keypair(engine)
    store = BlindCommitmentStore(default_ttl_seconds=300)
    now = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)

    record = store.create(
        service="hole_post",
        period="2026-09-17",
        user_id=KAT_USER,
        crypto_engine=engine,
        now=now,
    )
    assert len(record.commitment_id) == COMMITMENT_ID * 2  # 16 字节 → 32 hex
    assert len(record.secret_k) == SCALAR
    assert len(record.commitment_point) == POINT
    assert record.commitment_point[0] == 0x04
    assert _decode_probe(module, lib, record.commitment_point, public_key) == CCB_OK

    consumed = store.consume(
        commitment_id=record.commitment_id,
        user_id=KAT_USER,
        service="hole_post",
        period="2026-09-17",
        now=now,
    )
    assert consumed.secret_k == record.secret_k
    assert consumed.commitment_point == record.commitment_point
    assert consumed.consumed is True

    # 一次性：同一个承诺不能消费第二次
    from app.services.commitment_store import BlindCommitmentStoreError

    with pytest.raises(BlindCommitmentStoreError):
        store.consume(
            commitment_id=record.commitment_id,
            user_id=KAT_USER,
            service="hole_post",
            period="2026-09-17",
            now=now,
        )


def test_engine_blind_roundtrip_through_real_crypto(bridge, engine) -> None:
    module, lib = bridge
    keypair = engine.sm2_generate_keypair()

    secret_k, commitment_point = engine.blind_commit()
    commitment_id = b"\x5a" * COMMITMENT_ID  # 真实环境由 commitment_store 生成

    c_prime, state, r_prime = _client_blind(
        module, lib, commitment_point, keypair.public_key, MESSAGE
    )
    assert len(c_prime) == C_PRIME

    # 服务端第二轮入参：commitment_id(16) ‖ c'(32) = 48 字节
    blinded_message = commitment_id + c_prime
    assert len(blinded_message) == BLINDED_MESSAGE

    s_prime = engine.blind_sign(
        blinded_message=blinded_message,
        signer_private_key=keypair.private_key,
        secret_k=secret_k,
    )
    assert len(s_prime) == SCALAR

    s = _client_unblind(module, lib, s_prime, state)
    credential = _pack_credential(module, lib, r_prime, s)
    assert len(credential) == CREDENTIAL

    # 服务端验签（x-only，复用客户端模块的 cc_client_verify）
    assert (
        engine.blind_verify(
            message=MESSAGE,
            signature=credential,
            signer_public_key=keypair.public_key,
        )
        is True
    )

    # 客户端自己算一遍，两边必须一致
    assert _verify_client_side(module, lib, credential, MESSAGE, keypair.public_key) == 1


def test_engine_verify_rejects_tampering(bridge, engine) -> None:
    module, lib = bridge
    keypair = engine.sm2_generate_keypair()
    _other_private, other_public = _keypair(engine)

    secret_k, commitment_point = engine.blind_commit()
    c_prime, state, r_prime = _client_blind(
        module, lib, commitment_point, keypair.public_key, MESSAGE
    )
    s_prime = engine.blind_sign(
        blinded_message=b"\x5a" * COMMITMENT_ID + c_prime,
        signer_private_key=keypair.private_key,
        secret_k=secret_k,
    )
    s = _client_unblind(module, lib, s_prime, state)
    credential = _pack_credential(module, lib, r_prime, s)

    assert (
        engine.blind_verify(
            message=MESSAGE, signature=credential, signer_public_key=keypair.public_key
        )
        is True
    )

    tampered = bytearray(credential)
    tampered[0] ^= 0x01  # 改 R'_x
    assert (
        engine.blind_verify(
            message=MESSAGE, signature=bytes(tampered), signer_public_key=keypair.public_key
        )
        is False
    )

    tampered_s = bytearray(credential)
    tampered_s[SCALAR] ^= 0x01  # 改 s
    assert (
        engine.blind_verify(
            message=MESSAGE, signature=bytes(tampered_s), signer_public_key=keypair.public_key
        )
        is False
    )

    assert (
        engine.blind_verify(
            message=OTHER_MESSAGE, signature=credential, signer_public_key=keypair.public_key
        )
        is False
    )
    assert (
        engine.blind_verify(
            message=MESSAGE, signature=credential, signer_public_key=other_public
        )
        is False
    )


def test_engine_blind_sign_fails_closed_without_secret(bridge, engine) -> None:
    """没有 k 就绝不签名 —— 两轮协议的硬要求，缺 k 算不出 s'。

    而且要挡的是"悄悄退化成单轮签名"：单轮签名签名方能关联，盲性直接没了。
    """
    from app.crypto.errors import BridgeErrorCode, CryptoBridgeError

    module, lib = bridge
    keypair = engine.sm2_generate_keypair()
    _secret_k, commitment_point = engine.blind_commit()
    c_prime, _state, _r_prime = _client_blind(
        module, lib, commitment_point, keypair.public_key, MESSAGE
    )
    blinded_message = b"\x5a" * COMMITMENT_ID + c_prime

    with pytest.raises(CryptoBridgeError) as excinfo:
        engine.blind_sign(
            blinded_message=blinded_message,
            signer_private_key=keypair.private_key,
            secret_k=None,
        )
    assert excinfo.value.code == BridgeErrorCode.INVALID_ARGUMENT

    # 长度不对的 blinded_message（既不是 48 也不是 32）同样必须 fail-closed
    with pytest.raises(CryptoBridgeError) as excinfo2:
        engine.blind_sign(
            blinded_message=b"\x11" * 40,
            signer_private_key=keypair.private_key,
            secret_k=b"\x01" * SCALAR,
        )
    assert excinfo2.value.code == BridgeErrorCode.INVALID_ARGUMENT

    # k 长度不对也一样
    with pytest.raises(CryptoBridgeError) as excinfo3:
        engine.blind_sign(
            blinded_message=blinded_message,
            signer_private_key=keypair.private_key,
            secret_k=b"\x01" * 16,
        )
    assert excinfo3.value.code == BridgeErrorCode.INVALID_ARGUMENT


def test_engine_blind_verify_rejects_wrong_credential_length(bridge, engine) -> None:
    from app.crypto.errors import BridgeErrorCode, CryptoBridgeError

    _private_key, public_key = _keypair(engine)
    with pytest.raises(CryptoBridgeError) as excinfo:
        engine.blind_verify(message=MESSAGE, signature=b"\x00" * 63, signer_public_key=public_key)
    assert excinfo.value.code == BridgeErrorCode.INVALID_ARGUMENT


def test_message_encoding_matches_server_python(bridge) -> None:
    """M = SN || service || period 的编码，Python 侧与客户端模块必须逐字节一致。

    盲签名的 M 是客户端自己决定的（签名方只看得到 c'），所以客户端算 c 用的编码
    必须与消费端验证时用的编码完全相同。两边只要差一个分隔符或大小写，
    验签就会全挂，而且是在浏览器里挂。这类"两边各写一遍"的偏差必须在真库上钉死。
    """
    module, lib = bridge
    from app.schemas.credential import encode_credential_message

    out = module.allocate(len(MESSAGE) + 16)
    out_len = ctypes.c_uint32(0)
    sn_ro = module.ro(SN)
    service_ro = module.ro(SERVICE)
    period_ro = module.ro(PERIOD)
    result = lib.cc_client_encode_message(
        sn_ro.struct.data,
        len(SN),
        service_ro.struct.data,
        len(SERVICE),
        period_ro.struct.data,
        len(PERIOD),
        out.struct.data,
        out.struct.capacity,
        ctypes.byref(out_len),
    )
    assert result == CCB_OK, f"cc_client_encode_message 失败 ret={result}"
    out.struct.len = out_len.value
    encoded = out.data

    assert encoded == MESSAGE
    assert encoded == encode_credential_message(SN.hex(), "hole_post", "2026-09-17")