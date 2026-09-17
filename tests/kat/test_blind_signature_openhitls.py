"""SM2 盲签名跨端互通 KAT —— 直接驱动真实 libcc_bridge.so，不做任何 mock。

同时扮演三个角色，与真实部署的分工一一对应：

    签名方（服务端）    commit / sign
    客户端（浏览器侧）  blind / unblind
    任意验签方          verify

这不是「自己验自己」：除了用 C 的 verify，还用两条**互相独立**的路径复核协议，
任何一侧写错都会在这里暴露。

  1. 纯 Python 模运算复核三个关系式
         c' = (c + β) mod n
         s  = (s' + α) mod n
         s' = (k + c'·d) mod n
     其中 c 由 bridge 的 SM3 算出后自己 mod n（不调用任何盲签名代码）。

  2. 用**已验收的 ECDH 原语**复核几何。因为
         R' = R + [α]G + [β]P = [k]G + [α]G + [β·d]G = [k + α + β·d]G
     所以 x(R') 必须等于 ECDH((k + α + β·d) mod n, G) 的 x 坐标。
     ECDH 走 CRYPT_EAL_PkeyComputeShareKey，与盲签名用的
     ECC_PointMulAdd / ECC_PointAddAffine 是不同代码路径。

还有一条用例把「k 必须一次性」变成可执行事实：故意复用同一个 k 对两个不同的 c'
签名，然后把私钥 d 解出来。它存在的意义是证明服务层的一次性约束与 TTL 不是可选项。

凭证布局：credential[64] = R'_x(32) || s(32)。
x 是验签唯一需要的坐标（c = SM3(R'_x || M) mod n 本来就只用 x），所以凭证恰好 64 字节，
与 server/app/schemas/credential.py 里「必须严格 64 字节」的校验一致。
"""

from __future__ import annotations

import ctypes
import importlib.util
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WRAPPER_PATH = REPOSITORY_ROOT / "bridge" / "wrapper" / "cc_bridge.py"

CCB_OK = 0
CCB_INVALID_ARGUMENT = -1001
CCB_BUFFER_TOO_SMALL = -1002

SCALAR = 32
POINT = 65
STATE = 64
DIGEST = 32
CREDENTIAL = 64

# SM2 推荐曲线参数（GM/T 0003）
SM2_ORDER = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
SM2_GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
SM2_GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
SM2_GENERATOR = b"\x04" + SM2_GX.to_bytes(32, "big") + SM2_GY.to_bytes(32, "big")

# 与服务端 app/schemas/credential.py 的 encode_credential_message 同构：M = SN || service || period
SN = bytes(range(16))
SERVICE = b"hole_post"
PERIOD = b"2026-09-17"
MESSAGE = SN + SERVICE + PERIOD
OTHER_MESSAGE = SN + SERVICE + b"2026-09-18"


def _load_wrapper():
    spec = importlib.util.spec_from_file_location("cc_bridge_wrapper", WRAPPER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def bridge():
    module = _load_wrapper()
    try:
        lib = module.load()
    except (FileNotFoundError, OSError) as error:  # pragma: no cover - 环境缺失
        pytest.fail(
            "真实 cc_bridge 动态库不可用（KAT 不允许退化成 mock）："
            f"先 cmake --build bridge/build 或设置 CC_BRIDGE_LIBRARY。原始错误：{error}"
        )
    assert lib.cc_bridge_init(None) == CCB_OK
    return module, lib


# --------------------------------------------------------------------- 角色动作
# 注意：所有 ctypes 缓冲区都必须先绑定到局部变量再取 .struct.data，
# 否则临时对象会被 GC、指针悬空（server/app/crypto/hitls.py 也是同样的写法）。


def _keypair(module, lib) -> tuple[bytes, bytes]:
    private = module.allocate(SCALAR)
    public = module.allocate(POINT)
    assert lib.cc_bridge_sm2_generate_keypair(
        ctypes.byref(private.struct), ctypes.byref(public.struct)
    ) == CCB_OK
    assert private.struct.len == SCALAR and public.struct.len == POINT
    return private.data, public.data


def _signer_commit(module, lib) -> tuple[bytes, bytes]:
    """签名方第 1 步：k ← [1,n-1]，R = [k]G。k 必须留在服务端，绝不能发给客户端。"""
    secret = module.allocate(SCALAR)
    point = module.allocate(POINT)
    assert lib.cc_bridge_sm2_blind_commit(
        ctypes.byref(secret.struct), ctypes.byref(point.struct)
    ) == CCB_OK
    assert secret.struct.len == SCALAR and point.struct.len == POINT
    assert point.data[0] == 0x04
    return secret.data, point.data


def _client_blind(
    module, lib, commitment: bytes, signer_public_key: bytes, message: bytes
) -> tuple[bytes, bytes, bytes]:
    """客户端第 2 步：只需要公开信息（R、P、M），不需要任何私钥。"""
    c_prime = module.allocate(SCALAR)
    state = module.allocate(STATE)
    r_prime = module.allocate(POINT)
    commitment_ro = module.ro(commitment)
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
    assert result == CCB_OK, f"blind 失败 ret={result}"
    assert c_prime.struct.len == SCALAR
    assert state.struct.len == STATE
    assert r_prime.struct.len == POINT
    return c_prime.data, state.data, r_prime.data


def _signer_sign(
    module, lib, secret: bytes, c_prime: bytes, private_key: bytes
) -> bytes:
    """签名方第 3 步：s' = (k + c'·d) mod n。"""
    s_prime = module.allocate(SCALAR)
    secret_ro = module.ro(secret)
    c_prime_ro = module.ro(c_prime)
    private_ro = module.ro(private_key)
    result = lib.cc_bridge_sm2_blind_sign(
        secret_ro.struct.data,
        c_prime_ro.struct.data,
        private_ro.struct.data,
        ctypes.byref(s_prime.struct),
    )
    assert result == CCB_OK, f"sign 失败 ret={result}"
    assert s_prime.struct.len == SCALAR
    return s_prime.data


def _client_unblind(module, lib, s_prime: bytes, state: bytes) -> bytes:
    """客户端第 4 步：s = (s' + α) mod n。"""
    s = module.allocate(SCALAR)
    s_prime_ro = module.ro(s_prime)
    state_ro = module.ro(state)
    result = lib.cc_bridge_sm2_blind_unblind(
        s_prime_ro.struct.data, state_ro.struct.data, ctypes.byref(s.struct)
    )
    assert result == CCB_OK, f"unblind 失败 ret={result}"
    assert s.struct.len == SCALAR
    return s.data


def _verify(module, lib, r_prime, message: bytes, s, public_key) -> int:
    r_ro = module.ro(r_prime)
    message_ro = module.ro(message)
    s_ro = module.ro(s)
    public_ro = module.ro(public_key)
    return lib.cc_bridge_sm2_blind_verify(
        r_ro.struct.data,
        message_ro.struct.data,
        len(message),
        s_ro.struct.data,
        public_ro.struct.data,
    )


def _sm3(module, lib, data: bytes) -> bytes:
    digest = module.allocate(DIGEST)
    data_ro = module.ro(data)
    assert lib.cc_bridge_sm3_digest(
        data_ro.struct.data, len(data), ctypes.byref(digest.struct)
    ) == CCB_OK
    assert digest.struct.len == DIGEST
    return digest.data


def _ecdh_x(module, lib, scalar: int, peer_public_key: bytes) -> bytes:
    shared = module.allocate(DIGEST)
    scalar_ro = module.ro(scalar.to_bytes(32, "big"))
    peer_ro = module.ro(peer_public_key)
    result = lib.cc_bridge_sm2_ecdh(
        scalar_ro.struct.data, peer_ro.struct.data, ctypes.byref(shared.struct)
    )
    assert result == CCB_OK, f"ecdh 失败 ret={result}"
    assert shared.struct.len == DIGEST
    return shared.data


def _challenge(module, lib, r_prime: bytes, message: bytes) -> int:
    """在 Python 里独立重算 c = SM3(R'_x || M) mod n（不碰盲签名代码）。"""
    return int.from_bytes(_sm3(module, lib, r_prime[1:33] + message), "big") % SM2_ORDER


def _session(module, lib, public_key: bytes, message: bytes = MESSAGE, private_key: bytes = b""):
    secret, commitment = _signer_commit(module, lib)
    c_prime, state, r_prime = _client_blind(module, lib, commitment, public_key, message)
    s_prime = _signer_sign(module, lib, secret, c_prime, private_key)
    s = _client_unblind(module, lib, s_prime, state)
    return secret, commitment, c_prime, state, r_prime, s_prime, s


# ------------------------------------------------------------------------- 用例


def test_roundtrip_and_credential_layout(bridge) -> None:
    module, lib = bridge
    private, public = _keypair(module, lib)
    _k, _r, _cp, _st, r_prime, _sp, s = _session(module, lib, public, private_key=private)

    assert _verify(module, lib, r_prime, MESSAGE, s, public) == 1

    # 凭证 = R'_x || s，恰好 64 字节，与服务端 schema 的 64 字节校验一致
    credential = r_prime[1:33] + s
    assert len(credential) == CREDENTIAL
    assert credential[:SCALAR] == r_prime[1:33]
    assert credential[SCALAR:] == s


def test_algebra_matches_independent_python_computation(bridge) -> None:
    module, lib = bridge
    private, public = _keypair(module, lib)
    k_bytes, _r, c_prime, state, r_prime, s_prime, s = _session(
        module, lib, public, private_key=private
    )

    order = SM2_ORDER
    k = int.from_bytes(k_bytes, "big")
    d = int.from_bytes(private, "big")
    alpha = int.from_bytes(state[:SCALAR], "big")
    beta = int.from_bytes(state[SCALAR:], "big")
    challenge = _challenge(module, lib, r_prime, MESSAGE)

    assert int.from_bytes(c_prime, "big") == (challenge + beta) % order
    assert int.from_bytes(s_prime, "big") == (k + int.from_bytes(c_prime, "big") * d) % order
    assert int.from_bytes(s, "big") == (int.from_bytes(s_prime, "big") + alpha) % order


def test_geometry_cross_checked_via_ecdh_primitive(bridge) -> None:
    """R' = [k+α+β·d]G，所以 x(R') 必须等于 ECDH(k+α+β·d, G) 的 x。
    这条走 CRYPT_EAL_PkeyComputeShareKey，与盲签名的点运算不是同一条代码路径。"""
    module, lib = bridge
    private, public = _keypair(module, lib)
    k_bytes, _r, _cp, state, r_prime, _sp, _s = _session(
        module, lib, public, private_key=private
    )

    exponent = (
        int.from_bytes(k_bytes, "big")
        + int.from_bytes(state[:SCALAR], "big")
        + int.from_bytes(state[SCALAR:], "big") * int.from_bytes(private, "big")
    ) % SM2_ORDER
    assert exponent != 0
    assert _ecdh_x(module, lib, exponent, SM2_GENERATOR) == r_prime[1:33]


def test_blindness_two_sessions_differ_and_both_verify(bridge) -> None:
    module, lib = bridge
    private, public = _keypair(module, lib)

    first = _session(module, lib, public, private_key=private)
    second = _session(module, lib, public, private_key=private)

    for session in (first, second):
        assert _verify(module, lib, session[4], MESSAGE, session[6], public) == 1

    # 同一个 M、同一把签名方私钥，签名方视角与产物必须全不同
    assert first[0] != second[0]   # k
    assert first[1] != second[1]   # R
    assert first[2] != second[2]   # c'
    assert first[4] != second[4]   # R'
    assert first[6] != second[6]   # s
    # 盲化与去盲都真的改变了值（不是把 R、s' 原样传出去）
    assert first[4] != first[1]
    assert first[6] != first[5]


def test_reused_commitment_leaks_private_key(bridge) -> None:
    """故意复用同一个 k 对两个不同的 c' 签名：两式相减即可解出 d。
    这条用例证明服务层的一次性 k 约束与 TTL 不是可选项，而是安全前提。"""
    module, lib = bridge
    private, public = _keypair(module, lib)
    secret, commitment = _signer_commit(module, lib)

    cp_a, _st_a, _rp_a = _client_blind(module, lib, commitment, public, MESSAGE)
    cp_b, _st_b, _rp_b = _client_blind(module, lib, commitment, public, OTHER_MESSAGE)
    sp_a = _signer_sign(module, lib, secret, cp_a, private)
    sp_b = _signer_sign(module, lib, secret, cp_b, private)

    order = SM2_ORDER
    numerator = (int.from_bytes(sp_a, "big") - int.from_bytes(sp_b, "big")) % order
    denominator = (int.from_bytes(cp_a, "big") - int.from_bytes(cp_b, "big")) % order
    assert denominator != 0
    recovered = numerator * pow(denominator, -1, order) % order
    assert recovered == int.from_bytes(private, "big")


def test_tamper_matrix_rejects_every_single_change(bridge) -> None:
    module, lib = bridge
    private, public = _keypair(module, lib)
    _other_private, other_public = _keypair(module, lib)
    _k, _r, _cp, _st, r_prime, _sp, s = _session(module, lib, public, private_key=private)

    tampered_s = bytearray(s)
    tampered_s[0] ^= 0x01
    assert _verify(module, lib, r_prime, MESSAGE, bytes(tampered_s), public) == 0

    tampered_r = bytearray(r_prime)
    tampered_r[1] ^= 0x01
    assert _verify(module, lib, bytes(tampered_r), MESSAGE, s, public) == 0

    assert _verify(module, lib, r_prime, OTHER_MESSAGE, s, public) == 0
    assert _verify(module, lib, r_prime, MESSAGE, s, other_public) == 0
    assert _verify(module, lib, r_prime, MESSAGE, b"\x00" * SCALAR, public) == 0
    assert _verify(module, lib, b"\x04" + b"\x11" * (POINT - 1), MESSAGE, s, public) == 0


def test_client_side_sm3_matches_standard_vector(bridge) -> None:
    """客户端要自己算 c = SM3(R'_x || M)，所以先把 SM3 钉死在标准向量上。"""
    module, lib = bridge
    assert _sm3(module, lib, b"abc").hex() == (
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    )
    assert len(_sm3(module, lib, b"")) == DIGEST


def test_boundary_arguments_fail_closed(bridge) -> None:
    module, lib = bridge
    private, public = _keypair(module, lib)
    secret, commitment = _signer_commit(module, lib)
    c_prime, _state, r_prime = _client_blind(module, lib, commitment, public, MESSAGE)

    # 空指针
    assert _verify(module, lib, None, MESSAGE, r_prime, public) == CCB_INVALID_ARGUMENT
    assert _verify(module, lib, r_prime, MESSAGE, None, public) == CCB_INVALID_ARGUMENT

    # 输出缓冲不足：k 和 R 都给 16 字节
    tiny = module.allocate(16)
    assert lib.cc_bridge_sm2_blind_commit(
        ctypes.byref(tiny.struct), ctypes.byref(tiny.struct)
    ) == CCB_BUFFER_TOO_SMALL
    assert tiny.struct.len == 0

    # 私钥全零必须被拒
    zero_key = module.ro(b"\x00" * SCALAR)
    secret_ro = module.ro(secret)
    c_prime_ro = module.ro(c_prime)
    out = module.allocate(SCALAR)
    assert lib.cc_bridge_sm2_blind_sign(
        secret_ro.struct.data,
        c_prime_ro.struct.data,
        zero_key.struct.data,
        ctypes.byref(out.struct),
    ) == CCB_INVALID_ARGUMENT
    assert out.struct.len == 0

    # 注意：C 侧对 s / R' 是定长读取（32 / 65 字节），所以这里不能传长度不对的缓冲区 ——
    # 那会让 C 越界读。非法输入只用「长度正确但内容错」的样本覆盖，
    # 见 test_tamper_matrix_rejects_every_single_change 里的离曲线点用例。