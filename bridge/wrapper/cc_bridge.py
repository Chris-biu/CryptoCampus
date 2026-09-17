"""cc_bridge ctypes 绑定（bridge/wrapper，供 server 与 tests/kat 复用）。

职责：仅做 ABI 绑定与缓冲区生命周期管理，不含业务语义；
业务语义与错误码→异常映射见 server/app/crypto/hitls.py。

动态库查找顺序：
  1. 环境变量 CC_BRIDGE_LIBRARY
  2. <仓库根>/bridge/build/libcc_bridge.{so,dylib} / cc_bridge.dll
  3. 系统默认路径
加载失败抛出 FileNotFoundError/OSError，由调用方决定如何兜底（fail-closed）。
"""

from __future__ import annotations

import ctypes
import os
from pathlib import Path

# ---- 错误码（与 bridge/include/cc_bridge.h 严格一致） ----
CCB_OK = 0
CCB_INVALID_ARGUMENT = -1001
CCB_BUFFER_TOO_SMALL = -1002
CCB_AUTH_FAILED = -1003
CCB_INTEGRITY_FAILED = -1004
CCB_CERT_INVALID = -1005
CCB_CERT_REVOKED = -1006
CCB_REPLAYED = -1007
CCB_QUOTA_REJECTED = -1008
CCB_UNSUPPORTED = -1009
CCB_PROVIDER_UNAVAILABLE = -1010
CCB_RANDOM_FAILED = -1011
CCB_MEMORY_FAILED = -1012
CCB_INTERNAL_ERROR = -1099


class BridgeBuffer(ctypes.Structure):
    _fields_ = [
        ("data", ctypes.POINTER(ctypes.c_uint8)),
        ("capacity", ctypes.c_size_t),
        ("len", ctypes.c_size_t),
    ]


class BridgeEnvelope(ctypes.Structure):
    _fields_ = [
        ("ciphertext", BridgeBuffer),
        ("nonce", BridgeBuffer),
        ("tag", BridgeBuffer),
        ("enc_key_sm2", BridgeBuffer),
        ("enc_key_mlkem", BridgeBuffer),
        ("sender_signature", BridgeBuffer),
        ("sender_certificate", BridgeBuffer),
    ]


_U8 = ctypes.POINTER(ctypes.c_uint8)
_CSTR = ctypes.c_char_p


def _library_path() -> Path:
    configured = os.environ.get("CC_BRIDGE_LIBRARY")
    root = Path(__file__).resolve().parents[2]
    candidates = [
        Path(configured) if configured else None,
        root / "bridge" / "build" / "libcc_bridge.so",
        root / "bridge" / "build" / "libcc_bridge.dylib",
        root / "bridge" / "build" / "cc_bridge.dll",
        root / "bridge" / "build" / "Debug" / "cc_bridge.dll",
        Path("/usr/local/lib/libcc_bridge.so"),
        Path("/usr/lib/libcc_bridge.so"),
    ]
    for candidate in candidates:
        if candidate is not None and candidate.is_file():
            return candidate
    raise FileNotFoundError(
        "libcc_bridge 未找到：设置 CC_BRIDGE_LIBRARY 或先 cmake --build bridge/build"
    )


def load() -> ctypes.CDLL:
    lib = ctypes.CDLL(str(_library_path()))

    lib.cc_bridge_init.argtypes = [_CSTR]
    lib.cc_bridge_init.restype = ctypes.c_int
    lib.cc_bridge_version.argtypes = []
    lib.cc_bridge_version.restype = _CSTR
    lib.cc_bridge_random_bytes.argtypes = [_U8, ctypes.c_size_t]
    lib.cc_bridge_random_bytes.restype = ctypes.c_int

    lib.cc_bridge_sm3_digest.argtypes = [_U8, ctypes.c_size_t, ctypes.POINTER(BridgeBuffer)]
    lib.cc_bridge_sm3_digest.restype = ctypes.c_int
    lib.cc_bridge_sm3_hash_password.argtypes = [
        _U8, ctypes.c_size_t, _U8, ctypes.c_size_t, ctypes.POINTER(BridgeBuffer)
    ]
    lib.cc_bridge_sm3_hash_password.restype = ctypes.c_int
    lib.cc_bridge_hkdf_sm3.argtypes = [
        _U8, ctypes.c_size_t, _U8, ctypes.c_size_t, _U8, ctypes.c_size_t,
        ctypes.POINTER(BridgeBuffer),
    ]
    lib.cc_bridge_hkdf_sm3.restype = ctypes.c_int

    lib.cc_bridge_sm4_gcm_encrypt.argtypes = [
        _U8, _U8, ctypes.c_size_t, _U8, ctypes.c_size_t,
        ctypes.POINTER(BridgeBuffer), ctypes.POINTER(BridgeBuffer), ctypes.POINTER(BridgeBuffer),
    ]
    lib.cc_bridge_sm4_gcm_encrypt.restype = ctypes.c_int
    lib.cc_bridge_sm4_gcm_decrypt.argtypes = [
        _U8, _U8, _U8, ctypes.c_size_t, _U8, ctypes.c_size_t, _U8, ctypes.c_size_t,
        ctypes.POINTER(BridgeBuffer),
    ]
    lib.cc_bridge_sm4_gcm_decrypt.restype = ctypes.c_int

    lib.cc_bridge_sm2_generate_keypair.argtypes = [
        ctypes.POINTER(BridgeBuffer), ctypes.POINTER(BridgeBuffer)
    ]
    lib.cc_bridge_sm2_generate_keypair.restype = ctypes.c_int
    lib.cc_bridge_sm2_sign.argtypes = [_U8, _U8, ctypes.POINTER(BridgeBuffer)]
    lib.cc_bridge_sm2_sign.restype = ctypes.c_int
    lib.cc_bridge_sm2_verify.argtypes = [_U8, _U8, _U8, ctypes.c_size_t]
    lib.cc_bridge_sm2_verify.restype = ctypes.c_int
    lib.cc_bridge_sm2_encrypt.argtypes = [_U8, _U8, ctypes.c_size_t, ctypes.POINTER(BridgeBuffer)]
    lib.cc_bridge_sm2_encrypt.restype = ctypes.c_int
    lib.cc_bridge_sm2_decrypt.argtypes = [_U8, _U8, ctypes.c_size_t, ctypes.POINTER(BridgeBuffer)]
    lib.cc_bridge_sm2_decrypt.restype = ctypes.c_int
    lib.cc_bridge_sm2_ecdh.argtypes = [_U8, _U8, ctypes.POINTER(BridgeBuffer)]
    lib.cc_bridge_sm2_ecdh.restype = ctypes.c_int
# SM2 盲签名（两轮 EC-Schnorr 盲签名）：见 bridge/include/cc_bridge.h
    #   commit -> blind -> sign -> unblind -> verify
    # 注意：commit 返回的 k 是一次性秘密，只能留在签名方侧，禁止进入任何响应体；
    #       blind 返回的 state(α‖β) 只能留在客户端侧。
    lib.cc_bridge_sm2_blind_commit.argtypes = [
        ctypes.POINTER(BridgeBuffer), ctypes.POINTER(BridgeBuffer)
    ]
    lib.cc_bridge_sm2_blind_commit.restype = ctypes.c_int
    lib.cc_bridge_sm2_blind_blind.argtypes = [
        _U8, _U8, _U8, ctypes.c_size_t,
        ctypes.POINTER(BridgeBuffer), ctypes.POINTER(BridgeBuffer), ctypes.POINTER(BridgeBuffer),
    ]
    lib.cc_bridge_sm2_blind_blind.restype = ctypes.c_int
    lib.cc_bridge_sm2_blind_sign.argtypes = [_U8, _U8, _U8, ctypes.POINTER(BridgeBuffer)]
    lib.cc_bridge_sm2_blind_sign.restype = ctypes.c_int
    lib.cc_bridge_sm2_blind_unblind.argtypes = [_U8, _U8, ctypes.POINTER(BridgeBuffer)]
    lib.cc_bridge_sm2_blind_unblind.restype = ctypes.c_int
    # 返回约定：1 通过 / 0 无效 / <0 CCB_* 错误码
    lib.cc_bridge_sm2_blind_verify.argtypes = [_U8, _U8, ctypes.c_size_t, _U8, _U8]
    lib.cc_bridge_sm2_blind_verify.restype = ctypes.c_int
    # 凭证 x-only 验签（64 字节凭证: R'_x(32) || s(32)）
    lib.cc_client_verify.argtypes = [_U8, _U8, ctypes.c_uint32, _U8]
    lib.cc_client_verify.restype = ctypes.c_int
    lib.cc_bridge_envelope_seal.argtypes = [
        _U8, ctypes.c_size_t, _U8, ctypes.c_int, _U8,
        _U8, _U8, ctypes.c_size_t, _U8, ctypes.c_size_t,
        ctypes.POINTER(BridgeEnvelope),
    ]
    lib.cc_bridge_envelope_seal.restype = ctypes.c_int
    lib.cc_bridge_envelope_open.argtypes = [
        ctypes.POINTER(BridgeEnvelope), _U8, ctypes.c_int, _U8,
        _U8, ctypes.c_size_t, ctypes.POINTER(BridgeBuffer),
    ]
    lib.cc_bridge_envelope_open.restype = ctypes.c_int

    lib.cc_bridge_csr_create.argtypes = [
        _U8, ctypes.c_size_t, _U8, ctypes.c_size_t, _CSTR, ctypes.POINTER(BridgeBuffer)
    ]
    lib.cc_bridge_csr_create.restype = ctypes.c_int
    lib.cc_bridge_cert_sign.argtypes = [
        _U8, ctypes.c_size_t, _U8, ctypes.c_size_t, _U8, ctypes.c_size_t,
        ctypes.c_int64, ctypes.c_int64, ctypes.c_uint32,
        ctypes.POINTER(BridgeBuffer), ctypes.POINTER(BridgeBuffer),
    ]
    lib.cc_bridge_cert_sign.restype = ctypes.c_int
    lib.cc_bridge_cert_chain_verify.argtypes = [
        _U8, ctypes.c_size_t, _U8, ctypes.c_size_t, _U8, ctypes.c_size_t,
        ctypes.c_int64, ctypes.c_uint32,
    ]
    lib.cc_bridge_cert_chain_verify.restype = ctypes.c_int
    lib.cc_bridge_crl_create.argtypes = [
        _U8, ctypes.c_size_t, _U8, ctypes.c_size_t, _U8, ctypes.c_size_t,
        ctypes.c_int64, ctypes.c_int64, ctypes.POINTER(BridgeBuffer),
    ]
    lib.cc_bridge_crl_create.restype = ctypes.c_int
    lib.cc_bridge_crl_verify.argtypes = [
        _U8, ctypes.c_size_t, _U8, ctypes.c_size_t, ctypes.c_int64,
    ]
    lib.cc_bridge_crl_verify.restype = ctypes.c_int

    lib.cc_bridge_constant_time_equal.argtypes = [_U8, ctypes.c_size_t, _U8, ctypes.c_size_t]
    lib.cc_bridge_constant_time_equal.restype = ctypes.c_int
    lib.cc_bridge_buffer_free.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    lib.cc_bridge_buffer_free.restype = None

    return lib


class OwnedBuffer:
    """可写输出缓冲；持底层 ctypes 数组防止被 GC 提前回收。"""

    def __init__(self, capacity: int) -> None:
        self._array = (ctypes.c_uint8 * max(int(capacity), 1))()
        self.struct = BridgeBuffer(ctypes.cast(self._array, _U8), capacity, 0)

    @property
    def data(self) -> bytes:
        return bytes(self._array[: self.struct.len])

    def data_from(self, updated: BridgeBuffer) -> bytes:
        """Read a buffer embedded by value in an updated parent C structure."""
        expected_pointer = ctypes.cast(self.struct.data, ctypes.c_void_p).value
        updated_pointer = ctypes.cast(updated.data, ctypes.c_void_p).value
        if (
            updated_pointer != expected_pointer
            or updated.capacity != self.struct.capacity
            or updated.len > self.struct.capacity
        ):
            raise ValueError("bridge returned an invalid nested buffer")
        return bytes(self._array[: updated.len])


class RoBuffer:
    """只读输入缓冲；把 bytes 拷贝进 ctypes 数组。空数据 → NULL 指针。"""

    def __init__(self, data: bytes | None) -> None:
        if not data:
            self._array: ctypes.Array | None = None
            self.struct = BridgeBuffer(None, 0, 0)
            return
        self._array = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
        self.struct = BridgeBuffer(ctypes.cast(self._array, _U8), len(data), len(data))


def allocate(capacity: int) -> OwnedBuffer:
    return OwnedBuffer(capacity)


def ro(data: bytes | None) -> RoBuffer:
    return RoBuffer(data)
