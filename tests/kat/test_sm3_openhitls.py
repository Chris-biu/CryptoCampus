from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path

import pytest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
VECTOR_PATH = Path(__file__).with_name("vectors") / "openhitls-sm3.json"
CCB_OK = 0
CCB_INVALID_ARGUMENT = -1001
CCB_BUFFER_TOO_SMALL = -1002


class BridgeBuffer(ctypes.Structure):
    _fields_ = [
        ("data", ctypes.POINTER(ctypes.c_uint8)),
        ("capacity", ctypes.c_size_t),
        ("len", ctypes.c_size_t),
    ]


def _library_path() -> Path:
    configured = os.environ.get("CC_BRIDGE_LIBRARY")
    candidates = [
        Path(configured) if configured else None,
        REPOSITORY_ROOT / "bridge" / "build" / "libcc_bridge.so",
        REPOSITORY_ROOT / "bridge" / "build" / "libcc_bridge.dylib",
        REPOSITORY_ROOT / "bridge" / "build" / "cc_bridge.dll",
        REPOSITORY_ROOT / "bridge" / "build" / "Debug" / "cc_bridge.dll",
    ]
    for candidate in candidates:
        if candidate is not None and candidate.is_file():
            return candidate
    pytest.fail(
        "real cc_bridge library is unavailable; build bridge against openHiTLS or set "
        "CC_BRIDGE_LIBRARY (KAT must not fall back to a mock)"
    )


@pytest.fixture(scope="session")
def bridge() -> ctypes.CDLL:
    library = ctypes.CDLL(str(_library_path()))
    library.cc_bridge_init.argtypes = [ctypes.c_char_p]
    library.cc_bridge_init.restype = ctypes.c_int
    library.cc_bridge_version.argtypes = []
    library.cc_bridge_version.restype = ctypes.c_char_p
    library.cc_bridge_sm3_digest.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(BridgeBuffer),
    ]
    library.cc_bridge_sm3_digest.restype = ctypes.c_int
    assert library.cc_bridge_init(None) == CCB_OK
    version = library.cc_bridge_version()
    assert version and version.decode("ascii").startswith("cryptocampus-bridge-")
    return library


def _vectors() -> list[dict[str, str]]:
    payload = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    assert payload["algorithm"] == "SM3"
    return payload["cases"]


@pytest.mark.parametrize("vector", _vectors(), ids=lambda vector: vector["id"])
def test_official_openhitls_sm3_vectors(bridge: ctypes.CDLL, vector: dict[str, str]) -> None:
    message = bytes.fromhex(vector["message_hex"])
    message_array = (ctypes.c_uint8 * len(message)).from_buffer_copy(message) if message else None
    digest_array = (ctypes.c_uint8 * 32)()
    output = BridgeBuffer(digest_array, len(digest_array), 0)

    result = bridge.cc_bridge_sm3_digest(message_array, len(message), ctypes.byref(output))

    assert result == CCB_OK
    assert output.len == 32
    assert bytes(digest_array) == bytes.fromhex(vector["digest_hex"])


def test_sm3_rejects_null_input_with_nonzero_length(bridge: ctypes.CDLL) -> None:
    digest_array = (ctypes.c_uint8 * 32)()
    output = BridgeBuffer(digest_array, len(digest_array), 0)
    assert bridge.cc_bridge_sm3_digest(None, 1, ctypes.byref(output)) == CCB_INVALID_ARGUMENT
    assert output.len == 0


def test_sm3_rejects_small_output_without_writing(bridge: ctypes.CDLL) -> None:
    message = (ctypes.c_uint8 * 3).from_buffer_copy(b"abc")
    sentinel = bytes([0xA5] * 16)
    digest_array = (ctypes.c_uint8 * 16).from_buffer_copy(sentinel)
    output = BridgeBuffer(digest_array, len(digest_array), 0)

    assert bridge.cc_bridge_sm3_digest(message, 3, ctypes.byref(output)) == CCB_BUFFER_TOO_SMALL
    assert output.len == 0
    assert bytes(digest_array) == sentinel
