import ctypes

import pytest

from app.crypto.hitls import _bridge
from app.crypto.hitls import _nested_output
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError


def test_owned_buffer_reads_length_from_updated_nested_structure() -> None:
    output = _bridge.allocate(4)
    for index, value in enumerate(b"test"):
        output._array[index] = value
    updated = _bridge.BridgeBuffer(output.struct.data, output.struct.capacity, 4)

    assert output.struct.len == 0
    assert output.data_from(updated) == b"test"


@pytest.mark.parametrize("invalid_length", [5, 2**63])
def test_owned_buffer_rejects_nested_length_beyond_capacity(
    invalid_length: int,
) -> None:
    output = _bridge.allocate(4)
    updated = _bridge.BridgeBuffer(
        output.struct.data,
        output.struct.capacity,
        invalid_length,
    )

    with pytest.raises(ValueError, match="invalid nested buffer"):
        output.data_from(updated)


def test_owned_buffer_rejects_replaced_nested_pointer() -> None:
    output = _bridge.allocate(4)
    replacement = (ctypes.c_uint8 * 4)()
    updated = _bridge.BridgeBuffer(replacement, output.struct.capacity, 4)

    with pytest.raises(ValueError, match="invalid nested buffer"):
        output.data_from(updated)


@pytest.mark.parametrize("capacity", [0, 3, 5])
def test_owned_buffer_rejects_changed_nested_capacity(capacity: int) -> None:
    output = _bridge.allocate(4)
    updated = _bridge.BridgeBuffer(output.struct.data, capacity, 0)

    with pytest.raises(CryptoBridgeError) as raised:
        _nested_output(output, updated)

    assert raised.value.code is BridgeErrorCode.INTERNAL_ERROR
