import json
from pathlib import Path
from uuid import uuid4

from app.services.seals import FileSealSignerMaterialProvider


def _write_material(directory: Path, profile: str) -> tuple[str, bytes, bytes]:
    user_id = str(uuid4())
    certificate = f"{profile}-certificate".encode()
    private_key = bytes([len(profile)]) * 32
    (directory / f"{profile}.json").write_text(
        json.dumps({"user_id": user_id}), encoding="utf-8"
    )
    (directory / f"{profile}.der").write_bytes(certificate)
    (directory / f"{profile}.key").write_bytes(private_key)
    return user_id, certificate, private_key


def test_file_provider_loads_isolated_department_and_academic_materials(
    tmp_path: Path,
) -> None:
    department = _write_material(tmp_path, "department")
    academic = _write_material(tmp_path, "academic")
    provider = FileSealSignerMaterialProvider(tmp_path)

    department_material = provider.get_seal_material("department")
    academic_material = provider.get_seal_material("academic")

    assert department_material is not None
    assert academic_material is not None
    assert (
        department_material.user_id,
        department_material.certificate_der,
        department_material.private_key,
    ) == department
    assert (
        academic_material.user_id,
        academic_material.certificate_der,
        academic_material.private_key,
    ) == academic
    assert department_material.private_key != academic_material.private_key
    assert department_material.private_key.hex() not in repr(department_material)


def test_file_provider_rejects_unknown_profile_without_path_traversal(
    tmp_path: Path,
) -> None:
    _write_material(tmp_path, "department")
    provider = FileSealSignerMaterialProvider(tmp_path)

    assert provider.get_seal_material("../department") is None
    assert provider.get_seal_material("personal") is None


def test_file_provider_fails_closed_for_incomplete_or_invalid_material(
    tmp_path: Path,
) -> None:
    provider = FileSealSignerMaterialProvider(tmp_path)
    assert provider.get_seal_material("department") is None

    _write_material(tmp_path, "department")
    (tmp_path / "department.key").write_bytes(b"short")
    assert provider.get_seal_material("department") is None

    (tmp_path / "department.key").write_bytes(b"k" * 32)
    (tmp_path / "department.json").write_text(
        json.dumps({"user_id": "not-a-uuid"}), encoding="utf-8"
    )
    assert provider.get_seal_material("department") is None
