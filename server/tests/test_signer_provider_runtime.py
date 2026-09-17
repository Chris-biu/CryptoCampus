from pathlib import Path

from app.services.signer_provider import FileServerSignerKeyProvider


def _write_pair(directory: Path, service: str) -> tuple[bytes, bytes]:
    private_key = bytes([len(service)]) * 32
    public_key = b"\x04" + bytes([len(service) + 1]) * 64
    (directory / f"{service}.sk").write_bytes(private_key)
    (directory / f"{service}.pk").write_bytes(public_key)
    return private_key, public_key


def test_file_provider_loads_service_isolated_key_pairs(tmp_path: Path) -> None:
    post_private, post_public = _write_pair(tmp_path, "hole_post")
    comment_private, comment_public = _write_pair(tmp_path, "hole_comment")
    provider = FileServerSignerKeyProvider(tmp_path)

    assert provider.get_signer_private_key("hole_post") == post_private
    assert provider.get_signer_public_key("hole_post") == post_public
    assert provider.get_signer_private_key("hole_comment") == comment_private
    assert provider.get_signer_public_key("hole_comment") == comment_public
    assert post_private != comment_private
    assert post_public != comment_public


def test_file_provider_rejects_unknown_service_without_path_traversal(
    tmp_path: Path,
) -> None:
    (tmp_path / "outside.sk").write_bytes(b"k" * 32)
    provider = FileServerSignerKeyProvider(tmp_path)

    assert provider.get_signer_private_key("../outside") is None
    assert provider.get_signer_public_key("vote_ballot") is None


def test_file_provider_fails_closed_for_missing_or_malformed_keys(
    tmp_path: Path,
) -> None:
    (tmp_path / "hole_post.sk").write_bytes(b"short")
    (tmp_path / "hole_post.pk").write_bytes(b"\x02" + b"p" * 64)
    provider = FileServerSignerKeyProvider(tmp_path)

    assert provider.get_signer_private_key("hole_post") is None
    assert provider.get_signer_public_key("hole_post") is None


def test_file_provider_repr_does_not_contain_key_material(tmp_path: Path) -> None:
    private_key, _ = _write_pair(tmp_path, "hole_like")
    provider = FileServerSignerKeyProvider(tmp_path)

    assert private_key.hex() not in repr(provider)
