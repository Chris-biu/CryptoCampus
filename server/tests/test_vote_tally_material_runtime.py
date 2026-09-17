import asyncio
import json
from pathlib import Path
from uuid import uuid4

import pytest
from app.services.vote_tally_provider import (
    FileVoteTallyMaterialProvider,
    VoteTallyMaterialUnavailableError,
)


def _write_material(directory: Path) -> tuple[str, str, bytes, bytes, bytes]:
    system_user_id = str(uuid4())
    certificate_serial = "tally-cert:2026-01"
    certificate = b"DER-TALLY-CERTIFICATE"
    public_key = b"\x04" + (b"p" * 64)
    private_key = b"k" * 32
    (directory / "tally.json").write_text(
        json.dumps(
            {
                "system_user_id": system_user_id,
                "certificate_serial": certificate_serial,
            }
        ),
        encoding="utf-8",
    )
    (directory / "tally.der").write_bytes(certificate)
    (directory / "tally.pub").write_bytes(public_key)
    (directory / "tally.key").write_bytes(private_key)
    return system_user_id, certificate_serial, certificate, public_key, private_key


def test_file_provider_loads_tally_material_without_exposing_private_key(
    tmp_path: Path,
) -> None:
    expected = _write_material(tmp_path)
    provider = FileVoteTallyMaterialProvider(tmp_path)

    with provider.unlocked() as material:
        assert (
            material.system_user_id,
            material.certificate_serial,
            material.certificate_der,
            material.public_key,
            material.private_key,
        ) == expected
        assert expected[-1].hex() not in repr(material)


@pytest.mark.parametrize(
    ("file_name", "replacement"),
    [
        ("tally.key", b"short"),
        ("tally.pub", b"\x03" + (b"p" * 64)),
        ("tally.der", b""),
    ],
)
def test_file_provider_fails_closed_for_invalid_binary_material(
    tmp_path: Path, file_name: str, replacement: bytes
) -> None:
    _write_material(tmp_path)
    (tmp_path / file_name).write_bytes(replacement)
    provider = FileVoteTallyMaterialProvider(tmp_path)

    with (
        pytest.raises(VoteTallyMaterialUnavailableError) as exc_info,
        provider.unlocked(),
    ):
        pass
    assert exc_info.value.code == "engine_unavailable"


def test_file_provider_fails_closed_for_invalid_or_extra_manifest_fields(
    tmp_path: Path,
) -> None:
    _write_material(tmp_path)
    provider = FileVoteTallyMaterialProvider(tmp_path)

    (tmp_path / "tally.json").write_text(
        json.dumps(
            {
                "system_user_id": "not-a-uuid",
                "certificate_serial": "valid-serial",
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(VoteTallyMaterialUnavailableError), provider.unlocked():
        pass

    (tmp_path / "tally.json").write_text(
        json.dumps(
            {
                "system_user_id": str(uuid4()),
                "certificate_serial": "invalid/serial",
                "unexpected": True,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(VoteTallyMaterialUnavailableError), provider.unlocked():
        pass


def test_file_provider_rereads_rotated_material_per_unlock(tmp_path: Path) -> None:
    first = _write_material(tmp_path)
    provider = FileVoteTallyMaterialProvider(tmp_path)
    with provider.unlocked() as material:
        assert material.system_user_id == first[0]

    second = _write_material(tmp_path)
    with provider.unlocked() as material:
        assert material.system_user_id == second[0]
        assert material.system_user_id != first[0]


def test_cli_uses_the_configured_runtime_provider(monkeypatch) -> None:
    from app import cli

    provider = object()
    captured: dict[str, object] = {}

    class FakeSettlementService:
        def __init__(self, **kwargs) -> None:
            captured.update(kwargs)

        def settle_due(self, *, limit: int, now) -> list[object]:
            captured["limit"] = limit
            return []

    monkeypatch.setattr(cli, "get_vote_tally_provider", lambda: provider)
    monkeypatch.setattr(cli, "get_crypto_engine", lambda: object())
    monkeypatch.setattr(cli, "VoteSettlementService", FakeSettlementService)

    assert cli.settle_due_votes(limit=7) == 0
    assert captured["tally_material_provider"] is provider
    assert captured["limit"] == 7


@pytest.mark.parametrize(
    "mode", ["enabled", "disabled", "provider_failure", "scheduler_failure"]
)
def test_application_lifespan_preserves_both_workers_and_runtime_provider(
    monkeypatch, db_session, db_engine, mode: str,
) -> None:
    from app import main
    from app.crypto import dependencies
    from app.db.session import create_session_factory
    from app.services import vote_scheduler, vote_settlement, vote_tally_provider

    provider = object()
    captured: dict[str, object] = {}
    events: list[str] = []

    class FakeExecutor:
        def start(self) -> None:
            events.append("executor_start")

        def stop(self) -> None:
            events.append("executor_stop")

    def resolve_provider():
        events.append("resolve_provider")
        if mode == "provider_failure":
            raise RuntimeError("provider_initialization_failed")
        return provider

    class FakeSettlementService:
        def __init__(self, **kwargs) -> None:
            events.append("settlement_create")
            captured.update(kwargs)

    class FakeScheduler:
        def __init__(self, **kwargs) -> None:
            events.append("scheduler_create")
            captured.update(kwargs)

        def start(self) -> None:
            events.append("scheduler_start")
            if mode == "scheduler_failure":
                raise RuntimeError("scheduler_initialization_failed")

        def stop(self) -> None:
            events.append("scheduler_stop")

    monkeypatch.setenv(
        "CRYPTOCAMPUS_VOTE_SETTLEMENT_SCHEDULER_ENABLED",
        "false" if mode == "disabled" else "true",
    )
    monkeypatch.setattr(main, "engine", db_engine)
    monkeypatch.setattr(main, "SessionLocal", create_session_factory(db_engine))
    monkeypatch.setattr(main, "get_default_executor", lambda: FakeExecutor())
    monkeypatch.setattr(
        main, "recover_interrupted_jobs", lambda session: events.append("recover_jobs")
    )
    monkeypatch.setattr(dependencies, "get_crypto_engine", lambda: object())
    monkeypatch.setattr(
        vote_tally_provider, "get_vote_tally_provider", resolve_provider
    )
    monkeypatch.setattr(vote_settlement, "VoteSettlementService", FakeSettlementService)
    monkeypatch.setattr(vote_scheduler, "VoteSettlementScheduler", FakeScheduler)

    async def run_lifespan() -> None:
        async with main.lifespan(main.app):
            events.append("body")

    if mode.endswith("failure"):
        with pytest.raises(RuntimeError, match="initialization_failed"):
            asyncio.run(run_lifespan())
    else:
        asyncio.run(run_lifespan())

    expected = ["recover_jobs", "executor_start"]
    if mode != "disabled":
        expected.append("resolve_provider")
        if mode != "provider_failure":
            expected.extend(["settlement_create", "scheduler_create", "scheduler_start"])
            assert captured["tally_material_provider"] is provider
    if not mode.endswith("failure"):
        expected.append("body")
    if mode in ("enabled", "scheduler_failure"):
        expected.append("scheduler_stop")
    expected.append("executor_stop")
    assert events == expected
