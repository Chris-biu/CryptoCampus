from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier

from app.db.session import create_session_factory, init_database
from app.services.verification_code_store import SqlAlchemyVerificationCodeStore


class DigestEngine:
    def sm3_digest(self, message: bytes) -> bytes:
        return hashlib.sha256(message).digest()


NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)


def test_code_can_be_consumed_once_across_database_sessions(db_engine) -> None:
    init_database(db_engine)
    session_factory = create_session_factory(db_engine)
    with session_factory() as issuing_session:
        store = SqlAlchemyVerificationCodeStore(issuing_session, DigestEngine())
        store.issue("student@campus.edu", "123456", NOW + timedelta(minutes=10))

    with session_factory() as consuming_session:
        store = SqlAlchemyVerificationCodeStore(consuming_session, DigestEngine())
        assert store.consume("student@campus.edu", "123456", NOW) is True

    with session_factory() as second_session:
        store = SqlAlchemyVerificationCodeStore(second_session, DigestEngine())
        assert store.consume("student@campus.edu", "123456", NOW) is False


def test_wrong_or_expired_code_is_not_consumed(db_session) -> None:
    store = SqlAlchemyVerificationCodeStore(db_session, DigestEngine())
    store.issue("wrong@campus.edu", "123456", NOW + timedelta(minutes=10))
    store.issue("expired@campus.edu", "654321", NOW - timedelta(seconds=1))

    assert store.consume("wrong@campus.edu", "000000", NOW) is False
    assert store.consume("expired@campus.edu", "654321", NOW) is False


def test_failed_older_delivery_does_not_revoke_newer_issue(db_session) -> None:
    store = SqlAlchemyVerificationCodeStore(db_session, DigestEngine())
    older_issue = store.issue(
        "student@campus.edu", "111111", NOW + timedelta(minutes=10)
    )
    store.issue("student@campus.edu", "222222", NOW + timedelta(minutes=10))

    store.revoke("student@campus.edu", older_issue)

    assert store.consume("student@campus.edu", "222222", NOW) is True


def test_concurrent_consumers_have_exactly_one_winner(db_engine) -> None:
    init_database(db_engine)
    session_factory = create_session_factory(db_engine)
    with session_factory() as issuing_session:
        SqlAlchemyVerificationCodeStore(issuing_session, DigestEngine()).issue(
            "race@campus.edu", "123456", NOW + timedelta(minutes=10)
        )
    barrier = Barrier(4)

    def consume_once(_: int) -> bool:
        with session_factory() as session:
            barrier.wait()
            return SqlAlchemyVerificationCodeStore(session, DigestEngine()).consume(
                "race@campus.edu", "123456", NOW
            )

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(consume_once, range(4)))

    assert results.count(True) == 1
    assert results.count(False) == 3


def test_route_wires_runtime_smtp_and_persistent_store_together(
    db_engine, tmp_path, monkeypatch
) -> None:
    from app.api.routes.auth import get_verification_service
    from app.services.smtp_verification import SmtpVerificationCodeSender

    password_file = tmp_path / "smtp_password"
    password_file.write_text("test-smtp-password", encoding="utf-8")
    monkeypatch.setenv("CRYPTOCAMPUS_SMTP_HOST", "smtp.example.edu")
    monkeypatch.setenv("CRYPTOCAMPUS_SMTP_PORT", "587")
    monkeypatch.setenv("CRYPTOCAMPUS_SMTP_USERNAME", "mailer@example.edu")
    monkeypatch.setenv("CRYPTOCAMPUS_SMTP_FROM", "mailer@example.edu")
    monkeypatch.setenv("CRYPTOCAMPUS_SMTP_PASSWORD_FILE", str(password_file))
    sent: list[tuple[str, str]] = []
    monkeypatch.setattr(
        SmtpVerificationCodeSender,
        "send",
        lambda self, email, code: sent.append((email, code)),
    )
    init_database(db_engine)
    session_factory = create_session_factory(db_engine)

    with session_factory() as session:
        service = get_verification_service(session, DigestEngine())
        assert isinstance(service.sender, SmtpVerificationCodeSender)
        assert isinstance(service.store, SqlAlchemyVerificationCodeStore)
        service.issue("student@example.edu", now=NOW)

    assert len(sent) == 1
    email, code = sent[0]
    with session_factory() as session:
        service = get_verification_service(session, DigestEngine())
        assert service.consume(email, code, NOW) is True
    with session_factory() as session:
        service = get_verification_service(session, DigestEngine())
        assert service.consume(email, code, NOW) is False
