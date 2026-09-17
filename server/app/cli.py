import argparse
import sys
from datetime import datetime, timezone

from app.crypto.dependencies import get_crypto_engine
from app.db.session import engine, sessionmaker
from app.services.vote_settlement import VoteSettlementService
from app.services.vote_tally_provider import get_vote_tally_provider


def settle_due_votes(limit: int = 50) -> int:
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    crypto_engine = get_crypto_engine()
    tally_provider = get_vote_tally_provider()
    service = VoteSettlementService(
        session_factory=session_factory,
        crypto_engine=crypto_engine,
        tally_material_provider=tally_provider,
    )
    now = datetime.now(timezone.utc)
    settled = service.settle_due(limit=limit, now=now)
    print(f"Settled {len(settled)} due votes at {now.isoformat()}")
    return len(settled)


def main() -> None:
    parser = argparse.ArgumentParser(description="CryptoCampus CLI")
    subparsers = parser.add_subparsers(dest="command")

    settle_parser = subparsers.add_parser(
        "settle-due-votes", help="Settle all expired votes"
    )
    settle_parser.add_argument(
        "--limit", type=int, default=50, help="Maximum number of votes to settle"
    )

    args = parser.parse_args()
    if args.command == "settle-due-votes":
        settle_due_votes(limit=args.limit)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
