from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.router import api_router
from app.api.routes.password import router as password_router
from app.benchmarks.executor import get_default_executor, recover_interrupted_jobs
from app.core.config import get_settings
from app.core.errors import install_exception_handlers
from app.db.session import SessionLocal, engine, init_database


@asynccontextmanager
async def lifespan(application: FastAPI):
    del application
    init_database(engine)
    with SessionLocal() as session:
        recover_interrupted_jobs(session)
    executor = get_default_executor()
    executor.start()
    settings = get_settings()
    scheduler = None
    try:
        if settings.vote_settlement_scheduler_enabled:
            from app.crypto.dependencies import get_crypto_engine
            from app.services.vote_scheduler import VoteSettlementScheduler
            from app.services.vote_settlement import VoteSettlementService
            from app.services.vote_tally_provider import get_vote_tally_provider
            from sqlalchemy.orm import sessionmaker

            session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
            crypto_engine = get_crypto_engine()
            tally_provider = get_vote_tally_provider()
            settlement_service = VoteSettlementService(
                session_factory=session_factory,
                crypto_engine=crypto_engine,
                tally_material_provider=tally_provider,
            )
            scheduler = VoteSettlementScheduler(
                settlement_service=settlement_service,
                interval_seconds=settings.vote_settlement_interval_seconds,
                batch_size=settings.vote_settlement_batch_size,
            )
            scheduler.start()

        yield
    finally:
        if scheduler is not None:
            scheduler.stop()
        executor.stop()


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        lifespan=lifespan,
    )
    install_exception_handlers(application)
    application.include_router(api_router, prefix=settings.api_prefix)
    application.include_router(password_router, prefix=settings.api_prefix)
    return application


app = create_app()
