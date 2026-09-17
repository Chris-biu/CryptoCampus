from fastapi import APIRouter, Depends

from app.crypto.dependencies import get_crypto_engine
from app.crypto.engine import CryptoEngine
from app.schemas.system import SystemStatus
from app.services.system_status import CryptoEngineSystemStatusProvider

router = APIRouter(prefix="/system", tags=["System"])


@router.get("/status", response_model=SystemStatus)
async def get_system_status(
    engine: CryptoEngine = Depends(get_crypto_engine),
) -> SystemStatus:
    return await CryptoEngineSystemStatusProvider(engine).get_status()
