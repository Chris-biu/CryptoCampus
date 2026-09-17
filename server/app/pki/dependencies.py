from sqlalchemy.orm import Session

from app.crypto.engine import CryptoEngine
from app.pki.material import get_runtime_platform_ca_material_provider
from app.pki.service import PlatformCAService


def build_platform_ca_service(
    session: Session, engine: CryptoEngine
) -> PlatformCAService:
    return PlatformCAService(
        session,
        engine,
        get_runtime_platform_ca_material_provider(),
    )
