from fastapi import APIRouter

from app.api.routes.system import router as system_router
from app.api.routes.auth import router as auth_router
from app.api.routes.me import router as me_router
from app.api.routes.admin import router as admin_router
from app.api.routes.drops import router as drops_router
from app.api.routes.hole import router as hole_router
from app.api.routes.votes import router as votes_router
from app.api.routes.seals import router as seals_router
from app.api.routes.inspect import router as inspect_router
from app.api.routes.chat import router as chat_router
from app.api.routes.not_implemented import router as not_implemented_router

api_router = APIRouter()
api_router.include_router(system_router)
api_router.include_router(auth_router)
api_router.include_router(me_router)
api_router.include_router(admin_router)
api_router.include_router(drops_router)
api_router.include_router(hole_router)
api_router.include_router(votes_router)
api_router.include_router(seals_router)
api_router.include_router(inspect_router)
api_router.include_router(chat_router)
api_router.include_router(not_implemented_router)
