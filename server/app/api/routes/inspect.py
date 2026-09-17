from fastapi import APIRouter, Depends, Path, Query, Response
from sqlalchemy.orm import Session

from app.crypto.dependencies import get_crypto_engine
from app.crypto.engine import CryptoEngine
from app.db.session import get_db
from app.schemas.inspect import (
    ExperimentRequest,
    ExperimentResult,
    InspectRecord,
    InspectRecordPage,
    TlcpHandshake,
)
from app.security.auth_dependencies import CurrentUser, require_roles
from app.services.experiments import ExperimentService
from app.services.inspect_records import InspectRecordService
from app.services.tlcp_handshake import FileTlcpHandshakeProvider, TlcpHandshakeProvider

router = APIRouter(prefix="/inspect", tags=["Inspect"])


def get_inspect_record_service(session: Session = Depends(get_db)) -> InspectRecordService:
    return InspectRecordService(session)


def get_experiment_service() -> ExperimentService:
    return ExperimentService()


def get_tlcp_provider() -> TlcpHandshakeProvider:
    return FileTlcpHandshakeProvider()


@router.get(
    "/records",
    response_model=InspectRecordPage,
    operation_id="listInspectRecords",
    summary="获取本人密码透视记录",
)
def list_inspect_records(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    service: InspectRecordService = Depends(get_inspect_record_service),
) -> InspectRecordPage:
    return service.list_owned(
        owner_user_id=current_user.user_id,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/records/{record_id}",
    response_model=InspectRecord,
    operation_id="getInspectRecord",
    summary="获取脱敏密码透视记录",
)
def get_inspect_record(
    record_id: str = Path(..., pattern=r"^[0-9a-fA-F-]{36}$"),
    current_user: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    service: InspectRecordService = Depends(get_inspect_record_service),
) -> InspectRecord:
    return service.get_owned(
        owner_user_id=current_user.user_id,
        record_id=record_id,
    )


@router.get(
    "/records/{record_id}/report",
    operation_id="exportInspectReport",
    summary="导出本人操作的脱敏实验报告素材",
    response_class=Response,
)
def export_inspect_report(
    record_id: str = Path(..., pattern=r"^[0-9a-fA-F-]{36}$"),
    current_user: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    service: InspectRecordService = Depends(get_inspect_record_service),
) -> Response:
    report_content = service.export_owned_report(
        owner_user_id=current_user.user_id,
        record_id=record_id,
    )
    return Response(
        content=report_content,
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{record_id}.md"',
        },
    )


@router.post(
    "/experiments",
    response_model=ExperimentResult,
    operation_id="runCryptoExperiment",
    summary="运行课程算法试验台或 KAT 回归",
)
def run_crypto_experiment(
    request: ExperimentRequest,
    current_user: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    engine: CryptoEngine = Depends(get_crypto_engine),
    service: ExperimentService = Depends(get_experiment_service),
) -> ExperimentResult:
    return service.run_experiment(request=request, engine=engine)


@router.get(
    "/tlcp/handshake",
    response_model=TlcpHandshake,
    operation_id="getTlcpHandshakeDemo",
    summary="获取真实 TLCP 抓包的脱敏报文字段和双证书时序",
)
def get_tlcp_handshake_demo(
    current_user: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    provider: TlcpHandshakeProvider = Depends(get_tlcp_provider),
) -> TlcpHandshake:
    return provider.get_latest_redacted()
