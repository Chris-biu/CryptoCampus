from __future__ import annotations

import json
from typing import Any
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import ApiError
from app.models.inspect import InspectRecordEntity
from app.schemas.inspect import InspectRecord, InspectRecordPage, InspectStep


def escape_markdown(text: Any) -> str:
    """Escapes Markdown and HTML special characters and normalizes control characters per Section 8.9."""
    if text is None:
        return "none"
    s = str(text)
    # Remove/replace newlines and carriage returns to prevent line/block breakout
    s = s.replace("\r", " ").replace("\n", " ")
    # HTML escape
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # Markdown escape specified in section 8.9: \, backtick, [, ]
    s = s.replace("\\", "\\\\")
    s = s.replace("`", "\\`")
    s = s.replace("[", "\\[").replace("]", "\\]")
    return s.strip()


def generate_markdown_report(record: InspectRecord) -> str:
    """Pure function to deterministically generate markdown report for an inspect record."""
    result_map = {
        "passed": "通过",
        "failed": "失败",
        "skipped": "跳过",
    }

    created_at_str = (
        record.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        if hasattr(record.created_at, "strftime")
        else str(record.created_at)
    )

    lines = [
        "# CryptoCampus 密码透视实验记录",
        "",
        f"- 记录编号：{escape_markdown(record.id)}",
        f"- 操作类型：{escape_markdown(record.operation)}",
        f"- 创建时间：{created_at_str}",
        "- 数据说明：所有值均已脱敏，不包含业务明文或密钥。",
        "",
        "## 密码流程",
        "",
    ]

    for step in sorted(record.steps, key=lambda s: s.order):
        step_result = result_map.get(step.result, escape_markdown(step.result))
        lines.append(f"### 第 {step.order} 步：{escape_markdown(step.name)}")
        lines.append(f"- 算法：{escape_markdown(step.algorithm)}")
        lines.append(f"- 结果：{step_result}")

        if step.redacted_values:
            redacted_parts = []
            for k in sorted(step.redacted_values.keys()):
                v = step.redacted_values[k]
                redacted_parts.append(f"{escape_markdown(k)} = {escape_markdown(v)}")
            lines.append(f"- 脱敏数据：{', '.join(redacted_parts)}")
        else:
            lines.append("- 脱敏数据：无")
        lines.append("")

    lines.extend(
        [
            "## 安全边界",
            "- 本报告不包含口令、私钥、KEK、会话密钥、业务明文或匿名身份关联。",
            "",
        ]
    )

    return "\n".join(lines)


class InspectRecordService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def list_owned(
        self,
        *,
        owner_user_id: str,
        page: int = 1,
        page_size: int = 20,
    ) -> InspectRecordPage:
        page = max(1, page)
        page_size = min(max(1, page_size), 100)

        # Count total owned records
        count_stmt = (
            select(func.count())
            .select_from(InspectRecordEntity)
            .where(InspectRecordEntity.owner_user_id == owner_user_id)
        )
        total = self.session.scalar(count_stmt) or 0

        # Query records with pagination and stable ordering
        stmt = (
            select(InspectRecordEntity)
            .where(InspectRecordEntity.owner_user_id == owner_user_id)
            .order_by(InspectRecordEntity.created_at.desc(), InspectRecordEntity.id.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        entities = self.session.scalars(stmt).all()

        items = [
            InspectRecord(
                id=e.id,
                operation=e.operation,
                owner="self",
                created_at=e.created_at,
                steps=[
                    InspectStep(
                        order=s.order,
                        name=s.name,
                        algorithm=s.algorithm,
                        result=s.result,  # type: ignore
                        redacted_values=json.loads(s.redacted_values_json),
                    )
                    for s in sorted(e.steps, key=lambda x: x.order)
                ],
            )
            for e in entities
        ]

        return InspectRecordPage(
            items=items,
            page=page,
            page_size=page_size,
            total=total,
        )

    def get_owned(self, *, owner_user_id: str, record_id: str) -> InspectRecord:
        entity = self.session.get(InspectRecordEntity, record_id)
        if entity is None:
            raise ApiError(404, "NOT_FOUND", "透视记录不存在")
        if entity.owner_user_id != owner_user_id:
            raise ApiError(403, "FORBIDDEN", "无权访问此透视记录")

        return InspectRecord(
            id=entity.id,
            operation=entity.operation,
            owner="self",
            created_at=entity.created_at,
            steps=[
                InspectStep(
                    order=s.order,
                    name=s.name,
                    algorithm=s.algorithm,
                    result=s.result,  # type: ignore
                    redacted_values=json.loads(s.redacted_values_json),
                )
                for s in sorted(entity.steps, key=lambda x: x.order)
            ],
        )

    def export_owned_report(self, *, owner_user_id: str, record_id: str) -> str:
        record = self.get_owned(owner_user_id=owner_user_id, record_id=record_id)
        return generate_markdown_report(record)
