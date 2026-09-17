from __future__ import annotations

import json
from typing import Protocol
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models.inspect import InspectRecordEntity, InspectStepEntity
from app.schemas.inspect import (
    InspectEvent,
    InspectOwner,
    InspectRecordDTO,
    InspectStep,
    validate_and_sanitize_step,
)


class InspectionRecorder(Protocol):
    def record(
        self,
        *,
        event: InspectEvent,
        session: Session,
    ) -> InspectRecordDTO: ...


class NoopInspectionRecorder:
    def record(
        self,
        *,
        event: InspectEvent,
        session: Session,
    ) -> InspectRecordDTO:
        record_id = str(uuid4())
        owner: InspectOwner = "self" if event.owner_user_id else "system"
        owner_user_id = str(event.owner_user_id) if event.owner_user_id else None

        steps: list[InspectStep] = []
        overall_status = "passed"

        for s in sorted(event.steps, key=lambda x: x.order):
            if s.result == "failed":
                overall_status = "failed"
            sanitized = validate_and_sanitize_step(event.operation, s.redacted_values)
            steps.append(
                InspectStep(
                    order=s.order,
                    name=s.name,
                    algorithm=s.algorithm,
                    result=s.result,
                    redacted_values=sanitized,
                )
            )

        return InspectRecordDTO(
            id=record_id,
            owner_user_id=owner_user_id,
            owner=owner,
            operation=event.operation,
            status=overall_status,  # type: ignore
            schema_version=1,
            created_at=event.occurred_at,
            steps=steps,
        )


class DatabaseInspectionRecorder:
    def record(
        self,
        *,
        event: InspectEvent,
        session: Session,
    ) -> InspectRecordDTO:
        record_id = str(uuid4())
        owner: InspectOwner = "self" if event.owner_user_id else "system"
        owner_user_id = str(event.owner_user_id) if event.owner_user_id else None

        # Check unique step orders
        seen_orders: set[int] = set()
        for step in event.steps:
            if step.order in seen_orders:
                raise ValueError(f"Duplicate step order: {step.order}")
            seen_orders.add(step.order)

        overall_status = "passed"
        step_entities: list[InspectStepEntity] = []
        dto_steps: list[InspectStep] = []

        for step in sorted(event.steps, key=lambda x: x.order):
            if step.result == "failed":
                overall_status = "failed"

            sanitized_values = validate_and_sanitize_step(event.operation, step.redacted_values)
            canonical_json = json.dumps(sanitized_values, sort_keys=True, separators=(",", ":"))

            step_entity = InspectStepEntity(
                id=str(uuid4()),
                record_id=record_id,
                order=step.order,
                name=step.name,
                algorithm=step.algorithm,
                result=step.result,
                redacted_values_json=canonical_json,
            )
            step_entities.append(step_entity)

            dto_steps.append(
                InspectStep(
                    order=step.order,
                    name=step.name,
                    algorithm=step.algorithm,
                    result=step.result,
                    redacted_values=sanitized_values,
                )
            )

        record_entity = InspectRecordEntity(
            id=record_id,
            owner_user_id=owner_user_id,
            owner=owner,
            operation=event.operation,
            status=overall_status,
            schema_version=1,
            created_at=event.occurred_at,
            steps=step_entities,
        )

        session.add(record_entity)
        session.flush()

        return InspectRecordDTO(
            id=record_id,
            owner_user_id=owner_user_id,
            owner=owner,
            operation=event.operation,
            status=overall_status,  # type: ignore
            schema_version=1,
            created_at=event.occurred_at,
            steps=dto_steps,
        )


_DEFAULT_RECORDER: InspectionRecorder = DatabaseInspectionRecorder()


def get_inspection_recorder() -> InspectionRecorder:
    return _DEFAULT_RECORDER
