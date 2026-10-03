"""Data-access layer (SQLAlchemy ORM, parameterised queries only)."""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy import (Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text,
                        create_engine, delete, func, select, text)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from .schemas import EventType, LLMCall, SecurityEvent, utcnow


class Base(DeclarativeBase):
    pass


class RequestRow(Base):
    __tablename__ = "requests"
    request_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    status: Mapped[str] = mapped_column(String(32), default="in_progress", index=True)
    decision: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    model: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    provider: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    latency_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0)
    pii_count: Mapped[int] = mapped_column(Integer, default=0)
    placeholder_count: Mapped[int] = mapped_column(Integer, default=0)
    injection_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    error_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)


class EventRow(Base):
    __tablename__ = "security_events"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(64), unique=True)
    request_id: Mapped[str] = mapped_column(String(64), ForeignKey("requests.request_id"), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    event_type: Mapped[str] = mapped_column(String(48), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    source: Mapped[str] = mapped_column(String(64))
    category: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    decision: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    message: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")


class LLMCallRow(Base):
    __tablename__ = "llm_calls"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    request_id: Mapped[str] = mapped_column(String(64), ForeignKey("requests.request_id"), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    provider: Mapped[str] = mapped_column(String(64), index=True)
    model: Mapped[str] = mapped_column(String(128), index=True)
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(32), default="success")
    estimated_cost: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    error_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)


Index("ix_events_type_ts", EventRow.event_type, EventRow.timestamp)


@dataclass
class QueryFilters:
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    event_type: Optional[str] = None
    severity: Optional[str] = None
    decision: Optional[str] = None
    model: Optional[str] = None
    provider: Optional[str] = None
    status: Optional[str] = None
    limit: int = 100
    offset: int = 0


def _req_dict(r: RequestRow) -> dict[str, Any]:
    return {c.name: getattr(r, c.name) for c in RequestRow.__table__.columns}


def _event_dict(e: EventRow) -> dict[str, Any]:
    d = {c.name: getattr(e, c.name) for c in EventRow.__table__.columns if c.name != "metadata_json"}
    d["metadata"] = json.loads(e.metadata_json or "{}")
    return d


def _llm_dict(c: LLMCallRow) -> dict[str, Any]:
    return {col.name: getattr(c, col.name) for col in LLMCallRow.__table__.columns}


class ObservabilityRepository:
    """All persistence for the observability module. Backend is swappable via the DB URL."""

    def __init__(self, db_url: str = "sqlite:///./observability.db") -> None:
        kwargs: dict[str, Any] = {}
        if db_url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False, "timeout": 15}
            if ":memory:" in db_url or db_url == "sqlite://":
                kwargs["poolclass"] = StaticPool
        self.engine: Engine = create_engine(db_url, **kwargs)
        self._lock = threading.RLock()  # serialises writers (SQLite single-writer)
        self._Session = sessionmaker(self.engine, expire_on_commit=False)
        self.init_db()

    def init_db(self) -> None:
        Base.metadata.create_all(self.engine)

    # ---------- writes ----------
    @staticmethod
    def _get_or_create_request(s: Session, request_id: str, ts: datetime) -> RequestRow:
        row = s.get(RequestRow, request_id)
        if row is None:
            row = RequestRow(request_id=request_id, timestamp=ts, status="in_progress",
                             prompt_tokens=0, completion_tokens=0, total_tokens=0,
                             pii_count=0, placeholder_count=0, injection_detected=False)
            s.add(row)
        elif ts < row.timestamp:
            row.timestamp = ts
        return row

    @staticmethod
    def _apply_decision(row: RequestRow, decision: Optional[str]) -> None:
        if not decision:
            return
        if row.decision == "BLOCKED":
            return  # BLOCKED is terminal
        if decision in {"BLOCK", "BLOCKED"}:
            row.decision = "BLOCKED"
        elif decision in {"ALLOW", "ALLOWED"}:
            row.decision = "ALLOWED"
        elif row.decision is None:
            row.decision = decision

    def save_event(self, ev: SecurityEvent) -> None:
        """Persist event and update the per-request roll-up atomically."""
        meta = ev.metadata
        count = meta.get("count")
        count = int(count) if isinstance(count, (int, float)) and count >= 0 else 1
        with self._lock, self._Session() as s, s.begin():
            if s.execute(select(EventRow.seq).where(EventRow.event_id == ev.event_id)).first():
                return  # idempotent
            req = self._get_or_create_request(s, ev.request_id, ev.timestamp)
            s.add(EventRow(event_id=ev.event_id, request_id=ev.request_id, timestamp=ev.timestamp,
                           event_type=ev.event_type.value, severity=ev.severity.value, source=ev.source,
                           category=ev.category, confidence=ev.confidence, decision=ev.decision,
                           message=ev.message, metadata_json=json.dumps(meta, default=str)))
            t = ev.event_type
            if t == EventType.PII_DETECTED:
                req.pii_count += count
            elif t == EventType.PLACEHOLDER_CREATED:
                req.placeholder_count += count
            elif t == EventType.PROMPT_INJECTION_DETECTED:
                req.injection_detected = True
                self._apply_decision(req, ev.decision)
            elif t == EventType.REQUEST_BLOCKED:
                self._apply_decision(req, "BLOCKED")
                req.status = "blocked"
                lat = meta.get("latency_ms")
                if isinstance(lat, (int, float)):
                    req.latency_ms = float(lat)
            elif t == EventType.REQUEST_ALLOWED:
                self._apply_decision(req, "ALLOWED")
            elif t in (EventType.REQUEST_COMPLETED, EventType.REQUEST_FAILED):
                failed = t == EventType.REQUEST_FAILED
                if not (req.status == "blocked" and not failed):
                    req.status = "failed" if failed else "completed"
                lat = meta.get("latency_ms")
                req.latency_ms = float(lat) if isinstance(lat, (int, float)) else \
                    max((ev.timestamp - req.timestamp).total_seconds() * 1000.0, 0.0)
                if failed:
                    req.error_type = str(meta.get("error_type") or ev.category or "UNKNOWN")[:64]
                self._apply_decision(req, ev.decision)
            elif t == EventType.LLM_ERROR:
                req.error_type = str(meta.get("error_type") or ev.category or "LLM_ERROR")[:64]
            else:
                self._apply_decision(req, ev.decision)

    def save_llm_call(self, call: LLMCall) -> None:
        with self._lock, self._Session() as s, s.begin():
            req = self._get_or_create_request(s, call.request_id, call.timestamp)
            s.add(LLMCallRow(request_id=call.request_id, timestamp=call.timestamp, provider=call.provider,
                             model=call.model, prompt_tokens=call.prompt_tokens,
                             completion_tokens=call.completion_tokens, total_tokens=call.total_tokens,
                             latency_ms=call.latency_ms, status=call.status,
                             estimated_cost=call.estimated_cost, error_type=call.error_type))
            req.model, req.provider = call.model, call.provider
            req.prompt_tokens += call.prompt_tokens
            req.completion_tokens += call.completion_tokens
            req.total_tokens += call.total_tokens
            if call.error_type:
                req.error_type = call.error_type

    # ---------- reads ----------
    def _req_where(self, stmt, f: QueryFilters):
        if f.start_time: stmt = stmt.where(RequestRow.timestamp >= f.start_time)
        if f.end_time: stmt = stmt.where(RequestRow.timestamp <= f.end_time)
        if f.decision: stmt = stmt.where(RequestRow.decision == f.decision.upper())
        if f.model: stmt = stmt.where(RequestRow.model == f.model)
        if f.provider: stmt = stmt.where(RequestRow.provider == f.provider)
        if f.status: stmt = stmt.where(RequestRow.status == f.status.lower())
        return stmt

    def get_request(self, request_id: str) -> Optional[dict[str, Any]]:
        with self._Session() as s:
            row = s.get(RequestRow, request_id)
            return _req_dict(row) if row else None

    def list_requests(self, f: Optional[QueryFilters] = None) -> list[dict[str, Any]]:
        f = f or QueryFilters()
        stmt = self._req_where(select(RequestRow), f).order_by(RequestRow.timestamp.desc())
        with self._Session() as s:
            return [_req_dict(r) for r in s.scalars(stmt.limit(f.limit).offset(f.offset))]

    def count_requests(self, f: Optional[QueryFilters] = None) -> int:
        f = f or QueryFilters()
        with self._Session() as s:
            return s.scalar(self._req_where(select(func.count()).select_from(RequestRow), f)) or 0

    def get_security_events(self, f: Optional[QueryFilters] = None, request_id: Optional[str] = None
                            ) -> list[dict[str, Any]]:
        f = f or QueryFilters()
        stmt = select(EventRow)
        if request_id: stmt = stmt.where(EventRow.request_id == request_id)
        if f.start_time: stmt = stmt.where(EventRow.timestamp >= f.start_time)
        if f.end_time: stmt = stmt.where(EventRow.timestamp <= f.end_time)
        if f.event_type: stmt = stmt.where(EventRow.event_type == f.event_type.upper())
        if f.severity: stmt = stmt.where(EventRow.severity == f.severity.lower())
        if f.decision: stmt = stmt.where(EventRow.decision == f.decision.upper())
        if f.model or f.provider or f.status:
            stmt = stmt.join(RequestRow, RequestRow.request_id == EventRow.request_id)
            if f.model: stmt = stmt.where(RequestRow.model == f.model)
            if f.provider: stmt = stmt.where(RequestRow.provider == f.provider)
            if f.status: stmt = stmt.where(RequestRow.status == f.status.lower())
        order = (EventRow.timestamp.asc(), EventRow.seq.asc()) if request_id else \
                (EventRow.timestamp.desc(), EventRow.seq.desc())
        with self._Session() as s:
            return [_event_dict(e) for e in s.scalars(stmt.order_by(*order).limit(f.limit).offset(f.offset))]

    def list_llm_calls(self, f: Optional[QueryFilters] = None) -> list[dict[str, Any]]:
        f = f or QueryFilters()
        stmt = select(LLMCallRow)
        if f.start_time: stmt = stmt.where(LLMCallRow.timestamp >= f.start_time)
        if f.end_time: stmt = stmt.where(LLMCallRow.timestamp <= f.end_time)
        if f.model: stmt = stmt.where(LLMCallRow.model == f.model)
        if f.provider: stmt = stmt.where(LLMCallRow.provider == f.provider)
        with self._Session() as s:
            return [_llm_dict(c) for c in
                    s.scalars(stmt.order_by(LLMCallRow.timestamp.desc()).limit(f.limit).offset(f.offset))]

    # ---------- maintenance ----------
    def purge_older_than(self, days: int) -> int:
        cutoff = utcnow() - timedelta(days=days)
        with self._lock, self._Session() as s, s.begin():
            old = select(RequestRow.request_id).where(RequestRow.timestamp < cutoff)
            s.execute(delete(EventRow).where(EventRow.request_id.in_(old)))
            s.execute(delete(LLMCallRow).where(LLMCallRow.request_id.in_(old)))
            return s.execute(delete(RequestRow).where(RequestRow.timestamp < cutoff)).rowcount or 0

    def ping(self) -> bool:
        try:
            with self.engine.connect() as c:
                c.execute(text("SELECT 1"))
            return True
        except Exception:
            return False

    def clear_all(self) -> None:
        with self._lock, self._Session() as s, s.begin():
            for m in (EventRow, LLMCallRow, RequestRow):
                s.execute(delete(m))
