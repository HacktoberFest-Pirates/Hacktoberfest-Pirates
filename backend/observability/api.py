"""Read-only observability API. Mount `router` in the main app, or run `create_app()` standalone."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, FastAPI, HTTPException, Query

from .repository import QueryFilters
from .schemas import _ID_RE
from .service import get_service

router = APIRouter(prefix="/observability", tags=["observability"])


def _naive(dt: Optional[datetime]) -> Optional[datetime]:
    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt and dt.tzinfo else dt


def _filters(start_time: Optional[datetime], end_time: Optional[datetime], event_type: Optional[str],
             severity: Optional[str], decision: Optional[str], model: Optional[str],
             provider: Optional[str], status: Optional[str], limit: int, offset: int) -> QueryFilters:
    return QueryFilters(start_time=_naive(start_time), end_time=_naive(end_time), event_type=event_type,
                        severity=severity, decision=decision, model=model, provider=provider,
                        status=status, limit=limit, offset=offset)


def _params(start_time: Optional[datetime] = None, end_time: Optional[datetime] = None,
            event_type: Optional[str] = Query(None, max_length=48),
            severity: Optional[str] = Query(None, pattern="^(low|medium|high|critical)$"),
            decision: Optional[str] = Query(None, max_length=32),
            model: Optional[str] = Query(None, max_length=128),
            provider: Optional[str] = Query(None, max_length=64),
            status: Optional[str] = Query(None, max_length=32),
            limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)) -> QueryFilters:
    return _filters(start_time, end_time, event_type, severity, decision, model, provider, status, limit, offset)


from fastapi import Depends  # noqa: E402


@router.get("/summary")
def summary(f: QueryFilters = Depends(_params)) -> dict[str, Any]:
    return get_service().summary(f)


@router.get("/requests")
def requests_list(f: QueryFilters = Depends(_params)) -> dict[str, Any]:
    svc = get_service()
    items = svc.list_requests(f)
    return {"total": svc.repo.count_requests(f), "limit": f.limit, "offset": f.offset, "items": items}


@router.get("/requests/{request_id}")
def request_detail(request_id: str) -> dict[str, Any]:
    if not _ID_RE.match(request_id):
        raise HTTPException(422, "invalid request_id")
    result = get_service().get_request_timeline(request_id)
    if result is None:
        raise HTTPException(404, "request not found")
    return result


@router.get("/events")
def events(f: QueryFilters = Depends(_params)) -> dict[str, Any]:
    return {"limit": f.limit, "offset": f.offset, "items": get_service().list_events(f)}


@router.get("/security")
def security(f: QueryFilters = Depends(_params)) -> dict[str, Any]:
    return get_service().get_security_summary(f)


@router.get("/metrics")
def metrics(f: QueryFilters = Depends(_params)) -> dict[str, Any]:
    return get_service().calculate_metrics(f)


@router.get("/health")
def health() -> dict[str, Any]:
    return get_service().health()


def create_app() -> FastAPI:
    """Standalone app for running the observability API on its own."""
    app = FastAPI(title="AI Security Proxy - Observability API", version="0.1.0")
    app.include_router(router)
    return app


app = create_app()
