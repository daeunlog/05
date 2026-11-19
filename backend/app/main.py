
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
import logging
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from app.api.reports import router as report_router
from app.services import model_service
from starlette.concurrency import run_in_threadpool

from app.api.history import router as history_router
from app.api.scan import router as scan_router
from app.db.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    await run_in_threadpool(init_db)
    # httpx INFO logs the outbound request path (VT URL IDs are reversible).
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    await run_in_threadpool(model_service.load_model)
    yield

app = FastAPI(
    title="QRSafe API",
    description="URLBERT 기반 QR코드 큐싱 탐지 서비스",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(scan_router)
app.include_router(history_router)
app.include_router(report_router)


@app.exception_handler(RequestValidationError)
async def invalid_input(request, exc):
    # FastAPI's default validation detail includes the original input.
    errors = [{"type": e["type"], "loc": e["loc"]} for e in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": errors})


@app.get("/health")
def health_check():
    return {
        "status": "ok" if model_service.classifier is not None else "degraded",
        "model_status": "ready" if model_service.classifier is not None else "model_load_failed",
        "service": "qrsafe-backend",
        "version": "0.1.0",
    }
