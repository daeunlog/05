
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.concurrency import run_in_threadpool

from app.api.history import router as history_router
from app.api.scan import router as scan_router
from app.db.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    await run_in_threadpool(init_db)
    yield

app = FastAPI(
    title="QRSafe API",
    description="URLBERT 기반 QR코드 큐싱 탐지 서비스",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(scan_router)
app.include_router(history_router)


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "qrsafe-backend",
        "version": "0.1.0",
    }
