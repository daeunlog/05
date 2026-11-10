
from fastapi import FastAPI

from app.api.scan import router as scan_router

app = FastAPI(
    title="QRSafe API",
    description="URLBERT 기반 QR코드 큐싱 탐지 서비스",
    version="0.1.0",
)

app.include_router(scan_router)


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "qrsafe-backend",
        "version": "0.1.0",
    }
