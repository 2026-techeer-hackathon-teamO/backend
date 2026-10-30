from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routers import alerts, canary, logs

app = FastAPI(
    title="DLP Backend",
    description="사내 기밀 유출 방지 · 내부자 위협 탐지 · 허니팟/카나리토큰 서버",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Total-Count"],  # GET /api/logs 페이지네이션 전체 건수
)

app.include_router(logs.router)
app.include_router(alerts.router)
app.include_router(canary.router)


@app.get("/health", tags=["meta"])
async def health() -> dict:
    return {"status": "ok"}
