from collections import defaultdict, deque
from time import monotonic
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from .auth import router as auth_router
from .config import settings
from .files import router as files_router

app = FastAPI(title="Adaptive Security Encrypted File API", version="1.0.0", docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=[settings.frontend_origin], allow_credentials=True,
                   allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
                   allow_headers=["Content-Type", "X-CSRF-Token", "X-Upload-Token", "X-Content-SHA256"])
_requests: dict[str, deque[float]] = defaultdict(deque)

@app.middleware("http")
async def rate_limit(request: Request, call_next):
    now = monotonic()
    client = request.client.host if request.client else "unknown"
    bucket = _requests[client]
    while bucket and bucket[0] < now - settings.rate_limit_window_seconds:
        bucket.popleft()
    if len(bucket) >= settings.rate_limit_requests:
        return JSONResponse(status_code=429, content={"detail": "Too many requests"})
    bucket.append(now)
    return await call_next(request)

@app.get("/health")
def health():
    return {"status": "ok"}

app.include_router(auth_router)
app.include_router(files_router)
