from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend_api.core.config import get_settings
from backend_api.routers import search, ai, health

settings = get_settings()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

# Routers
app.include_router(health.router, tags=["Health"])
app.include_router(search.router, prefix="/search", tags=["Search"])
app.include_router(ai.router, prefix="/ai", tags=["AI Analysis"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
