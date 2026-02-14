from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend_api.core.config import settings
from backend_api.routers import health, search, ai

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Configuration
# Production: strict allow list
# Local/Dev: might need more permissiveness (but adhering to prod reqs for now)
origins = settings.BACKEND_CORS_ORIGINS

app.add_middleware(
    CORSMiddleware,
    allow_origins=[str(origin) for origin in origins],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(health.router)
app.include_router(search.router)
app.include_router(ai.router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
