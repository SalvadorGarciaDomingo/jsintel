from fastapi import APIRouter
from backend_api.models.schemas import ErrorResponse

router = APIRouter()

@router.get("/health", response_model=dict)
async def health_check():
    return {"status": "ok", "service": "Vysion OSINT API", "ready": True}
