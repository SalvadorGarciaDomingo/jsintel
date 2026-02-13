from fastapi import APIRouter, HTTPException
from backend_api.models.schemas import AIRequest, AIResponse
from backend_api.services.ai_service import generate_analysis
import uuid

router = APIRouter()

@router.post("/analyze", response_model=AIResponse)
async def analyze_results(request: AIRequest):
    try:
        # If search_id provided, fetch from DB (mocked here)
        # If context_data provided, use it directly
        data_to_analyze = request.context_data
        if not data_to_analyze and not request.search_id:
            raise HTTPException(status_code=400, detail="Must provide search_id or context_data")

        analysis = await generate_analysis(data_to_analyze)
        
        return AIResponse(
            success=True,
            analysis_id=str(uuid.uuid4()),
            **analysis
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
