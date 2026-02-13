from fastapi import APIRouter, HTTPException, Depends
from backend_api.models.schemas import SearchRequest, SearchResponse, ErrorResponse
from backend_api.services.aggregator_service import run_osint_scan
import uuid
from datetime import datetime

router = APIRouter()

@router.post("/", response_model=SearchResponse)
async def perform_search(request: SearchRequest):
    try:
        # Aggregation Logic
        results, risk_score, detected_type = await run_osint_scan(request.query, request.type)
        
        return SearchResponse(
            success=True,
            search_id=str(uuid.uuid4()),
            query=request.query,
            detected_type=detected_type,
            results=results,
            risk_score=risk_score,
            timestamp=datetime.utcnow().isoformat()
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
