from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from backend_api_prod.models.api_models import SearchRequest, SearchResponse
from backend_api_prod.core.orchestrator import AnalysisEngine
import uuid
from datetime import datetime

router = APIRouter(prefix="/api/v1/search", tags=["Search"])

@router.post("/", response_model=SearchResponse)
async def perform_search(request: SearchRequest):
    try:
        engine = AnalysisEngine(max_depth=2) # Configurable depth
        search_id = str(uuid.uuid4())
        
        # Detect type if not provided (simple heuristic or let orchestrator handle)
        tipo = request.tipo
        if not tipo:
            # Basic detection logic could go here, or pass 'unknown' to orchestrator
            # For parity, let's simplistic detection based on input
            if "@" in request.objetivo: tipo = "email"
            elif request.objetivo.replace('.', '').isdigit(): tipo = "phone" # Very basic
            elif "http" in request.objetivo: tipo = "url"
            else: tipo = "user" # Default fallback
            
        resultados, correlaciones, geopuntos, tipo_detectado = await engine.run_analysis(
            objetivo_inicial=request.objetivo,
            tipo_inicial=tipo
        )
        
        # Calculate aggregations or risk score here based on correlations
        risk_score = "BAJO"
        critical_count = sum(1 for c in correlaciones if c.get('nivel') in ['Alta', 'Crítica'])
        if critical_count > 0: risk_score = "ALTO"
        elif len(correlaciones) > 5: risk_score = "MEDIO"

        return SearchResponse(
            exito=True,
            search_id=search_id,
            query=request.objetivo,
            detected_type=tipo_detectado,
            risk_score=risk_score,
            timestamp=datetime.utcnow(),
            data=resultados,
            correlaciones=correlaciones,
            geopuntos=geopuntos
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
