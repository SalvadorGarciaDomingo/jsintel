from fastapi import APIRouter, HTTPException
from backend_api_prod.models.api_models import AIAnalysisRequest, AIAnalysisResponse
from backend_api_prod.core.ai_client import AIIdentityAnalyst

router = APIRouter(prefix="/api/v1/ai", tags=["AI"])

@router.post("/analyze", response_model=AIAnalysisResponse)
async def analyze_with_ai(request: AIAnalysisRequest):
    try:
        analyst = AIIdentityAnalyst()
        # Route to specific method based on context or generic prompt?
        # For simplicity and parity, we might use a generic chat or specific analysis function.
        # Assuming generic chat/analysis for now as per previous monolith usage pattern.
        
        if "osint_data" in request.context:
             analysis_result = analyst.analizar_resultados_globales(request.context["osint_data"])
             return AIAnalysisResponse(
                 exito=True,
                 analisis=analysis_result.get("analisis", ""),
                 riesgo=analysis_result.get("nivel_riesgo", "DESCONOCIDO")
             )
        
        # Fallback to generic query if implemented, currently only implementing structured analysis
        return AIAnalysisResponse(exito=False, analisis="Contexto insuficiente", riesgo="N/A")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
