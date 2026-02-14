from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime

class SearchRequest(BaseModel):
    objetivo: str = Field(..., description="El objetivo a analizar (IP, Dominio, Usuario, etc)")
    tipo: Optional[str] = Field(None, description="Tipo de objetivo: ip, domain, email, user, phone, etc")

class SearchResponse(BaseModel):
    exito: bool
    search_id: str
    query: str
    detected_type: str
    risk_score: str
    timestamp: datetime
    data: Dict[str, Any]
    correlaciones: List[Dict[str, Any]]
    geopuntos: List[Dict[str, Any]] = []

class AIAnalysisRequest(BaseModel):
    prompt: str
    context: Dict[str, Any] = {}

class AIAnalysisResponse(BaseModel):
    exito: bool
    analisis: str
    riesgo: str
