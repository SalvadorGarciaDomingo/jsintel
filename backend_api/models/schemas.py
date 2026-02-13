from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

# --- Shared Models ---
class ErrorResponse(BaseModel):
    success: bool = False
    data: Optional[Dict] = None
    error: str

# --- Search Models ---
class SearchRequest(BaseModel):
    query: str = Field(..., min_length=3, description="Identifier to search (IP, Domain, Username, Email)")
    type: Optional[str] = Field(None, description="Optional type hint: ip, domain, username, email")

class SearchResponse(BaseModel):
    success: bool = True
    search_id: str
    query: str
    detected_type: str
    results: Dict[str, Any] # Flexible dict for OSINT results
    risk_score: int
    timestamp: str

# --- AI Models ---
class AIRequest(BaseModel):
    search_id: Optional[str] = None
    context_data: Optional[Dict[str, Any]] = None # Direct payload if search_id not provided
    prompt_override: Optional[str] = None

class AIResponse(BaseModel):
    success: bool = True
    analysis_id: str
    summary: str
    key_findings: List[str]
    risks: List[str]
    recommendations: List[str]
    confidence_score: float
    confidence_justification: str
