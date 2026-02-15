from fastapi import APIRouter, HTTPException
from backend_api.models.api_models import AIAnalysisRequest, AIAnalysisResponse
from backend_api.core.ai_client import AIIdentityAnalyst
import json

router = APIRouter(prefix="/api/v1/ai", tags=["AI"])

@router.post("/analyze", response_model=AIAnalysisResponse)
async def analyze_with_ai(request: AIAnalysisRequest):
    try:
        analyst = AIIdentityAnalyst()
        if "osint_data" in request.context:
            osint = request.context["osint_data"] or {}
            resumen = build_osint_summary(osint)
            result = analyst.analizar_global(resumen)
            return AIAnalysisResponse(
                exito=("error" not in result),
                analisis=json.dumps(result, ensure_ascii=False),
                riesgo=result.get("nivel_amenaza", "N/A")
            )
        return AIAnalysisResponse(exito=False, analisis="Contexto insuficiente", riesgo="N/A")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def build_osint_summary(data: dict) -> str:
    parts = []
    ip = data.get("ip", {}).get("datos", {}).get("ip_api", {})
    if ip:
        parts.append(f"IP: {ip.get('ip')} | Ubicación: {ip.get('ubicacion')} | ISP: {ip.get('isp')} | ASN: {ip.get('asn')}")
    domain = data.get("domain", {}).get("datos", {}).get("dominio", {})
    if domain:
        subs = ", ".join(domain.get("subdominios", [])[:10])
        parts.append(f"Dominio: {domain.get('dominio')} | IP asociada: {domain.get('ip_asociada')} | Subdominios (10): {subs}")
    email = data.get("email", {}).get("datos", {})
    if email:
        parts.append(f"Email: {email.get('email')} | Dominio: {email.get('dominio')} | Usuario: {email.get('usuario')} | Desechable: {email.get('es_desechable')}")
    for item in data.get("emails", []) or []:
        e = item.get("datos", {})
        if e:
            parts.append(f"Email derivado: {e.get('email')} | Dominio: {e.get('dominio')}")
    user = data.get("user", {}).get("datos", {}).get("username", {})
    if user:
        perfiles = " | ".join([p.get("sitio", "") for p in user.get("perfiles_encontrados", [])])
        parts.append(f"Usuario: {user.get('usuario')} | Perfiles: {perfiles}")
    vysion = data.get("vysion", {}).get("datos", {})
    if vysion:
        total = vysion.get("total", 0)
        parts.append(f"Vysion resultados web: {total}")
        leaks = vysion.get("leaks", {})
        if leaks:
            parts.append(f"Vysion leaks: {leaks.get('total', 0)}")
    return "\n".join(parts)
