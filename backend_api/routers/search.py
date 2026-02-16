from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, UploadFile, File, Form
from backend_api.models.api_models import SearchRequest, SearchResponse, CheckURLRequest, CheckURLResponse
from backend_api.core.orchestrator import AnalysisEngine
import uuid
from datetime import datetime
import requests
import tempfile
import os

router = APIRouter(prefix="/api/v1/search", tags=["Search"])

@router.post("/", response_model=SearchResponse)
async def perform_search(request: SearchRequest):
    try:
        engine = AnalysisEngine(max_depth=2) # Configurable depth
        search_id = str(uuid.uuid4())
        
        # Detect type if not provided (simple heuristic or let orchestrator handle)
        tipo = request.tipo
        if not tipo:
            objetivo = (request.objetivo or "").strip()
            objetivo_lower = objetivo.lower().strip()
            objetivo_lower = objetivo_lower.rstrip("/")
            if objetivo_lower.startswith("www."):
                objetivo_lower = objetivo_lower[4:]
            tipo = "user"
            if "@" in objetivo:
                tipo = "email"
            elif objetivo_lower.startswith("http://") or objetivo_lower.startswith("https://"):
                tipo = "url"
            else:
                import re
                ipv4_regex = r"^(?:\d{1,3}\.){3}\d{1,3}$"
                domain_regex = r"^[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}$"
                phone_regex = r"^\+?\d{7,15}$"
                if re.match(ipv4_regex, objetivo_lower):
                    tipo = "ip"
                elif re.match(domain_regex, objetivo_lower):
                    tipo = "domain"
                elif re.match(phone_regex, objetivo_lower.replace(" ", "").replace("-", "")):
                    tipo = "phone"
            
        resultados, correlaciones, graph_data, tipo_detectado = await engine.run_analysis(
            objetivo_inicial=request.objetivo,
            tipo_inicial=tipo
        )
        
        # Calculate aggregations or risk score here based on correlations
        risk_score = "BAJO"
        critical_count = sum(1 for c in correlaciones if c.get('nivel') in ['Alta', 'Crítica'])
        if critical_count > 0: risk_score = "ALTO"
        elif len(correlaciones) > 5: risk_score = "MEDIO"

        resultados["graph_data"] = graph_data
        return SearchResponse(
            exito=True,
            search_id=search_id,
            query=request.objetivo,
            detected_type=tipo_detectado,
            risk_score=risk_score,
            timestamp=datetime.utcnow(),
            data=resultados,
            correlaciones=correlaciones,
            geopuntos=[]
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/check_url", response_model=CheckURLResponse)
async def check_url(req: CheckURLRequest):
    url = (req.url or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL vacía")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    try:
        resp = requests.get(url, headers=headers, timeout=6, allow_redirects=True, stream=True)
        status = resp.status_code
        final = resp.url
        resp.close()
        active = 200 <= status < 400
        return CheckURLResponse(active=active, status_code=status, final_url=final)
    except Exception as e:
        return CheckURLResponse(active=False, status_code=None, final_url=None, error=str(e))

@router.post("/upload_analyze", response_model=SearchResponse)
async def upload_analyze(
    file: UploadFile = File(...),
    tipo: str = Form(...),
):
    try:
        if tipo not in ["image", "document"]:
            raise HTTPException(status_code=400, detail="Tipo inválido. Use 'image' o 'document'.")
        # Guardar archivo temporalmente
        suffix = os.path.splitext(file.filename or "")[1] or ""
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            content = await file.read()
            tmp.write(content)
            tmp_path = tmp.name
        # Ejecutar análisis con archivo adjunto
        engine = AnalysisEngine(max_depth=0)  # sin pivots para archivos
        search_id = str(uuid.uuid4())
        resultados, correlaciones, graph_data, tipo_detectado = await engine.run_analysis(
            objetivo_inicial=tmp_path,
            tipo_inicial=tipo,
            archivos_adjuntos=[]
        )
        # Limpieza del archivo temporal
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        # Riesgo simple (archivos no generan correlaciones típicas)
        risk_score = "BAJO"
        resultados["graph_data"] = graph_data
        return SearchResponse(
            exito=True,
            search_id=search_id,
            query=file.filename or "archivo",
            detected_type=tipo_detectado,
            risk_score=risk_score,
            timestamp=datetime.utcnow(),
            data=resultados,
            correlaciones=correlaciones,
            geopuntos=[]
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
