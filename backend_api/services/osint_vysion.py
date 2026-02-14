import vysion
from vysion import client
from typing import Dict, Any, List
from backend_api.core.config import settings

class ServicioVysion:
    def __init__(self):
        self.client = None
        if settings.VYSION_API_KEY:
            try:
                self.client = client.Client(api_key=settings.VYSION_API_KEY)
            except: pass

    def analizar(self, objetivo: str, tipo: str = "general") -> Dict[str, Any]:
        if not self.client: return {"exito": False, "error": "API Key no configurada"}
        
        try:
            result = self.client.search(objetivo)
            hits_data = []
            
            if hasattr(result, 'hits'):
                for hit in result.hits:
                     # Simplified extraction for safety
                     page = getattr(hit, 'page', None)
                     if page:
                         hits_data.append({
                             "titulo": getattr(page, 'title', 'Sin título'),
                             "url": str(getattr(page, 'url', '')),
                             "fecha": str(getattr(page, 'date', ''))
                         })
            
            return {"exito": True, "datos": {"hits": hits_data, "total": len(hits_data)}}
        except Exception as e:
            return {"exito": False, "error": str(e)}
