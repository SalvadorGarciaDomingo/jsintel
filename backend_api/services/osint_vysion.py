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

    def analizar(self, objetivo: str, tipo: str = "general", gte: str = None, lte: str = None) -> Dict[str, Any]:
        if not self.client: return {"exito": False, "error": "API Key no configurada"}
        
        try:
            # Búsqueda general (web)
            result = self.client.search(objetivo)
            web_hits = []
            
            if hasattr(result, 'hits'):
                for hit in result.hits:
                    page = getattr(hit, 'page', None)
                    tags = getattr(hit, 'tag', []) or []
                    ransomware_group = getattr(hit, 'ransomwareGroup', None)
                    company_name = getattr(hit, 'companyName', None)
                    company_address = getattr(hit, 'companyAddress', None)
                    company_link = getattr(hit, 'companyLink', None)
                    country = getattr(hit, 'country', None)
                    naics = getattr(hit, 'naics', None)
                    industry = getattr(hit, 'industry', None)

                    page_url = {}
                    page_dict = {}
                    if page:
                        # URL object fields
                        url_obj = getattr(page, 'url', None)
                        if url_obj:
                            page_url = {
                                "url": str(getattr(url_obj, 'url', '')),
                                "networkProtocol": getattr(url_obj, 'networkProtocol', None),
                                "domainName": getattr(url_obj, 'domainName', None),
                                "port": getattr(url_obj, 'port', None),
                                "path": getattr(url_obj, 'path', None),
                                "signature": getattr(url_obj, 'signature', None),
                                "network": getattr(url_obj, 'network', None)
                            }
                        page_dict = {
                            "id": getattr(page, 'id', None),
                            "url": page_url,
                            "foundAt": getattr(page, 'foundAt', None),
                            "pageTitle": getattr(page, 'pageTitle', None) or getattr(page, 'title', None),
                            "language": getattr(page, 'language', None),
                            "html": getattr(page, 'html', None),
                            "text": getattr(page, 'text', None),
                            "sha1sum": getattr(page, 'sha1sum', None),
                            "sha256sum": getattr(page, 'sha256sum', None),
                            "ssdeep": getattr(page, 'ssdeep', None),
                            "detectionDate": getattr(page, 'detectionDate', None) or getattr(page, 'date', None),
                            "screenshot": getattr(page, 'screenshot', None),
                            "chunk": getattr(page, 'chunk', None)
                        }

                    web_hits.append({
                        "page": page_dict,
                        "tag": [{"namespace": getattr(t, 'namespace', None), "predicate": getattr(t, 'predicate', None), "value": getattr(t, 'value', None)} for t in tags] if isinstance(tags, list) else [],
                        "ransomwareGroup": ransomware_group,
                        "companyName": company_name,
                        "companyAddress": company_address,
                        "companyLink": company_link,
                        "country": country,
                        "naics": naics,
                        "industry": industry
                    })

            # Búsqueda de filtraciones (leaks), si está disponible
            leaks_data = {"total": 0, "hits": []}
            try:
                # If date range not provided, use last 12 months window (optional)
                leak_result = None
                if hasattr(self.client, 'search_leaks'):
                    leak_result = self.client.search_leaks(q=objetivo, gte=gte, lte=lte)
                if leak_result and hasattr(leak_result, 'hits'):
                    leak_hits = []
                    for hit in leak_result.hits:
                        leak_hits.append({
                            "id": getattr(hit, 'id', None),
                            "filePath": getattr(hit, 'filePath', None),
                            "fileHash": getattr(hit, 'fileHash', None),
                            "detectionDate": str(getattr(hit, 'detectionDate', '')),
                            "detectedInfo": {
                                "emails": list(getattr(getattr(hit, 'detectedInfo', None) or {}, 'emails', []) or getattr(getattr(hit, 'detectedInfo', None) or {}, 'emails', [])),
                                "usernames": list(getattr(getattr(hit, 'detectedInfo', None) or {}, 'usernames', []) or getattr(getattr(hit, 'detectedInfo', None) or {}, 'usernames', []))
                            },
                            "highlight": {
                                "detectedInfo.emails": list((getattr(getattr(hit, 'highlight', None) or {}, 'detectedInfo.emails', []) or [])),
                                "content": list((getattr(getattr(hit, 'highlight', None) or {}, 'content', []) or []))
                            }
                        })
                    leaks_data = {"total": len(leak_hits), "hits": leak_hits}
            except Exception:
                # Keep leaks section empty if endpoint not available or error
                leaks_data = {"total": 0, "hits": []}

            return {
                "exito": True,
                "datos": {
                    "hits": web_hits,
                    "total": len(web_hits),
                    "leaks": leaks_data
                }
            }
        except Exception as e:
            return {"exito": False, "error": str(e)}
