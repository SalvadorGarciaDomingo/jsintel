import requests
import time
from typing import Dict, Any
from backend_api.core.config import settings

class ServicioUrlscan:
    SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
    RESULT_URL = "https://urlscan.io/api/v1/result/"

    def __init__(self):
        self.api_key = settings.URLSCAN_API_KEY

    def analizar(self, objetivo: str) -> Dict[str, Any]:
        headers = {'Content-Type': 'application/json', 'API-Key': self.api_key}
        data = {'url': objetivo, 'public': 'on'}
        
        try:
            resp = requests.post(self.SUBMIT_URL, headers=headers, json=data, timeout=15)
            if resp.status_code in [200, 201]:
                uuid = resp.json().get('uuid')
                result = {
                    "uuid": uuid,
                    "url_resultado": f"https://urlscan.io/result/{uuid}/",
                    "mensaje": "Escaneo iniciado."
                }
                # Intentar obtener el resultado si ya está disponible
                try:
                    r = requests.get(f"{self.RESULT_URL}{uuid}/", timeout=10)
                    if r.status_code == 200:
                        j = r.json() or {}
                        page = j.get('page', {}) or {}
                        verdicts = j.get('verdicts', {}) or {}
                        overall = verdicts.get('overall', {}) or {}
                        url = page.get('url')
                        domain = page.get('domain')
                        ip = page.get('ip')
                        asn = page.get('asn')
                        country = page.get('country')
                        title = page.get('title')
                        s = 0
                        try:
                            s = int(overall.get('score') or 0)
                        except:
                            s = 0
                        if overall.get('malicious'): s = max(s, 90)
                        # Fallback simple de puntuación si no hay score
                        if s == 0:
                            text = f"{(title or '')} {(url or '')}".lower()
                            flags = ['login', 'bank', 'paypal', 'verify', 'account', 'admin', 'wallet']
                            count = sum(1 for w in flags if w in text)
                            s = min(100, count * 20)
                        result['resultado'] = {
                            "url": url,
                            "dominio": domain,
                            "ip": ip,
                            "asn": asn,
                            "pais": country,
                            "titulo": title,
                            "score": s
                        }
                        result['mensaje'] = "Resultado obtenido"
                except Exception:
                    pass
                return {"exito": True, "datos": result}
            return {"exito": False, "error": f"Error API: {resp.status_code}"}
        except Exception as e: return {"exito": False, "error": str(e)}

    def obtener_resultado(self, uuid: str) -> Dict[str, Any]:
        try:
            resp = requests.get(f"{self.RESULT_URL}{uuid}/", timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "exito": True,
                    "datos": {
                        "screenshot": f"https://urlscan.io/screenshots/{uuid}.png",
                        "score": data.get('verdicts', {}).get('overall', {}).get('score')
                    }
                }
            return {"exito": False, "error": "Procesando o no encontrado"}
        except Exception as e: return {"exito": False, "error": str(e)}
