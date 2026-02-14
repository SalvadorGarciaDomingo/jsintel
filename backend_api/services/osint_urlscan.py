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
                # In prod, we shouldn't sleep, but for parity with logic:
                # time.sleep(2) 
                return {
                    "exito": True,
                    "datos": {
                        "uuid": uuid,
                        "url_resultado": f"https://urlscan.io/result/{uuid}/",
                        "mensaje": "Escaneo iniciado."
                    }
                }
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
