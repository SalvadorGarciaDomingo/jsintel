import requests
import base64
from typing import Dict, Any
from backend_api.core.config import settings

class ServicioVirusTotal:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        self.api_key = settings.VIRUSTOTAL_API_KEY
        self.headers = {"x-apikey": self.api_key}

    def analizar(self, valor: str, tipo: str) -> Dict[str, Any]:
        endpoint = ""
        if tipo == 'ip':
            endpoint = f"/ip_addresses/{valor}"
        elif tipo == 'domain':
            clean = str(valor or "").strip().lower().rstrip(".")
            if clean.startswith("www."):
                clean = clean[4:]
            endpoint = f"/domains/{clean}"
        elif tipo == 'url':
            encoded = base64.urlsafe_b64encode(valor.encode()).decode().strip("=")
            endpoint = f"/urls/{encoded}"
        else: return {"exito": False, "error": "Tipo no soportado"}

        try:
            resp = requests.get(f"{self.BASE_URL}{endpoint}", headers=self.headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                return {
                    "exito": True,
                    "datos": {
                        "malicioso": stats.get('malicious', 0),
                        "reputacion": data.get('reputation', 0),
                        "tags": data.get('tags', [])
                    }
                }
            return {"exito": False, "error": f"API {resp.status_code}"}
        except Exception as e: return {"exito": False, "error": str(e)}
