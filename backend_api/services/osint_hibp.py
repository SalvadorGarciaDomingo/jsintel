import httpx
from typing import Dict, Any
from backend_api_prod.core.config import settings

class ServicioHIBP:
    """
    Servicio para interactuar con la API v3 de HaveIBeenPwned.
    """
    BASE_URL = "https://haveibeenpwned.com/api/v3"
    
    def __init__(self):
        self.api_key = settings.HIBP_API_KEY
        self.user_agent = "SJ-OSINT-Analyzer/1.0"
        self.headers = {
            "hibp-api-key": self.api_key,
            "user-agent": self.user_agent
        }

    async def check_account(self, account: str) -> Dict[str, Any]:
        if not account: return {"found": False, "error": "Cuenta vacía"}
        account = account.strip()
        url = f"{self.BASE_URL}/breachedaccount/{account}?truncateResponse=false"

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, headers=self.headers, timeout=10.0)
                if response.status_code == 200:
                    data = response.json()
                    return {"found": True, "breaches": data, "count": len(data), "summary": f"Cuenta encontrada en {len(data)} filtraciones."}
                elif response.status_code == 404:
                    return {"found": False, "breaches": [], "count": 0, "summary": "No se encontraron filtraciones."}
                elif response.status_code == 429:
                    return {"found": False, "error": "Rate Limit Exceeded", "breaches": []}
                else:
                    return {"found": False, "error": f"Error API ({response.status_code})", "breaches": []}
        except Exception as e:
            return {"found": False, "error": str(e), "breaches": []}

    def sync_check_account(self, account: str) -> Dict[str, Any]:
        """Versión síncrona para compatibilidad."""
        url = f"{self.BASE_URL}/breachedaccount/{account}?truncateResponse=false"
        try:
            with httpx.Client() as client:
                response = client.get(url, headers=self.headers, timeout=10.0)
                if response.status_code == 200:
                    data = response.json()
                    return {"found": True, "breaches": data, "count": len(data)}
                elif response.status_code == 404:
                    return {"found": False, "breaches": [], "count": 0}
                elif response.status_code == 429:
                    return {"found": False, "error": "Rate Limit", "breaches": []}
                else:
                    return {"found": False, "error": str(response.status_code), "breaches": []}
        except Exception as e:
            return {"found": False, "error": str(e), "breaches": []}
