import requests
from typing import Dict, Any
from backend_api_prod.core.config import settings

class ServicioIP:
    BASE_URL = "http://ip-api.com/json/"
    ABUSE_IPDB_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self):
        self.api_key = settings.ABUSEIPDB_API_KEY

    def analizar(self, ip: str) -> Dict[str, Any]:
        try:
            response = requests.get(f"{self.BASE_URL}{ip}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    datos_ip = {
                        "ip": data.get("query"),
                        "pais": data.get("country"),
                        "region": data.get("regionName"),
                        "ciudad": data.get("city"),
                        "ubicacion": f"{data.get('city')}, {data.get('regionName')}, {data.get('country')}",
                        "zip": data.get("zip"),
                        "timezone": data.get("timezone"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "asn": data.get("as"),
                        "latitud": data.get("lat"),
                        "longitud": data.get("lon"),
                        "puertos_abiertos": [],
                        "reputacion": self._consultar_abuseipdb(ip)
                    }
                    
                    # Logic to override country based on AbuseIPDB if discrepancies exist (e.g., Anycast IPs)
                    abuse_cc = datos_ip['reputacion'].get('pais_abuse')
                    if abuse_cc:
                        code_map = {'ES': 'Spain', 'US': 'United States', 'FR': 'France'} # Simplified map
                        if abuse_cc in code_map:
                            pais_real = code_map[abuse_cc]
                            if pais_real != datos_ip.get('pais'):
                                datos_ip['pais'] = pais_real
                                # Override coords for major countries if mismatch detected (simplified for brevity)
                                if abuse_cc == 'ES': 
                                    datos_ip.update({'latitud': 40.4168, 'longitud': -3.7038, 'ciudad': "Madrid (Approx)"})

                    return {"exito": True, "datos": datos_ip}
                else:
                    return {"exito": False, "error": data.get('message')}
            return {"exito": False, "error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"exito": False, "error": str(e)}

    def _consultar_abuseipdb(self, ip: str) -> Dict[str, Any]:
        if not self.api_key: return {"error": "No API Key configured"}
        
        headers = {'Accept': 'application/json', 'Key': self.api_key}
        params = {'ipAddress': ip, 'maxAgeInDays': '90'}
        try:
            response = requests.get(self.ABUSE_IPDB_URL, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    "puntuacion_abuso": data.get('abuseConfidenceScore', 0),
                    "total_reportes": data.get('totalReports', 0),
                    "es_whitelisted": data.get('isWhitelisted', False),
                    "ultima_actividad": data.get('lastReportedAt', 'N/A'),
                    "dominio_asociado": data.get('domain', 'N/A'),
                    "tipo_uso": data.get('usageType', 'Desconocido'),
                    "pais_abuse": data.get('countryCode')
                }
            return {"error": f"Error API AbuseIPDB: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
