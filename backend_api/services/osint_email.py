import re
import dns.resolver
from typing import Dict, Any
from concurrent.futures import ThreadPoolExecutor
from backend_api.services.osint_hibp import ServicioHIBP
# Holehe integration would go here if available, keeping simplified for now ensuring robust imports

class ServicioEmail:
    DISPOSABLE_DOMAINS = ["tempmail.com", "10minutemail.com", "yopmail.com"]

    def analizar(self, email: str) -> Dict[str, Any]:
        email = str(email or "").strip().lower()
        if "@" not in email: return {"exito": False, "error": "Email inválido"}
        
        usuario, dominio = email.split('@')
        
        # HIBP Check
        hibp_data = ServicioHIBP().sync_check_account(email)
        
        # MX Check
        mx_records = []
        try:
            answers = dns.resolver.resolve(dominio, 'MX')
            mx_records = [str(r.exchange) for r in answers]
        except: pass

        return {
            "exito": True,
            "datos": {
                "email": email,
                "usuario": usuario,
                "dominio": dominio,
                "mx_records": mx_records,
                "es_desechable": dominio in self.DISPOSABLE_DOMAINS,
                "hibp_data": hibp_data
            }
        }
