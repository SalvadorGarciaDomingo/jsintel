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

        # SPF / DMARC
        spf_record = None
        dmarc_policy = None
        try:
            txt_answers = dns.resolver.resolve(dominio, 'TXT')
            for r in txt_answers:
                txt = str(r.strings[0] if getattr(r, 'strings', None) else r.to_text())
                if txt.lower().startswith('"v=spf1') or txt.lower().startswith('v=spf1'):
                    spf_record = txt.strip('"')
        except: pass
        try:
            dmarc_domain = f"_dmarc.{dominio}"
            dmarc_answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            for r in dmarc_answers:
                txt = str(r.strings[0] if getattr(r, 'strings', None) else r.to_text())
                if 'v=DMARC1' in txt:
                    dmarc_policy = txt.strip('"')
        except: pass

        return {
            "exito": True,
            "datos": {
                "email": email,
                "usuario": usuario,
                "dominio": dominio,
                "mx_records": mx_records,
                "es_desechable": dominio in self.DISPOSABLE_DOMAINS,
                "hibp_data": hibp_data,
                "spf": spf_record,
                "dmarc": dmarc_policy
            }
        }
