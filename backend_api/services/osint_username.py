import requests
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from backend_api.services.osint_hibp import ServicioHIBP
from vysion import client
from backend_api.core.config import settings

class ServicioUsuario:
    SITIOS = {
        "Twitter": "https://twitter.com/{}",
        "GitHub": "https://github.com/{}",
        "Instagram": "https://www.instagram.com/{}",
        "Reddit": "https://www.reddit.com/user/{}",
        "Twitch": "https://www.twitch.tv/{}"
    }
    def __init__(self):
        self.vysion = None
        if settings.VYSION_API_KEY:
            try:
                self.vysion = client.Client(api_key=settings.VYSION_API_KEY)
            except:
                self.vysion = None

    def analizar(self, usuario: str) -> Dict[str, Any]:
        resultados = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._check_site, s, u, usuario): s for s, u in self.SITIOS.items()}
            for f in as_completed(futures):
                if f.result(): results = resultados.append(f.result())
        
        hibp_data = ServicioHIBP().sync_check_account(usuario)
        profiles = {"total": 0, "hits": [], "error": None}
        try:
            if self.vysion and hasattr(self.vysion, "search_im_profiles"):
                res = self.vysion.search_im_profiles(q=usuario, gte=None, lte=None)
                hits_out = []
                for h in getattr(res, "hits", []):
                    emails = []
                    for e in getattr(h, "email", []) or []:
                        v = getattr(e, "value", None) if hasattr(e, "value") else e.get("value") if isinstance(e, dict) else None
                        if v: emails.append(v)
                    paste = []
                    for e in getattr(h, "paste", []) or []:
                        v = getattr(e, "value", None) if hasattr(e, "value") else e.get("value") if isinstance(e, dict) else None
                        if v: paste.append(v)
                    skype = []
                    for e in getattr(h, "skype", []) or []:
                        v = getattr(e, "value", None) if hasattr(e, "value") else e.get("value") if isinstance(e, dict) else None
                        if v: skype.append(v)
                    telegram = []
                    for e in getattr(h, "telegram", []) or []:
                        v = getattr(e, "value", None) if hasattr(e, "value") else e.get("value") if isinstance(e, dict) else None
                        if v: telegram.append(v)
                    whatsapp = []
                    for e in getattr(h, "whatsapp", []) or []:
                        v = getattr(e, "value", None) if hasattr(e, "value") else e.get("value") if isinstance(e, dict) else None
                        if v: whatsapp.append(v)
                    btc = []
                    for e in getattr(h, "bitcoin_address", []) or []:
                        v = getattr(e, "value", None) if hasattr(e, "value") else e.get("value") if isinstance(e, dict) else None
                        if v: btc.append(v)
                    polkadot = []
                    for e in getattr(h, "polkadot_address", []) or []:
                        v = getattr(e, "value", None) if hasattr(e, "value") else e.get("value") if isinstance(e, dict) else None
                        if v: polkadot.append(v)
                    eth = []
                    for e in getattr(h, "ethereum_address", []) or []:
                        v = getattr(e, "value", None) if hasattr(e, "value") else e.get("value") if isinstance(e, dict) else None
                        if v: eth.append(v)
                    monero = []
                    for e in getattr(h, "monero_address", []) or []:
                        v = getattr(e, "value", None) if hasattr(e, "value") else e.get("value") if isinstance(e, dict) else None
                        if v: monero.append(v)
                    ripple = []
                    for e in getattr(h, "ripple_address", []) or []:
                        v = getattr(e, "value", None) if hasattr(e, "value") else e.get("value") if isinstance(e, dict) else None
                        if v: ripple.append(v)
                    zcash = []
                    for e in getattr(h, "zcash_address", []) or []:
                        v = getattr(e, "value", None) if hasattr(e, "value") else e.get("value") if isinstance(e, dict) else None
                        if v: zcash.append(v)
                    hits_out.append({
                        "userId": getattr(h, "userId", None),
                        "usernames": list(getattr(h, "usernames", []) or []),
                        "firstName": list(getattr(h, "firstName", []) or []),
                        "lastName": list(getattr(h, "lastName", []) or []),
                        "detectionDate": str(getattr(h, "detectionDate", "")),
                        "profilePhoto": list(getattr(h, "profilePhoto", []) or []),
                        "bot": bool(getattr(h, "bot", False)),
                        "discordLink": list(getattr(h, "discordLink", []) or []),
                        "discriminator": list(getattr(h, "discriminator", []) or []),
                        "platform": getattr(h, "platform", None),
                        "email": emails,
                        "paste": paste,
                        "skype": skype,
                        "telegram": telegram,
                        "whatsapp": whatsapp,
                        "bitcoin_address": btc,
                        "polkadot_address": polkadot,
                        "ethereum_address": eth,
                        "monero_address": monero,
                        "ripple_address": ripple,
                        "zcash_address": zcash
                    })
                profiles = {"total": len(hits_out), "hits": hits_out, "error": None}
                # Intentar capturar error del objeto si existe
                err = getattr(res, "error", None)
                if err:
                    try:
                        code = getattr(err, "code", None)
                        msg = getattr(err, "message", None)
                        profiles["error"] = f"API Error {code}: {msg}" if (code or msg) else "API Error"
                    except:
                        profiles["error"] = "API Error"
        except Exception as e:
            profiles = {"total": 0, "hits": [], "error": str(e)}

        return {
            "exito": True,
            "datos": {
                "usuario": usuario,
                "perfiles_encontrados": resultados,
                "hibp_data": hibp_data,
                "total_encontrados": len(resultados),
                "vysion_im_profiles": profiles
            }
        }

    def _check_site(self, sitio, url_template, usuario):
        url = url_template.format(usuario)
        try:
            resp = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
            if resp.status_code == 200:
                return {"sitio": sitio, "url": url, "estado": "Encontrado"}
            elif resp.status_code == 404:
                return {"sitio": sitio, "url": url, "estado": "No Encontrado"}
        except: pass
        return None
