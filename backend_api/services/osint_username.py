import requests
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from backend_api.services.osint_hibp import ServicioHIBP

class ServicioUsuario:
    SITIOS = {
        "Twitter": "https://twitter.com/{}",
        "GitHub": "https://github.com/{}",
        "Instagram": "https://www.instagram.com/{}",
        "Reddit": "https://www.reddit.com/user/{}",
        "Twitch": "https://www.twitch.tv/{}"
    }

    def analizar(self, usuario: str) -> Dict[str, Any]:
        resultados = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._check_site, s, u, usuario): s for s, u in self.SITIOS.items()}
            for f in as_completed(futures):
                if f.result(): results = resultados.append(f.result())
        
        hibp_data = ServicioHIBP().sync_check_account(usuario)

        return {
            "exito": True,
            "datos": {
                "usuario": usuario,
                "perfiles_encontrados": resultados,
                "hibp_data": hibp_data,
                "total_encontrados": len(resultados)
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
