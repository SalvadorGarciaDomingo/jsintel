import requests
from typing import Dict, Any, List
import re
import socket
import whois

class ServicioDominio:
    BASE_URL = "https://crt.sh/?q={}&output=json"
    CLOUDFLARE_IPS = [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
    ]

    def analizar(self, dominio: str) -> Dict[str, Any]:
        fuentes = {}
        subdominios = set()
        correos = set()
        errores = []
        
        # 1. CRT.SH
        try:
            resp = requests.get(self.BASE_URL.format(dominio), headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for item in data:
                    name_value = item.get('name_value', '')
                    for nombre in name_value.split('\n'):
                        if '@' in nombre: correos.add(nombre)
                        else: subdominios.add(nombre)
            else: errores.append(f"crt.sh HTTP {resp.status_code}")
        except Exception as e: errores.append(f"crt.sh Error: {str(e)}")

        # 2. Web Analysis
        meta_web = self._scrape_homepage(dominio)
        http_data = self._analisis_avanzado_http(dominio)
        
        for email in meta_web.get('emails', []): correos.add(email)

        return {
            "exito": True,
            "datos": {
                "dominio": dominio,
                "subdominios": list(subdominios),
                "correos_relacionados": list(correos),
                "telefonos_relacionados": meta_web.get('telefonos', []),
                "total_subdominios": len(subdominios),
                "analisis_web": http_data,
                "errores_api": errores,
                "web_status": meta_web.get('estado', 'UNKNOWN'),
                "titulo_pagina": meta_web.get('titulo_web', 'N/A'),
                "fecha_creacion_dominio": self._get_whois_info(dominio).get('creation_date')
            }
        }

    def _analisis_avanzado_http(self, dominio: str) -> Dict[str, Any]:
        res = {"http_headers": {}, "cookies": [], "security_txt": {}, "robots_txt": {}}
        try:
            resp = requests.get(f"https://{dominio}", timeout=8, headers={'User-Agent': 'Mozilla/5.0'})
            res["http_headers"] = {k:v for k,v in resp.headers.items() if k.lower() in ['server', 'x-powered-by']}
            res["cookies"] = [{"nombre": c.name, "domain": c.domain} for c in resp.cookies]
        except: pass
        return res

    def _scrape_homepage(self, dominio: str) -> Dict[str, Any]:
        meta = {"emails": [], "telefonos": [], "estado": "UNKNOWN"}
        try:
            resp = requests.get(f"http://{dominio}", timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
            meta['estado'] = "ONLINE" if resp.status_code < 400 else f"HTTP {resp.status_code}"
            if resp.status_code == 200:
                meta['emails'] = list(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', resp.text)))
                meta['telefonos'] = list(set(re.findall(r'\+?\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}', resp.text)))
                title = re.search(r'<title>(.*?)</title>', resp.text, re.IGNORECASE | re.DOTALL)
                if title: meta['titulo_web'] = title.group(1).strip()
        except: meta['estado'] = "OFFLINE/ERROR"
        return meta

    def _get_whois_info(self, dominio: str) -> Dict[str, Any]:
        try:
            w = whois.whois(dominio)
            cd = w.creation_date
            if isinstance(cd, list): cd = cd[0]
            return {"creation_date": str(cd) if cd else None}
        except: return {"creation_date": None}
