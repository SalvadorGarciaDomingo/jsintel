import requests
from typing import Dict, Any, List
import re
import socket
import whois
import ssl
from urllib.parse import urlparse

class ServicioDominio:
    BASE_URL = "https://crt.sh/?q={}&output=json"
    CLOUDFLARE_IPS = [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
    ]

    def analizar(self, dominio: str) -> Dict[str, Any]:
        # Normalizar dominio para consultas (evitar 'www.' y slashes finales)
        clean = str(dominio or "").strip().lower().rstrip(".").rstrip("/")
        if clean.startswith("www."):
            clean = clean[4:]
        fuentes = {}
        subdominios = set()
        correos = set()
        errores = []
        
        try:
            resp = requests.get(self.BASE_URL.format(clean), headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for item in data:
                    name_value = item.get('name_value', '')
                    for nombre in name_value.split('\n'):
                        if '@' in nombre: correos.add(nombre)
                        else: subdominios.add(nombre)
            else: errores.append(f"crt.sh HTTP {resp.status_code}")
        except Exception as e: errores.append(f"crt.sh Error: {str(e)}")
        try:
            resp2 = requests.get(self.BASE_URL.format(f"%25.{clean}"), headers={'User-Agent': 'Mozilla/5.0'}, timeout=8)
            if resp2.status_code == 200:
                data2 = resp2.json()
                for item in data2[:2000]:
                    name_value = item.get('name_value', '')
                    for nombre in name_value.split('\n'):
                        if '@' in nombre: correos.add(nombre)
                        else: subdominios.add(nombre)
            else: errores.append(f"crt.sh* HTTP {resp2.status_code}")
        except Exception as e: errores.append(f"crt.sh* Error: {str(e)}")
        try:
            wb = requests.get(f"https://web.archive.org/cdx/search/cdx?url=*.{clean}&output=json&fl=original&collapse=urlkey", headers={'User-Agent': 'Mozilla/5.0'}, timeout=8)
            if wb.status_code == 200:
                j = wb.json()
                rows = j[1:1501] if isinstance(j, list) and len(j) > 1 else []
                for r in rows:
                    u = r[0] if isinstance(r, list) and r else (r if isinstance(r, str) else "")
                    try:
                        h = urlparse(u).hostname or ""
                        h = h.lower()
                        if h and h != clean and (h.endswith(f".{clean}")):
                            subdominios.add(h)
                        if h == clean:
                            p = urlparse(u).path or ""
                            m = re.search(r'([a-z0-9-]+)\.' + re.escape(clean), u, re.IGNORECASE)
                            if m:
                                subdominios.add(m.group(0).lower())
                    except: pass
            else: errores.append(f"wayback HTTP {wb.status_code}")
        except Exception as e: errores.append(f"wayback Error: {str(e)}")
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((clean, 443), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=clean) as ssock:
                    cert = ssock.getpeercert()
                    san = cert.get('subjectAltName', []) if isinstance(cert, dict) else []
                    for t, n in san:
                        if t == 'DNS':
                            x = n.lower().lstrip("*.")
                            if x and x != clean and x.endswith(f".{clean}"):
                                subdominios.add(x)
        except Exception as e: errores.append(f"tls Error: {str(e)}")

        # 2. Web Analysis
        meta_web = self._scrape_homepage(clean)
        http_data = self._analisis_avanzado_http(clean)
        ip_resuelta = self._resolve_ip(clean)
        
        for email in meta_web.get('emails', []): correos.add(email)

        return {
            "exito": True,
            "datos": {
                "dominio": clean,
                "subdominios": list(subdominios),
                "correos_relacionados": list(correos),
                "telefonos_relacionados": meta_web.get('telefonos', []),
                "total_subdominios": len(subdominios),
                "analisis_web": http_data,
                "errores_api": errores,
                "web_status": meta_web.get('estado', 'UNKNOWN'),
                "titulo_pagina": meta_web.get('titulo_web', 'N/A'),
                "fecha_creacion_dominio": self._get_whois_info(clean).get('creation_date'),
                "ip_asociada": ip_resuelta
            }
        }

    def _analisis_avanzado_http(self, dominio: str) -> Dict[str, Any]:
        res = {"http_headers": {}, "cookies": [], "security_txt": {}, "robots_txt": {}}
        try:
            resp = requests.get(f"https://{dominio}", timeout=8, headers={'User-Agent': 'Mozilla/5.0'})
            res["http_headers"] = {k:v for k,v in resp.headers.items() if k.lower() in ['server', 'x-powered-by']}
            res["cookies"] = [{"nombre": c.name, "domain": c.domain} for c in resp.cookies]
        except: pass
        try:
            rbt = requests.get(f"https://{dominio}/robots.txt", timeout=6, headers={'User-Agent': 'Mozilla/5.0'})
            if rbt.status_code == 200 and rbt.text:
                res["robots_txt"] = {"url": f"https://{dominio}/robots.txt", "contenido": rbt.text}
        except: pass
        try:
            sec = requests.get(f"https://{dominio}/.well-known/security.txt", timeout=6, headers={'User-Agent': 'Mozilla/5.0'})
            if sec.status_code == 200 and sec.text:
                res["security_txt"] = {"url": f"https://{dominio}/.well-known/security.txt", "contenido": sec.text}
            else:
                sec2 = requests.get(f"https://{dominio}/security.txt", timeout=6, headers={'User-Agent': 'Mozilla/5.0'})
                if sec2.status_code == 200 and sec2.text:
                    res["security_txt"] = {"url": f"https://{dominio}/security.txt", "contenido": sec2.text}
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

    def _resolve_ip(self, dominio: str) -> str:
        try:
            return socket.gethostbyname(dominio)
        except:
            return None
