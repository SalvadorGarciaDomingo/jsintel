import re
from typing import List, Dict, Any

class ExtractorIdentificadores:
    """
    Motor de extracción de identificadores digitales desde texto libre.
    Detecta: Emails, IPs, Dominios, URLs, Crypto Wallets, Usuarios, Teléfonos.
    """
    
    PATRONES = {
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'ip_v4': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        'domain': r'\b((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}\b',
        'url': r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+',
        'phone': r'\+?\d{1,3}[-. ]?\(?\d{2,4}\)?[-. ]?\d{3,4}[-. ]?\d{3,4}',
        'btc_wallet': r'\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b',
        'eth_wallet': r'\b0x[a-fA-F0-9]{40}\b',
        'discord_invite': r'(?:https?://)?(?:www\.)?(?:discord\.gg|discord\.com/invite)/([a-zA-Z0-9]+)',
        'usuario_handle': r'(?:^|\s)@([a-zA-Z0-9_]{3,20})'
    }

    def extraer_todos(self, texto: str) -> List[Dict[str, str]]:
        if not texto: return []

        identificadores = []
        vistos = set()
        texto_busqueda = texto
        
        # EMAILS
        for match in re.finditer(self.PATRONES['email'], texto_busqueda, re.IGNORECASE):
            val = match.group(0).lower()
            if val not in vistos:
                identificadores.append({'tipo': 'email', 'valor': val})
                vistos.add(val)
        
        # IPs
        for match in re.finditer(self.PATRONES['ip_v4'], texto_busqueda):
            val = match.group(0)
            if val not in vistos:
                identificadores.append({'tipo': 'ip', 'valor': val})
                vistos.add(val)
        
        # DOMINIOS
        dominios_candidatos = []
        for match in re.finditer(self.PATRONES['domain'], texto_busqueda, re.IGNORECASE):
            val = match.group(0).lower()
            if not re.match(r'^\d+(\.\d+){3}$', val): 
                dominios_candidatos.append(val)
        
        # URLs
        for match in re.finditer(self.PATRONES['url'], texto_busqueda, re.IGNORECASE):
            val = match.group(0)
            if val not in vistos:
                identificadores.append({'tipo': 'url', 'valor': val})
                vistos.add(val)

        # Procesar Dominios
        for dom in dominios_candidatos:
            es_parte_de_email = any(dom in d['valor'] and d['tipo'] == 'email' for d in identificadores)
            if not es_parte_de_email and dom not in vistos:
                 identificadores.append({'tipo': 'domain', 'valor': dom})
                 vistos.add(dom)

        # PHONES
        for match in re.finditer(self.PATRONES['phone'], texto_busqueda):
            val = match.group(0).strip()
            val_clean = re.sub(r'[^0-9+]', '', val)
            if len(val_clean) >= 7 and val_clean not in vistos:
                identificadores.append({'tipo': 'phone', 'valor': val_clean})
                vistos.add(val_clean)
        
        # WALLETS
        for match in re.finditer(self.PATRONES['btc_wallet'], texto_busqueda):
            val = match.group(0)
            if val not in vistos:
               identificadores.append({'tipo': 'wallet', 'valor': val, 'subtipo': 'BTC'})
               vistos.add(val)
        
        for match in re.finditer(self.PATRONES['eth_wallet'], texto_busqueda, re.IGNORECASE):
            val = match.group(0)
            if val not in vistos:
               identificadores.append({'tipo': 'wallet', 'valor': val, 'subtipo': 'ETH'})
               vistos.add(val)
           
        # DISCORD
        for match in re.finditer(self.PATRONES['discord_invite'], texto_busqueda, re.IGNORECASE):
             val = match.group(0)
             codigo = match.group(1)
             if val not in vistos:
                 identificadores.append({'tipo': 'discord', 'valor': val, 'codigo': codigo})
                 vistos.add(val)
        
        # USUARIOS
        handles = re.findall(self.PATRONES['usuario_handle'], texto_busqueda)
        for h in handles:
            if h.lower() not in vistos:
                 identificadores.append({'tipo': 'user', 'valor': h})
                 vistos.add(h.lower())

        # FALLBACK
        if not identificadores and len(texto.split()) < 3:
            limpio = texto.strip()
            if limpio and "." not in limpio:
                 identificadores.append({'tipo': 'user', 'valor': limpio})

        return identificadores
