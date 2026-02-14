import re
import unicodedata
from typing import Dict, Any, List, Optional

class HeuristicIntelligence:
    """
    Motor de inferencia heurística para OSINT.
    Deduce información probable (nombres, ubicación, género) a partir de cadenas de texto.
    """

    GEO_KEYWORDS = {
        'madrid': 'Madrid, España',
        'bcn': 'Barcelona, España',
        'barcelona': 'Barcelona, España',
        'mex': 'México',
        'df': 'Ciudad de México',
        'arg': 'Argentina',
        'ba': 'Buenos Aires, Argentina',
        'bogota': 'Bogotá, Colombia',
        'col': 'Colombia',
        'santiago': 'Santiago, Chile',
        'cl': 'Chile',
        'lima': 'Lima, Perú',
        'pe': 'Perú',
        'valencia': 'Valencia, España',
        'sevilla': 'Sevilla, España',
        'uk': 'Reino Unido',
        'london': 'Londres, UK',
        'ny': 'New York, USA',
        'usa': 'Estados Unidos',
        'fr': 'Francia',
        'paris': 'París, Francia'
    }

    COMMON_NAMES = {
        'juan', 'jose', 'maria', 'ana', 'carlos', 'david', 'luis', 'pedro', 'manuel', 'javier',
        'antonio', 'francisco', 'jorge', 'alberto', 'daniel', 'miguel', 'rafael', 'fernando',
        'pablo', 'alejo', 'santiago', 'diego', 'sergio', 'andres', 'roberto', 'ricardo',
        'laura', 'carmen', 'elena', 'isabel', 'lucia', 'marta', 'cristina', 'sara', 'paula'
    }

    def _normalizar_texto(self, texto: str) -> str:
        """Elimina acentos y convierte a minúsculas para análisis."""
        nfkd_form = unicodedata.normalize('NFKD', texto)
        return "".join([c for c in nfkd_form if not unicodedata.combining(c)]).lower()

    def inferir_desde_identificador(self, identificador: str, tipo: str = 'user') -> Dict[str, Any]:
        """
        Analiza un identificador (usuario o parte local del email) y retorna inferencias.
        """
        resultado = {
            "nombres_probables": [],
            "ubicaciones_probables": [],
            "fechas_probables": [],
            "confianza": "Baja"
        }
        
        if not identificador: 
            return resultado

        # Limpiar identificador
        raw_id = identificador
        if tipo == 'email' and '@' in raw_id:
            raw_id = raw_id.split('@')[0]
        if tipo == 'user' and raw_id.startswith('@'):
            raw_id = raw_id[1:]
        if tipo == 'domain':
            for tld in ['.com', '.net', '.org', '.es', '.io', '.co']:
                if raw_id.endswith(tld):
                    raw_id = raw_id[:-len(tld)]
                    break
        
        # 1. Análisis de Separadores
        partes = re.split(r'[._-]', raw_id)
        partes = [p for p in partes if p] 

        score = 0
        nombres_detectados = []
        locs_detectadas = []

        # 2. Iterar partes
        for p in partes:
            p_norm = self._normalizar_texto(p)
            
            # Chequeo de Nombre
            if p_norm in self.COMMON_NAMES:
                nombres_detectados.append(p.capitalize())
                score += 30
            
            # Chequeo Geo
            if p_norm in self.GEO_KEYWORDS:
                locs_detectadas.append(self.GEO_KEYWORDS[p_norm])
                score += 40
            
            # Chequeo Año (19xx o 20xx)
            if re.match(r'^(19|20)\d{2}$', p):
                resultado['fechas_probables'].append(p)
                score += 20
        
        # 3. Reconstrucción de Nombre Completo
        if len(partes) >= 2 and nombres_detectados:
            nombre_compuesto = " ".join([pt.capitalize() for pt in partes if not pt.isdigit() and self._normalizar_texto(pt) not in self.GEO_KEYWORDS])
            if nombre_compuesto not in resultado['nombres_probables']:
                resultado['nombres_probables'].insert(0, nombre_compuesto) # Prioridad alta
                score += 20

        for n in nombres_detectados:
            if not any(n in nc for nc in resultado['nombres_probables']):
                resultado['nombres_probables'].append(n)
        
        resultado['ubicaciones_probables'] = list(set(locs_detectadas))

        # 4. Cálculo de Confianza
        if score >= 60: 
            resultado['confianza'] = "Alta"
        elif score >= 30: 
            resultado['confianza'] = "Media"
        else:
            resultado['confianza'] = "Baja"

        # Heurística extra: CamelCase
        if len(partes) == 1 and not nombres_detectados:
            camel_parts = re.findall(r'[A-Z][a-z]+', raw_id)
            if len(camel_parts) > 1:
                rec_call = self.inferir_desde_identificador(".".join(camel_parts), tipo)
                if rec_call['confianza'] != "Baja":
                    return rec_call 

        return resultado
