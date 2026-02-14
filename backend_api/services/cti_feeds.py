import requests
from bs4 import BeautifulSoup
from typing import Dict, Any, List

class ServicioCTI:
    """
    Recolección de Inteligencia de Amenazas (CTI) desde fuentes públicas.
    """
    RANSOMWARE_URL = "https://ransomware.live"

    def verificar_ransomware(self, objetivo: str) -> Dict[str, Any]:
        """
        Verifica si el objetivo aparece en la lista reciente de víctimas de ransomware.live.
        """
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(self.RANSOMWARE_URL, headers=headers, timeout=10)
            
            encontrado = False
            detalles = []

            if response.status_code == 200:
                obj_l = (objetivo or "").lower()
                if obj_l and obj_l in response.text.lower():
                    encontrado = True
                    detalles.append(f"El indicador '{objetivo}' aparece mencionado en la página principal de Ransomware.live.")
                
                return {
                    "exito": True,
                    "datos": {
                        "fuente": "Ransomware.live",
                        "en_lista_victimas": encontrado,
                        "detalles": detalles
                    }
                }
            else:
                 return {"exito": False, "error": f"Error HTTP {response.status_code}"}

        except Exception as e:
            return {"exito": False, "error": f"Excepción Scraping: {str(e)}"}

    def verificar_agente_malicioso(self, objetivo: str) -> Dict[str, Any]:
        """
        Evalúa la probabilidad de que el identificador pertenezca a un AGENTE MALICIOSO.
        """
        probabilidad = 0
        razones = []
        
        GRUPOS_AMENAZA = [
            "lockbit", "blackcat", "alphv", "cl0p", "play", "akira", "8base", 
            "bianlian", "medusa", "lockfile", "revil", "conti", "lapsus", 
            "scattered spider", "darkside", "hive", "royal", "blackbasta"
        ]
        
        ROLES_CRIMINALES = [
            "support", "admin", "recruitment", "decrypt", "recovery", "sales", 
            "hacked", "pwned", "leak", "onion", "tox", "jabber"
        ]

        obj_lower = (objetivo or "").lower()
        if not obj_lower:
            return {"es_agente_potencial": False, "nivel_riesgo": "NULO", "justificacion": []}

        # 1. Coincidencia Directa con Nombre de Grupo
        for grupo in GRUPOS_AMENAZA:
            if grupo == obj_lower:
                probabilidad = 90
                razones.append(f"El identificador coincide EXACTAMENTE con el grupo criminal conocido: {grupo.upper()}.")
                break
            elif grupo in obj_lower:
                probabilidad += 40
                razones.append(f"El identificador contiene el nombre del grupo criminal: {grupo.upper()}.")

        # 2. Coincidencia de Rol/Jerga
        for rol in ROLES_CRIMINALES:
            if rol in obj_lower:
                probabilidad += 15
                razones.append(f"Contiene término asociado a operaciones cibercriminales: '{rol}'.")

        # 3. Patrones de Infraestructura Sospechosa
        if "onion" in obj_lower or "proton" in obj_lower or "tutanota" in obj_lower:
             probabilidad += 10
             razones.append("Usa proveedores o terminologías favorecidos por actores de amenazas.")

        probabilidad = min(probabilidad, 100)
        
        nivel_riesgo = "BAJO"
        if probabilidad > 75: nivel_riesgo = "CRÍTICO (Actor Identificado)"
        elif probabilidad > 50: nivel_riesgo = "ALTO (Probable Actor M.)"
        elif probabilidad > 25: nivel_riesgo = "MEDIO (Sospechoso)"
        elif probabilidad > 0: nivel_riesgo = "BAJO (Coincidencia menor)"
        else: nivel_riesgo = "NULO"

        return {
            "es_agente_potencial": probabilidad > 0,
            "probabilidad": probabilidad,
            "nivel_riesgo": nivel_riesgo,
            "justificacion": razones
        }
