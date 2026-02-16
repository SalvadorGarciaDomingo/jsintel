import requests
import json
import time
import base64
import os
import random
import threading
from backend_api.core.config import get_settings

settings = get_settings()

class RateLimiter:
    """
    Token Bucket Rate Limiter to control AI API usage.
    """
    def __init__(self, max_tokens=2, refill_rate=15):
        self.capacity = max_tokens
        self.tokens = max_tokens
        self.refill_rate = refill_rate / 60.0 # Tokens per second
        self.last_refill = time.time()
        self.lock = threading.Lock()

    def acquire(self):
        with self.lock:
            now = time.time()
            elapsed = now - self.last_refill
            new_tokens = elapsed * self.refill_rate
            
            if new_tokens > 0:
                self.tokens = min(self.capacity, self.tokens + new_tokens)
                self.last_refill = now
            
            if self.tokens >= 1:
                self.tokens -= 1
                time.sleep(random.uniform(0.1, 0.5))
                return
            else:
                deficit = 1 - self.tokens
                wait_time = deficit / self.refill_rate
                time.sleep(wait_time)
                self.last_refill = time.time()
                self.tokens = 0
                time.sleep(random.uniform(0.1, 0.3))
                return

_global_rate_limiter = RateLimiter(max_tokens=2, refill_rate=15)

class AIIdentityAnalyst:
    """
    Lightweight client for processing identity deductions using Google Gemini.
    """
    
    def __init__(self):
        self.api_key = settings.GOOGLE_API_KEY
        self.enabled = bool(self.api_key)
        self.base_url = f"https://generativelanguage.googleapis.com/v1beta/models/{settings.AI_MODEL}:generateContent"
        self.limiter = _global_rate_limiter

    def analizar_email(self, email: str) -> dict:
        if not self.enabled: return {"error": "IA Desactivada"}

        prompt = f"""
        ACTÚA COMO UN PERFILADOR CRIMINAL Y ANALISTA DE INTELIGENCIA.
        Analiza la dirección de correo electrónico: '{email}'

        Deduce la siguiente información basada SOLO en la estructura del texto del correo:
        1. **Nombre Real Probable**: (Separa nombre y apellidos si es posible).
        2. **Año de Nacimiento/Edad**: (Si hay números que parezcan años).
        3. **Género Probable**: (Basado en nombre).
        4. **Perfil Psicológico/Profesional**: (¿Es formal? ¿Gamer? ¿Desechable?).
        5. **Nivel de Riesgo**: (Bajo/Medio/Alto) basado en la aleatoriedad.

        Responde ÚNICAMENTE en formato JSON válido con estas claves:
        {{
            "nombre_probable": "...",
            "edad_estimada": "...",
            "genero_probable": "...",
            "perfil": "...",
            "nivel_riesgo": "..."
        }}
        """
        return self._call_gemini(prompt)

    def analizar_usuario(self, username: str) -> dict:
        if not self.enabled: return {"error": "IA Desactivada"}

        prompt = f"""
        ACTÚA COMO UN ANALISTA DE INTELIGENCIA DE FUENTES ABIERTAS (OSINT).
        Analiza el siguiente nombre de usuario/alias: '{username}'

        Tu objetivo es realizar un perfilado criminalístico/psicológico basado únicamente en la semántica del alias.
        
        Deduce:
        1. **Origen/Nacionalidad Probable**: (Basado en idioma o referencias culturales).
        2. **Año de Nacimiento/Edad Estimada**: (Si hay dígitos).
        3. **Intereses/Aficiones**: (Gaming, Hacking, Anime, Deportes, etc.).
        4. **Género Probable**: (Si aplica).
        5. **Patrón de Creación**: (¿Aleatorio? ¿NombreReal? ¿LeetSpeak?).

        Responde ÚNICAMENTE en formato JSON válido con estas claves:
        {{
            "origen_probable": "...",
            "edad_estimada": "...",
            "intereses": "...",
            "genero_probable": "...",
            "patron": "..."
        }}
        """
        return self._call_gemini(prompt)

    def analizar_ip(self, ip: str) -> dict:
        if not self.enabled: return {"error": "IA Desactivada"}

        prompt = f"""
        ACTÚA COMO UN ANALISTA DE CIBERINTELIGENCIA (CTI).
        Analiza la siguiente Dirección IP: '{ip}'
        
        Deduce su contexto basándote en patrones comunes y tu conocimiento:
        1. **Contexto/Tipo de Red**: (¿Residencial/ISP, Datacenter/Hosting, VPN/Proxy, Tor Exit Node, Móvil/CGNAT?).
        2. **Uso Probable**: (¿Usuario doméstico, servidor web, botnet, infraestructura corporativa?).
        3. **Nivel de Riesgo**: (Bajo/Medio/Alto/Crítico).
        4. **Acción Recomendada**: (Monitorizar, Bloquear, Investigar, Ignorar).
        
        Responde ÚNICAMENTE en formato JSON válido con estas claves:
        {{
            "contexto": "...",
            "uso_probable": "...",
            "nivel_riesgo": "...",
            "accion_recomendada": "..."
        }}
        """
        return self._call_gemini(prompt)

    def analizar_dominio(self, dominio: str) -> dict:
        if not self.enabled: return {"error": "IA Desactivada"}

        prompt = f"""
        ACTÚA COMO UN ANALISTA DE SEGURIDAD DEFENSIVA (BLUE TEAM).
        Analiza el dominio: '{dominio}'
        
        Evalúa su legitimidad:
        1. **Legitimidad**: (¿Parece un negocio real, un sitio personal, o un dominio de phishing/typosquatting?).
        2. **Intención**: (Comercial, Informativa, Maliciosa, Infraestructura).
        3. **Nivel de Riesgo**: (Bajo/Medio/Alto).
        4. **Posible Suplantación**: (Si parece imitar a una marca conocida, indica cuál).
        
        Responde ÚNICAMENTE en formato JSON válido con estas claves:
        {{
            "legitimidad": "...",
            "intencion": "...",
            "nivel_riesgo": "...",
            "posible_suplantacion": "..."
        }}
        """
        return self._call_gemini(prompt)

    def analizar_hash(self, hash_str: str) -> dict:
        if not self.enabled: return {"error": "IA Desactivada"}

        prompt = f"""
        ACTÚA COMO UN ANALISTA DE MALWARE.
        Analiza el siguiente Hash: '{hash_str}'
        
        Aunque no puedes consultarlo en tiempo real, intenta inferir si es un hash conocido o describe qué harías:
        1. **Tipo de Objeto Probable**: (Executable, Document, Script, Desconocido).
        2. **Asociación Malware**: (Si reconoces el hash como un malware famoso, dilo. Si no, di "No reconocido en base de conocimiento inmutable").
        3. **Recomendación**: (Subir a sandbox, bloquear, etc.).
        
        Responde ÚNICAMENTE en formato JSON válido con estas claves:
        {{
            "tipo_objeto": "...",
            "asociacion_malware": "...",
            "recomendacion": "..."
        }}
        """
        return self._call_gemini(prompt)

    def analizar_wallet(self, wallet: str) -> dict:
        if not self.enabled: return {"error": "IA Desactivada"}

        prompt = f"""
        ACTÚA COMO UN INVESTIGADOR FORENSE DE BLOCKCHAIN.
        Analiza la dirección de Wallet: '{wallet}'
        
        Deduce:
        1. **Red Probable**: (Bitcoin, Ethereum, Tron, etc. basado en el formato).
        2. **Perfil de Riesgo**: (¿Es una dirección de exchange conocido, una wallet personal, o tiene formato sospechoso?).
        3. **Patrón de Uso Típico**: (HODL, Trading, Mixer, Darknet).
        
        Responde ÚNICAMENTE en formato JSON válido con estas claves:
        {{
            "red_probable": "...",
            "perfil_riesgo": "...",
            "patron_uso": "..."
        }}
        """
        return self._call_gemini(prompt)
    
    def analizar_telefono(self, telefono: str) -> dict:
        if not self.enabled: return {"error": "IA Desactivada"}

        prompt = f"""
        ACTÚA COMO UN ANALISTA DE INTELIGENCIA.
        Analiza el número de teléfono: '{telefono}'
        
        Deduce:
        1. **País/Región**: (Basado en prefijo).
        2. **Tipo de Línea**: (Móvil, Fijo, VoIP).
        3. **Riesgo de Fraude**: (Bajo/Medio/Alto - ej. números virtuales suelen ser más riesgosos).
        
        Responde ÚNICAMENTE en formato JSON válido con estas claves:
        {{
            "pais_region": "...",
            "tipo_linea": "...",
            "riesgo_fraude": "..."
        }}
        """
        return self._call_gemini(prompt)

    def analizar_empresa(self, empresa: str) -> dict:
        if not self.enabled: return {"error": "IA Desactivada"}

        prompt = f"""
        ACTÚA COMO UN ANALISTA DE INTELIGENCIA CORPORATIVA.
        Analiza la entidad/empresa: '{empresa}'
        
        Deduce:
        1. **Sector/Industria**: (Tecnología, Finanzas, Salud, etc.).
        2. **Reputación/Sentimiento**: (Líder, Emergente, Controvertida, Desconocida).
        3. **Riesgos Potenciales**: (Estafas, Quiebras recientes, Mala reputación).
        4. **Puntos Clave**: (CEO, País origen, productos bandera).
        
        Responde ÚNICAMENTE en formato JSON válido con estas claves:
        {{
            "sector": "...",
            "reputacion": "...",
            "riesgo": "...",
            "datos_clave": "..."
        }}
        """
        return self._call_gemini(prompt)

    def analizar_imagen(self, image_path: str) -> dict:
        if not self.enabled: return {"error": "IA Desactivada"}
        
        image_data = None
        
        # URL Logic
        if image_path.startswith('http://') or image_path.startswith('https://'):
            try:
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
                    "Referer": "https://www.google.com/"
                }
                resp = requests.get(image_path, headers=headers, timeout=15)
                if resp.status_code == 200:
                    image_data = base64.b64encode(resp.content).decode('utf-8')
                else:
                    return self._analizar_imagen_fallback(image_path, f"Error: {resp.status_code}")
            except Exception as e:
                return self._analizar_imagen_fallback(image_path, str(e))
        else:
            # Local file logic (Ephemeral in Render)
            if os.path.exists(image_path):
                try:
                    with open(image_path, "rb") as image_file:
                        image_data = base64.b64encode(image_file.read()).decode('utf-8')
                except Exception as e:
                    return {"error": f"Error reading file: {e}"}
            else:
                return {"error": "File not found"}

        if not image_data: return {"error": "Failed to process image"}
        # Determine MIME
        mime_type = "image/jpeg"
        try:
            if image_path.startswith('http://') or image_path.startswith('https://'):
                ct = resp.headers.get("Content-Type", "")
                if ct:
                    mime_type = ct.split(";")[0].strip()
            else:
                ext = os.path.splitext(image_path)[1].lower()
                if ext in [".jpg", ".jpeg"]: mime_type = "image/jpeg"
                elif ext == ".png": mime_type = "image/png"
                elif ext == ".webp": mime_type = "image/webp"
                elif ext == ".gif": mime_type = "image/gif"
                elif ext == ".bmp": mime_type = "image/bmp"
        except:
            pass

        prompt = """
        ACTÚA COMO UN ANALISTA EXPERTO EN INTELIGENCIA DE IMÁGENES (IMINT) Y GEO-LOCALIZACIÓN (GEOINT).
        Analiza la imagen con máxima profundidad OSINT.
        
        Responde ÚNICAMENTE en JSON:
        {
            "contexto": "Resumen situacional...",
            "geolocalizacion": "Deducción exacta de lugar (Ciudad, País)...",
            "identificacion_visual": "Monumentos, montañas, playas o barcos específicos identificados...",
            "texto_extraido": "...",
            "info_tecnica": "..."
        }
        """

        payload = {
            "contents": [{
                "parts": [
                    {"text": prompt},
                    {"inline_data": {"mime_type": mime_type, "data": image_data}}
                ]
            }],
            "generationConfig": {"response_mime_type": "application/json"}
        }

        return self._call_gemini_raw(payload)

    def analizar_documento(self, doc_input: str) -> dict:
        if not self.enabled: return {"error": "IA Desactivada"}

        text_content = ""
        doc_data = None
        is_file = False
        
        if os.path.exists(doc_input):
             try:
                if doc_input.lower().endswith('.txt') or doc_input.lower().endswith('.md'):
                    with open(doc_input, "r", encoding="utf-8", errors="ignore") as f:
                        text_content = f.read()
                else:
                    with open(doc_input, "rb") as f:
                        doc_data = base64.b64encode(f.read()).decode('utf-8')
                        is_file = True
             except: pass

        prompt = """
        ACTÚA COMO UN ANALISTA DE INTELIGENCIA DE FUENTES DOCUMENTALES (OSINT).
        Analiza el documento proporcionado.

        Responde ÚNICAMENTE en formato JSON válido con estas claves:
        {
            "resumen": "...",
            "entidades": "...",
            "metadatos": "...",
            "sensibilidad": "..."
        }
        """
        
        if is_file and doc_data:
             ext = os.path.splitext(doc_input)[1].lower()
             if ext == ".pdf":
                 payload = {
                    "contents": [{
                        "parts": [
                            {"text": prompt},
                            {"inline_data": {"mime_type": "application/pdf", "data": doc_data}}
                        ]
                    }],
                    "generationConfig": {"responseMimeType": "application/json"}
                }
                 return self._call_gemini_raw(payload)
             else:
                 return self._call_gemini(f"{prompt}\n\nDOCUMENT NAME: {os.path.basename(doc_input)}")
        
        elif text_content:
             return self._call_gemini(f"{prompt}\n\nCONTENT:\n{text_content[:30000]}")
        
        else:
             return self._call_gemini(f"{prompt}\n\nDOCUMENT NAME: {doc_input}")

    def analizar_global(self, resumen_hallazgos: str) -> dict:
        if not self.enabled: return {"error": "IA Desactivada"}

        prompt = f"""
        ACTÚA COMO UN ANALISTA SENIOR DE INTELIGENCIA DE FUENTES ABIERTAS (OSINT).
        Se te proporciona un resumen de hallazgos de una investigación:
        
        {resumen_hallazgos}

        TU MISIÓN: Correlacionar los puntos de datos para extraer una conclusión lógica.
        
        Responde ÚNICAMENTE en formato JSON válido con estas claves:
        {{
            "hipotesis": "...",
            "narrativa": "...",
            "puntos_ciegos": "...",
            "nivel_amenaza": "..."
        }}
        """
        return self._call_gemini(prompt)
    
    def _analizar_imagen_fallback(self, image_path: str, error_reason: str) -> dict:
        prompt = f"""
        ACTÚA COMO UN ANALISTA DE IMÁGENES (IMINT).
        Error al descargar: {error_reason}.
        Analiza metadatos/URL: '{image_path}'

        Responde ÚNICAMENTE en JSON con estas claves EXACTAS:
        {{
            "contexto": "...",
            "geolocalizacion": "No disponible (Imagen bloqueada por WAF)",
            "identificacion_visual": "Análisis basado en metadatos de URL: ...",
            "texto_extraido": "N/A",
            "info_tecnica": "Fuente: {image_path} | Error: {error_reason}"
        }}
        """
        return self._call_gemini(prompt)

    def _call_gemini(self, prompt: str) -> dict:
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"response_mime_type": "application/json"}
        }
        self.limiter.acquire()
        try:
            response = requests.post(f"{self.base_url}?key={self.api_key}", headers=headers, json=payload, timeout=30)
            if response.status_code == 200:
                return self._clean_json_response(response.json()["candidates"][0]["content"]["parts"][0]["text"])
            return {"error": f"Error API: {response.status_code}"}
        except Exception as e:
            return {"error": f"Fallo IA: {str(e)}"}

    def _call_gemini_raw(self, payload: dict) -> dict:
        headers = {"Content-Type": "application/json"}
        self.limiter.acquire()
        try:
            response = requests.post(f"{self.base_url}?key={self.api_key}", headers=headers, json=payload, timeout=30)
            if response.status_code == 200:
                 return self._clean_json_response(response.json()["candidates"][0]["content"]["parts"][0]["text"])
            return {"error": f"Error API: {response.status_code}"}
        except Exception as e:
            return {"error": f"Excepción IA: {str(e)}"}

    def _clean_json_response(self, text: str) -> dict:
        try:
            return json.loads(text.replace("```json", "").replace("```", "").strip())
        except:
            return {"error": "Invalid JSON response"}

    def chatear(self, contexto: dict, pregunta: str) -> dict:
        if not self.enabled: return {"respuesta": "IA Desactivada"}
        prompt = f"""
        ACTÚA COMO UN ASISTENTE DE INTELIGENCIA.
        Contexto: {json.dumps(contexto, indent=2)}
        
        Pregunta: {pregunta}
        """
        res = self._call_gemini(prompt)
        # Handle simple text response if JSON fails or structure differs
        return res if "respuesta" in res else {"respuesta": str(res)}
