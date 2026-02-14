import asyncio
import logging
from typing import Dict, Any, List
from collections import deque

# Importaciones de Módulos (Production Path)
from backend_api_prod.core.extractor import ExtractorIdentificadores
from backend_api_prod.core.heuristic import HeuristicIntelligence
from backend_api_prod.core.correlation import Correlador
from backend_api_prod.core.ai_client import AIIdentityAnalyst, RateLimiter

# Servicios
from backend_api_prod.services.osint_ip import ServicioIP
from backend_api_prod.services.osint_domain import ServicioDominio
from backend_api_prod.services.osint_email import ServicioEmail
from backend_api_prod.services.osint_username import ServicioUsuario
from backend_api_prod.services.osint_phone import ServicioTelefono
# from backend_api_prod.services.osint_image import ServicioImagen # On demand only
from backend_api_prod.services.osint_discord import ServicioDiscord
from backend_api_prod.services.osint_wallet import ServicioWallet
from backend_api_prod.services.cti_feeds import ServicioCTI
from backend_api_prod.services.osint_vysion import ServicioVysion
from backend_api_prod.services.osint_urlscan import ServicioUrlscan
from backend_api_prod.services.osint_virustotal import ServicioVirusTotal

class AnalysisEngine:
    """
    Motor de análisis OSINT para producción.
    Orquesta la ejecución de servicios y la correlación de datos.
    """
    
    def __init__(self, max_depth: int = 1, max_workers: int = 50):
        self.max_depth = max_depth
        self.max_workers = max_workers
        self.extractor = ExtractorIdentificadores()
        self.heuristica = HeuristicIntelligence()
        self.correlador = Correlador()
        self.servicios = {
            'ip': ServicioIP(),
            'domain': ServicioDominio(),
            'email': ServicioEmail(),
            'user': ServicioUsuario(),
            'phone': ServicioTelefono(),
            'discord': ServicioDiscord(),
            'wallet': ServicioWallet(),
            'cti': ServicioCTI(),
            'vysion': ServicioVysion(),
            'urlscan': ServicioUrlscan(),
            'virustotal': ServicioVirusTotal()
        }
    
    async def run_analysis(self, objetivo_inicial: str, tipo_inicial: str, archivos_adjuntos: List[Dict] = []) -> Dict[str, Any]:
        """
        Ejecuta el ciclo completo de análisis.
        """
        resultados_raw = {}
        cola_analisis = deque()
        procesados = set() # Evitar bucles
        
        # 1. Encolar Objetivo Inicial
        cola_analisis.append({
            'tipo': tipo_inicial,
            'valor': objetivo_inicial,
            'profundidad': 0,
            'origen': 'input_usuario'
        })
        
        # 2. Encolar Archivos Adjuntos (si los hay)
        for adj in archivos_adjuntos:
            cola_analisis.append({
                'tipo': adj['tipo'],
                'valor': adj['valor'], # Ruta local
                'profundidad': 0,
                'origen': 'archivo_subido',
                'es_archivo': True
            })

        desglose_final = []
        
        # 3. Bucle Principal (BFS Limitado)
        while cola_analisis:
            item = cola_analisis.popleft()
            valor = item['valor']
            tipo = item['tipo']
            depth = item['profundidad']
            
            # Key única para deduplicación
            key = f"{tipo}:{valor}"
            if key in procesados: continue
            procesados.add(key)
            
            # --- EJECUCIÓN DEL ANÁLISIS ---
            resultado_item = await self._analizar_item(tipo, valor, item.get('es_archivo', False))
            
            # Guardar en resultados
            if depth == 0:
                if tipo not in resultados_raw: resultados_raw[tipo] = resultado_item
            
            desglose_final.append(resultado_item)

            # --- EXTRACCIÓN Y PIVOTING (Si profundidad lo permite) ---
            if depth < self.max_depth and resultado_item.get('exito'):
                nuevos_identificadores = self._extraer_nuevos_objetivos(resultado_item)
                for nuevo in nuevos_identificadores:
                    if f"{nuevo['tipo']}:{nuevo['valor']}" not in procesados:
                        cola_analisis.append({
                            'tipo': nuevo['tipo'],
                            'valor': nuevo['valor'],
                            'profundidad': depth + 1,
                            'origen': f"derivado_de_{tipo}"
                        })

        # 4. Enriquecimiento Global (CTI, Vysion) sobre el objetivo principal
        # Solo lo hacemos para el objetivo input real para ahorrar cuota
        cti_global = self.servicios['cti'].verificar_agente_malicioso(objetivo_inicial)
        
        # 5. Correlación Final
        resultados_check = {'desglose': desglose_final}
        correlaciones = self.correlador.correlacionar(resultados_check)

        return resultados_raw, correlaciones, [], tipo_inicial # Geo points placeholder

    async def _analizar_item(self, tipo: str, valor: str, es_archivo: bool = False) -> Dict[str, Any]:
        """Despacha al servicio correspondiente."""
        datos = {}
        exito = False
        error = None
        
        try:
            # Ejecutar servicio sincrónico en threadpool si es necesario
            # Por simplicidad en este paso, asumimos llamadas directas rápidas o bloqueantes
            svc_res = None
            
            if tipo == 'ip': svc_res = self.servicios['ip'].analizar(valor)
            elif tipo == 'domain': svc_res = self.servicios['domain'].analizar(valor)
            elif tipo == 'email': svc_res = self.servicios['email'].analizar(valor)
            elif tipo == 'user': svc_res = self.servicios['user'].analizar(valor)
            elif tipo == 'phone': svc_res = self.servicios['phone'].analizar(valor)
            # ... otros ...

            if svc_res:
                return {
                    "tipo": tipo,
                    "input": valor,
                    "exito": svc_res.get('exito', False),
                    "datos": svc_res.get('datos', {}),
                    "error": svc_res.get('error'),
                    "es_archivo": es_archivo
                }

        except Exception as e:
            error = str(e)
        
        return {"tipo": tipo, "input": valor, "exito": False, "error": error, "datos": {}}

    def _extraer_nuevos_objetivos(self, resultado_item: Dict) -> List[Dict]:
        """Extrae nuevos pivots del resultado de un análisis."""
        nuevos = []
        datos = resultado_item.get('datos', {})
        tipo = resultado_item.get('tipo')
        
        # Logic to extract from 'datos' based on known structure
        # E.g. extracted emails from domain analysis
        if tipo == 'domain':
            for email in datos.get('correos_relacionados', []):
                nuevos.append({'tipo': 'email', 'valor': email})
        
        return nuevos
