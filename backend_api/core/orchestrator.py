import asyncio
import logging
from typing import Dict, Any, List
from collections import deque

# Importaciones de Módulos (Production Path)
from backend_api.core.extractor import ExtractorIdentificadores
from backend_api.core.heuristic import HeuristicIntelligence
from backend_api.core.correlation import Correlador
from backend_api.core.ai_client import AIIdentityAnalyst, RateLimiter

# Servicios
from backend_api.services.osint_ip import ServicioIP
from backend_api.services.osint_domain import ServicioDominio
from backend_api.services.osint_email import ServicioEmail
from backend_api.services.osint_username import ServicioUsuario
from backend_api.services.osint_phone import ServicioTelefono
from backend_api.services.osint_image import ServicioImagen
from backend_api.services.osint_metadata import ServicioMetadatos
from backend_api.services.osint_discord import ServicioDiscord
from backend_api.services.osint_wallet import ServicioWallet
from backend_api.services.cti_feeds import ServicioCTI
from backend_api.services.osint_vysion import ServicioVysion
from backend_api.services.osint_urlscan import ServicioUrlscan
from backend_api.services.osint_virustotal import ServicioVirusTotal
from backend_api.core.graph_builder import GraphBuilder

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
            'image': ServicioImagen(),
            'document': ServicioMetadatos(),
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
        resultados_raw['emails'] = []
        
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
            else:
                if tipo == 'email':
                    resultados_raw['emails'].append(resultado_item)
            
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
        resultados_raw['cti'] = cti_global
        try:
            vysion_global = self.servicios['vysion'].analizar(objetivo_inicial)
            resultados_raw['vysion'] = vysion_global
        except Exception as _:
            resultados_raw['vysion'] = {"exito": False, "error": "Vysion error"}
        
        # 5. Correlación Final
        resultados_check = {'desglose': desglose_final}
        correlaciones = self.correlador.correlacionar(resultados_check)

        graph_data = GraphBuilder().build(resultados_raw, objetivo_inicial, tipo_inicial)
        return resultados_raw, correlaciones, graph_data, tipo_inicial

    async def _analizar_item(self, tipo: str, valor: str, es_archivo: bool = False) -> Dict[str, Any]:
        """Despacha al servicio correspondiente."""
        datos = {}
        exito = False
        error = None
        
        try:
            # Ejecutar servicio sincrónico en threadpool si es necesario
            # Por simplicidad en este paso, asumimos llamadas directas rápidas o bloqueantes
            svc_res = None
            
            if tipo == 'ip':
                ip_res = self.servicios['ip'].analizar(valor)
                vt_res = self.servicios['virustotal'].analizar(valor, 'ip')
                svc_res = {
                    "exito": ip_res.get('exito', False) or vt_res.get('exito', False),
                    "datos": {
                        "ip_api": ip_res.get('datos', {}),
                        "virustotal": vt_res.get('datos', {})
                    },
                    "error": ip_res.get('error') or vt_res.get('error')
                }
            elif tipo == 'domain':
                dom_res = self.servicios['domain'].analizar(valor)
                vt_res = self.servicios['virustotal'].analizar(valor, 'domain')
                svc_res = {
                    "exito": dom_res.get('exito', False) or vt_res.get('exito', False),
                    "datos": {
                        "dominio": dom_res.get('datos', {}),
                        "virustotal": vt_res.get('datos', {})
                    },
                    "error": dom_res.get('error') or vt_res.get('error')
                }
            elif tipo == 'url':
                us_res = self.servicios['urlscan'].analizar(valor)
                vt_res = self.servicios['virustotal'].analizar(valor, 'url')
                svc_res = {
                    "exito": us_res.get('exito', False) or vt_res.get('exito', False),
                    "datos": {
                        "urlscan": us_res.get('datos', {}),
                        "virustotal": vt_res.get('datos', {})
                    },
                    "error": us_res.get('error') or vt_res.get('error')
                }
            elif tipo == 'email':
                em_res = self.servicios['email'].analizar(valor)
                svc_res = em_res
            elif tipo == 'user':
                us_res = self.servicios['user'].analizar(valor)
                dc_res = self.servicios['discord'].analizar_usuario(valor)
                svc_res = {
                    "exito": us_res.get('exito', False) or dc_res.get('exito', False),
                    "datos": {
                        "username": us_res.get('datos', {}),
                        "discord": dc_res.get('datos', {})
                    },
                    "error": us_res.get('error') or dc_res.get('error')
                }
            elif tipo == 'phone':
                ph_res = self.servicios['phone'].analizar(valor)
                svc_res = ph_res
            elif tipo == 'discord':
                if 'discord.gg' in valor or 'discordapp.com/invite' in valor:
                    dc = self.servicios['discord'].analizar_invitacion(valor)
                elif valor.isdigit():
                    dc = self.servicios['discord'].analizar_usuario_id(valor)
                else:
                    dc = self.servicios['discord'].analizar_usuario(valor)
                svc_res = dc
            elif tipo == 'wallet':
                wl_res = self.servicios['wallet'].analizar(valor)
                svc_res = wl_res
            elif tipo == 'image':
                meta_res = self.servicios['image'].analizar(valor)
                ia = AIIdentityAnalyst()
                ia_res = ia.analizar_imagen(valor)
                svc_res = {
                    "exito": meta_res.get('exito', False) or ("error" not in ia_res),
                    "datos": {
                        "metadata": meta_res.get('datos', {}),
                        "ia": ia_res
                    },
                    "error": meta_res.get('error')
                }
            elif tipo == 'document':
                md = ServicioMetadatos()
                docx_res = {}
                try:
                    low = valor.lower()
                    if low.endswith(".docx"):
                        docx_res = md.analizar_docx(valor)
                except: 
                    docx_res = {}
                ia = AIIdentityAnalyst()
                ia_res = ia.analizar_documento(valor)
                svc_res = {
                    "exito": (docx_res.get('exito', False) if docx_res else False) or ("error" not in ia_res),
                    "datos": {
                        "docx": docx_res.get('datos', {}) if docx_res else {},
                        "ia": ia_res
                    },
                    "error": docx_res.get('error')
                }

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
        if tipo == 'user':
            usr = datos.get('username', {})
            vip = usr.get('vysion_im_profiles', {})
            for h in vip.get('hits', []):
                for e in h.get('email', []):
                    nuevos.append({'tipo': 'email', 'valor': e})
        
        return nuevos
