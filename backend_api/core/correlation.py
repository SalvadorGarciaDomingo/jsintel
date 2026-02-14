from typing import Dict, Any, List

class Correlador:
    def correlacionar(self, datos_osint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Genera correlaciones basadas en los datos recolectados.
        Soporta correlación cruzada de múltiples identificadores (todos contra todos).
        """
        correlaciones = []
        elementos = datos_osint.get('desglose', [])
        
        if not elementos:
            # Fallback legacy
            return []

        # 1. Análisis Individual (Insights por elemento)
        for item in elementos:
            self._analizar_individual(item, correlaciones)

        # 2. Correlación Todos vs Todos (O(N^2))
        procesados = set()
        
        for i, item_a in enumerate(elementos):
            for item_b in elementos[i+1:]:
                if item_a is item_b: continue
                
                key_pair = frozenset([str(item_a.get('input')), str(item_b.get('input'))])
                if key_pair in procesados: continue
                procesados.add(key_pair)
                
                self._cruzar_elementos(item_a, item_b, correlaciones)

        return correlaciones

    def _analizar_individual(self, item: Dict[str, Any], lista_corr: List[Dict[str, Any]]):
        """Genera insights basados en un solo item."""
        t = item.get('tipo')
        d = item.get('datos', {})
        cti = item.get('analisis_adicional', {}).get('cti_ransomware', {})
        
        # CTI Check Global
        if cti and cti.get('en_lista_victimas'):
             lista_corr.append({
                "tipo": "AMENAZA_CRITICA",
                "relacion": f"Identificador Comprometido ({t.upper()})",
                "descripcion": f"El objetivo '{item.get('input')}' figura en listas de víctimas de Ransomware.",
                "nivel": "Crítica"
            })

        # CTI Check VirusTotal
        vt = item.get('analisis_adicional', {}).get('virustotal', {})
        malicious_count = vt.get('malicioso', 0)
        
        if malicious_count > 0:
             engines = [d['motor'] for d in vt.get('detectores_positivos', [])[:3]]
             engine_str = ", ".join(engines)
             lista_corr.append({
                "tipo": "MALWARE_DETECTADO",
                "relacion": f"VirusTotal ({malicious_count} hits)",
                "descripcion": f"⚠️ ALERTA: El identificador '{t}' fue marcado como malicioso por {malicious_count} motores antivirus ({engine_str}).",
                "nivel": "Crítica" if malicious_count > 2 else "Alta"
            })

        # IP Specific
        if t == 'ip':
            pais = d.get('pais')
            isp = str(d.get('isp') or '') # Safety cast
            
            if pais and pais.lower() in ['russia', 'china', 'north korea', 'iran']:
                 lista_corr.append({
                    "tipo": "RIESGO_GEO",
                    "relacion": "Jurisdicción Hostil",
                    "descripcion": f"La IP {d.get('ip')} está ubicada en {pais}, zona de alto riesgo para ciberseguridad.",
                    "nivel": "Media"
                })
            if 'tor' in isp.lower() or 'vpn' in isp.lower():
                 lista_corr.append({
                    "tipo": "ANONIMIZACION",
                    "relacion": "Uso de Proxy/VPN",
                    "descripcion": f"El ISP ({isp}) sugiere el uso de redes de anonimización.",
                    "nivel": "Alta"
                })

        # Email Specific
        if t == 'email':
             if d.get('es_desechable'):
                 lista_corr.append({"tipo": "FRAUDE", "relacion": "Email Temporal", "descripcion": "Correo desechable detectado.", "nivel": "Alta"})

        # User Specific Insights
        if t == 'user' or t == 'usuario':
            perfiles = d.get('perfiles_encontrados', [])
            encontrados = [p for p in perfiles if p.get('estado') in ['Encontrado', 'Verificar Manualmente']]
            
            if len(encontrados) > 5:
                lista_corr.append({
                    "tipo": "HUELLA_DIGITAL",
                    "relacion": "Presencia Extensa",
                    "descripcion": f"👤 Alta Exposición: Se han localizado {len(encontrados)} perfiles activos. Esto facilita un perfilado exhaustivo del objetivo.",
                    "nivel": "Informativa"
                })

            # Check for real names in metadata
            nombres = set()
            for p in encontrados:
                n = p.get('metadatos', {}).get('nombre_real')
                if n: nombres.add(n)
            
            if len(nombres) > 1:
                lista_corr.append({
                    "tipo": "IDENTIDAD_MULTIPLE",
                    "relacion": "Nombres Inconsistentes",
                    "descripcion": f"⚠️ Discrepancia: El usuario utiliza diferentes nombres reales en sus redes: {', '.join(list(nombres)[:3])}. Posible uso de identidades falsas o alias.",
                    "nivel": "Media"
                })

    def _cruzar_elementos(self, a: Dict[str, Any], b: Dict[str, Any], lista_corr: List[Dict[str, Any]]):
        """Compara dos elementos y busca relaciones."""
        ta, va = a.get('tipo'), a.get('input')
        tb, vb = b.get('tipo'), b.get('input')
        
        da = a.get('datos', {})
        db = b.get('datos', {})

        # Normalizar tipos para reducir combinaciones
        # Aseguramos orden consistente: email vs domain (no domain vs email)
        if ta > tb: 
            ta, tb = tb, ta
            va, vb = vb, va
            a, b = b, a
            da, db = db, da
        
        # CASO 1: Email vs Email (Coincidencia de Dominio)
        if ta == 'email' and tb == 'email':
            dom_a = da.get('dominio')
            dom_b = db.get('dominio')
            if dom_a and dom_b and dom_a == dom_b:
                lista_corr.append({
                    "tipo": "VINCULO_ORGANIZATIVO",
                    "relacion": "Mismo Dominio de Correo",
                    "descripcion": f"💡 Análisis de Organización: Ambos correos ({va} y {vb}) operan bajo la misma empresa o entidad '{dom_a}'. Esto indica una relación laboral o institucional directa.",
                    "nivel": "Baja"
                })

        # CASO 2: Domain vs Email (Pertenencia)
        if ta == 'domain' and tb == 'email':
            email_dom = db.get('dominio', '')
            if email_dom and (email_dom == va or email_dom.endswith(f".{va}")):
                # Check si es dominio de infraestructura conocida
                INFRA_DOMAINS = ['cloudflare.com', 'akamaitechnologies.com', 'google.com', 'amazon.com', 'azure.com', 'godaddy.com']
                es_infra = any(d in str(va).lower() for d in INFRA_DOMAINS)
                
                if es_infra:
                    lista_corr.append({
                        "tipo": "DEPENDENCIA_TECNICA",
                        "relacion": "Servicio de Terceros",
                        "descripcion": f"🛠️ Infraestructura Externa: El correo {vb} ({va}) indica el uso de servicios gestionados por proveedores externos, no necesariamente personal del objetivo.",
                        "nivel": "Informativa"
                    })
                else:
                    lista_corr.append({
                        "tipo": "JERARQUIA",
                        "relacion": "Email Corporativo",
                        "descripcion": f"🔍 Estructura Corporativa: El correo {vb} utiliza el dominio {va}, lo que confirma que es una dirección oficial gestionada por dicha organización.",
                        "nivel": "Fuerte"
                    })

        # CASO 3: IP vs Domain (Resolución)
        if ta == 'domain' and tb == 'ip':
             ip_asociada = da.get('ip_asociada')
             es_waf = da.get('es_waf', False)
             bypass = da.get('bypass_exito', False)
             waf_name = da.get('waf_proveedor', 'WAF')

             if ip_asociada and ip_asociada == vb:
                 if es_waf and bypass:
                     lista_corr.append({
                        "tipo": "INFRAESTRUCTURA_CRITICA",
                        "relacion": "Bypass de WAF Exitoso",
                        "descripcion": f"🔓 WAF Evadido: Se ha descubierto la IP real ({vb}) oculta detrás de {waf_name}. Esto permite atacar directamente al servidor origen.",
                        "nivel": "Crítica"
                    })
                 elif es_waf:
                     lista_corr.append({
                        "tipo": "INFRAESTRUCTURA_PROTEGIDA",
                        "relacion": f"Protección Detectada ({waf_name})",
                        "descripcion": f"🛡️ Infraestructura Proxy: El sitio utiliza {waf_name}. La IP {vb} es solo una 'máscara' de seguridad y no el servidor real.",
                        "nivel": "Informativa"
                    })
                 else:
                     lista_corr.append({
                        "tipo": "INFRAESTRUCTURA",
                        "relacion": "Alojamiento Detectado",
                        "descripcion": f"🖥️ Infraestructura Digital: El sitio web {va} está alojado físicamente en el servidor con IP {vb}. Es su 'dirección digital' real.",
                        "nivel": "Fuerte"
                    })

        # CASO 4: User vs User (Mismo Handle)
        if ta == 'user' and tb == 'user':
            if str(va or "").lower() == str(vb or "").lower():
                 lista_corr.append({
                    "tipo": "IDENTIDAD",
                    "relacion": "Alias Reutilizado",
                    "descripcion": f"👤 Perfilado de Usuario: El alias '{va}' aparece en múltiples plataformas. Dado que es un nombre de usuario idéntico, es altamente probable que pertenezca a la misma persona.",
                    "nivel": "Media"
                })
        
        # CASO 5: User vs Email
        if ta == 'email' and tb == 'user':
             user_part = da.get('usuario')
             if user_part and str(user_part).lower() == str(vb or "").lower():
                lista_corr.append({
                    "tipo": "IDENTIDAD",
                    "relacion": "Patrón de Usuario",
                    "descripcion": f"🧩 Coincidencia de Alias: La parte inicial del correo ({user_part}) coincide exactamente con el usuario buscado ({vb}). Es común que las personas usen su nick habitual en sus correos personales.",
                    "nivel": "Media"
                })

                # ENRICHMENT: Warn about Email Compromise in User item
                email_hibp = da.get('hibp_data')
                
                if email_hibp and (email_hibp.get('found') or (email_hibp.get('email_breaches') and email_hibp['email_breaches'].get('found'))):
                     if not db.get('hibp_data'):
                         db['hibp_data'] = {'found': False, 'breaches': [], 'breaches_count': 0}
                     
                     db['hibp_data']['found'] = True
                     db['hibp_data']['derived_risk'] = True
                     db['hibp_data']['derived_via'] = va # The email address string
        
        # CASO EXTRA: Domain vs User (Para casos corporativos)
        if ta == 'domain' and tb == 'user':
            vb_clean = str(vb or "").lower().replace(" ", "")
            va_str = str(va or "").lower()
            if vb_clean and (vb_clean in va_str or va_str in vb_clean):
                 lista_corr.append({
                    "tipo": "IDENTIDAD_CORPORATIVA",
                    "relacion": "Posible Sitio Personal/Oficial",
                    "descripcion": f"🏢 Huella Corporativa: El dominio {va} contiene el nombre del usuario {vb}, sugiriendo que podría ser su página web personal, portfolio o sitio de su empresa.",
                    "nivel": "Alta"
                })

        # CASO 6: Coincidencia Geográfica (General)
        pais_a = self._extraer_pais(a)
        pais_b = self._extraer_pais(b)
        
        if pais_a and pais_b and pais_a == pais_b:
             lista_corr.append({
                    "tipo": "GEO_COINCIDENCIA",
                    "relacion": f"Coincidencia Geográfica ({pais_a})",
                    "descripcion": f"🌍 Región Común: Tanto {va} ({ta}) como {vb} ({tb}) parecen operar desde {pais_a}. Esto refuerza la posibilidad de que estén relacionados localmente.",
                    "nivel": "Baja"
             })

        # CASO 7: User vs Domain (Similarity check if not exact)
        if ta == 'user' and tb == 'domain':
            if va.lower() in vb.lower():
                lista_corr.append({
                    "tipo": "INFRAESTRUCTURA_PERSONAL",
                    "relacion": "Dominio Relacionado",
                    "descripcion": f"🌐 El usuario {va} aparece contenido en el dominio {vb}. Es probable que sea su sitio web oficial o de su propiedad.",
                    "nivel": "Media"
                })

    def _extraer_pais(self, item):
        d = item.get('datos', {})
        t = item.get('tipo')
        if t == 'ip': return d.get('pais')
        if t == 'phone': return d.get('pais')
        if t == 'user' or t == 'usuario':
            perfiles = d.get('perfiles_encontrados', [])
            for p in perfiles:
                loc_raw = p.get('metadatos', {}).get('ubicacion')
                loc = str(loc_raw).lower() if loc_raw else ""
                
                if not loc: continue
                if 'spain' in loc or 'españa' in loc: return 'Spain'
                if 'usa' in loc or 'united states' in loc or 'eeuu' in loc: return 'United States'
                if 'uk' in loc or 'united kingdom' in loc: return 'United Kingdom'
                if 'france' in loc or 'francia' in loc: return 'France'
                if 'germany' in loc or 'alemania' in loc: return 'Germany'
                if 'russia' in loc or 'rusia' in loc: return 'Russia'
                if 'china' in loc: return 'China'
                if 'brazil' in loc or 'brasil' in loc: return 'Brazil'
        return None
