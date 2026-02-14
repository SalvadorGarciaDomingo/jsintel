from typing import Dict, Any, List, Optional

class ServicioGeolocalizacion:
    """
    Servicio para extraer y correlacionar información de geolocalización.
    """
    def __init__(self):
        # Simplified dictionary for production parity
        self.geocoding_dict = {
            "madrid": (40.4168, -3.7038),
            "barcelona": (41.3851, 2.1734),
            "london": (51.5074, -0.1278),
            "new york": (40.7128, -74.0060),
            "spain": (40.4168, -3.7038),
            "usa": (38.8951, -77.0364)
            # Add more as needed or load from external resource
        }

    def correlacionar_geopuntos(self, resultados_osint: Dict[str, Any]) -> List[Dict[str, Any]]:
        geopuntos = []
        elementos = resultados_osint.get('desglose', [])
        
        # Add root items
        if resultados_osint.get('ip'): elementos.append(resultados_osint['ip'])
        
        for item in elementos:
            if not item.get('exito'): continue
            datos = item.get('datos', {})
            tipo = item.get('tipo')

            if tipo == 'ip':
                # Simplified Extraction
                lat = datos.get('latitud') or datos.get('lat')
                lon = datos.get('longitud') or datos.get('lon')
                if lat and lon:
                    geopuntos.append({
                        "lat": float(lat), "lon": float(lon),
                        "label": f"IP: {datos.get('ip')}",
                        "tipo": "ip"
                    })
            
            elif tipo == 'image' and 'gps' in datos and datos['gps']:
                 gps = datos['gps']
                 geopuntos.append({
                     "lat": gps['lat'], "lon": gps['lon'],
                     "label": "Metadatos Imagen",
                     "tipo": "imagen"
                 })
                 
        return geopuntos
