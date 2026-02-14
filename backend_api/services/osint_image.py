from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from typing import Dict, Any, Optional

class ServicioImagen:
    def analizar(self, ruta_imagen: str) -> Dict[str, Any]:
        try:
            with Image.open(ruta_imagen) as img:
                info = {
                    "exito": True,
                    "datos": {
                        "formato": img.format,
                        "tamano": img.size,
                        "exif": {},
                        "gps": None
                    }
                }
                
                exif_data = img._getexif()
                if exif_data:
                    for tag, value in exif_data.items():
                        tag_name = TAGS.get(tag, tag)
                        if tag_name == "GPSInfo":
                            info["datos"]["gps"] = self._extraer_gps(value)
                        elif not isinstance(value, bytes):
                            info["datos"]["exif"][tag_name] = str(value)
                return info
        except Exception as e:
            return {"exito": False, "error": str(e)}

    def _extraer_gps(self, gps_info: Dict) -> Optional[Dict[str, float]]:
        try:
            def to_decimal(values, ref):
                d, m, s = [float(x) for x in values]
                res = d + (m / 60.0) + (s / 3600.0)
                return -res if ref in ['S', 'W'] else res

            if 'GPSLatitude' in gps_info and 'GPSLongitude' in gps_info:
                lat = to_decimal(gps_info['GPSLatitude'], gps_info.get('GPSLatitudeRef', 'N'))
                lon = to_decimal(gps_info['GPSLongitude'], gps_info.get('GPSLongitudeRef', 'E'))
                return {"lat": lat, "lon": lon}
        except: pass
        return None
