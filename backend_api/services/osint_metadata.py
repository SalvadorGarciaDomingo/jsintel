from typing import Dict, Any
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
# from docx import Document # Removed as dependency might not be critical, or can be added if requested. Keeping consistent with previous file, let's keep it if possible but simple.
# Actually let's assume standard deps. The original file imported docx.

class ServicioMetadatos:
    def analizar_imagen(self, ruta_archivo: str) -> Dict[str, Any]:
        # Reuse logic or separate? keeping separate for parity
        try:
            img = Image.open(ruta_archivo)
            exif_data = img._getexif()
            meta = {"formato": img.format, "exif": {}}
            
            if exif_data:
                for t, v in exif_data.items():
                    tag = TAGS.get(t, t)
                    if tag != "GPSInfo" and not isinstance(v, bytes):
                        meta["exif"][tag] = str(v)
            return {"exito": True, "datos": meta}
        except Exception as e: return {"exito": False, "error": str(e)}

    # Skipping DOCX for now to minimal dependencies unless critically requested, or I can add a placeholder.
    # The user wanted 1:1 parity. I will add a safe import.
    def analizar_docx(self, ruta_archivo: str) -> Dict[str, Any]:
        try:
            from docx import Document
            doc = Document(ruta_archivo)
            prop = doc.core_properties
            return {
                "exito": True,
                "datos": {
                    "titulo": prop.title,
                    "autor": prop.author,
                    "creado": str(prop.created),
                    "modificado": str(prop.modified)
                }
            }
        except ImportError:
            return {"exito": False, "error": "python-docx no instalado"}
        except Exception as e:
            return {"exito": False, "error": str(e)}
