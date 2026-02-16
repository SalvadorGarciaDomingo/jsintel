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

    def analizar_archivo(self, ruta_archivo: str) -> Dict[str, Any]:
        try:
            import os, hashlib
            stat = os.stat(ruta_archivo)
            nombre = os.path.basename(ruta_archivo)
            ext = os.path.splitext(nombre)[1].lower()
            datos = {
                "nombre": nombre,
                "tamano_bytes": stat.st_size,
                "extension": ext or ''
            }
            sha256 = None
            md5 = None
            try:
                h_sha = hashlib.sha256()
                h_md5 = hashlib.md5()
                with open(ruta_archivo, "rb") as f:
                    while True:
                        chunk = f.read(8192)
                        if not chunk: break
                        h_sha.update(chunk)
                        h_md5.update(chunk)
                sha256 = h_sha.hexdigest()
                md5 = h_md5.hexdigest()
                datos["sha256"] = sha256
                datos["md5"] = md5
            except: pass
            if ext == '.exe':
                tipo = 'exe'
                try:
                    with open(ruta_archivo, "rb") as f:
                        mz = f.read(2)
                        f.seek(0x3C)
                        pe_off = int.from_bytes(f.read(4), 'little')
                        f.seek(pe_off)
                        pe_sig = f.read(4)
                    datos["es_pe"] = (mz == b'MZ' and pe_sig == b'PE\x00\x00')
                except:
                    datos["es_pe"] = False
            else:
                tipo = 'documento'
            datos["tipo_archivo"] = tipo
            return {"exito": True, "datos": datos}
        except Exception as e:
            return {"exito": False, "error": str(e)}
