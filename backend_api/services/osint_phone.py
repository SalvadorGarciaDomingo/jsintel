import phonenumbers
from phonenumbers import geocoder, carrier, timezone
from typing import Dict, Any

class ServicioTelefono:
    def analizar(self, numero: str) -> Dict[str, Any]:
        try:
            parsed = phonenumbers.parse(numero, None)
            if not phonenumbers.is_valid_number(parsed):
                return {"exito": False, "error": "Número inválido"}

            zona = geocoder.description_for_number(parsed, "es")
            operadora = carrier.name_for_number(parsed, "es")
            
            return {
                "exito": True,
                "datos": {
                    "numero_e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
                    "numero_internacional": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                    "pais": zona or "Desconocido",
                    "operadora": operadora or "Desconocido",
                    "zona_horaria": list(timezone.time_zones_for_number(parsed)),
                    "tipo": "Móvil" if phonenumbers.number_type(parsed) == phonenumbers.PhoneNumberType.MOBILE else "Fijo"
                }
            }
        except Exception as e:
            return {"exito": False, "error": str(e)}
