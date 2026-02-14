import requests
from typing import Dict, Any
import re
from datetime import datetime
from backend_api.core.config import settings

class ServicioDiscord:
    API_BASE = "https://discord.com/api/v10"

    def __init__(self):
        self.headers = {
            'User-Agent': 'SJ_OSINT_Bot/1.0',
            'Content-Type': 'application/json'
        }
        if settings.DISCORD_BOT_TOKEN:
            self.headers['Authorization'] = f'Bot {settings.DISCORD_BOT_TOKEN}'

    def analizar_invitacion(self, invite_link: str) -> Dict[str, Any]:
        match = re.search(r'discord(?:\.gg|app\.com/invite)/([a-zA-Z0-9-]+)', invite_link)
        if not match: return {"exito": False, "error": "Enlace inválido"}
        
        code = match.group(1)
        try:
            resp = requests.get(f"{self.API_BASE}/invites/{code}?with_counts=true", headers=self.headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                guild = data.get('guild', {})
                return {
                    "exito": True,
                    "tipo": "SERVIDOR",
                    "datos": {
                        "nombre": guild.get('name'),
                        "id": guild.get('id'),
                        "miembros": data.get('approximate_member_count'),
                        "online": data.get('approximate_presence_count'),
                        "invitador": data.get('inviter', {}).get('username')
                    }
                }
            return {"exito": False, "error": f"API Error {resp.status_code}"}
        except Exception as e: return {"exito": False, "error": str(e)}

    def analizar_usuario_id(self, user_id: str) -> Dict[str, Any]:
        if not user_id.isdigit(): return {"exito": False, "error": "ID no numérico"}
        
        # Calculate creation date from Snowflake
        timestamp_ms = ((int(user_id) >> 22) + 1420070400000)
        created_at = datetime.fromtimestamp(timestamp_ms / 1000).strftime('%Y-%m-%d %H:%M:%S')

        # Try API if token exists
        if settings.DISCORD_BOT_TOKEN:
            try:
                resp = requests.get(f"{self.API_BASE}/users/{user_id}", headers=self.headers, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "exito": True,
                        "tipo": "USUARIO_ID",
                        "datos": {
                            "id": user_id,
                            "username": data.get('username'),
                            "global_name": data.get('global_name'),
                            "avatar_url": f"https://cdn.discordapp.com/avatars/{user_id}/{data.get('avatar')}.png" if data.get('avatar') else None,
                            "fecha_creacion": created_at,
                            "es_bot": data.get('bot', False)
                        }
                    }
            except: pass

        return {
            "exito": True,
            "tipo": "USUARIO_ID",
            "datos": {
                "id": user_id,
                "fecha_creacion": created_at,
                "fuente": "CALCULO_SNOWFLAKE"
            },
            "advertencia": "Datos limitados (Sin Token de Bot)"
        }

    def analizar_usuario(self, username: str) -> Dict[str, Any]:
        # Fallback to search links since username search requires context
        return {
            "exito": True,
            "tipo": "USUARIO_USERNAME",
            "datos": {
                "username": username,
                "dorks": [
                    {"nombre": "Google", "url": f"https://www.google.com/search?q=\"{username}\" site:discord.com"},
                    {"nombre": "BreachDirectory", "url": f"https://breachdirectory.org/search?query={username}"}
                ]
            }
        }
