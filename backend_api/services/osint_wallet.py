import re
from typing import Dict, Any

class ServicioWallet:
    # Validación simple de direcciones BTC/ETH usando expresiones regulares
    PATRONES = {
        "BTC": r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$",
        "ETH": r"^0x[a-fA-F0-9]{40}$"
    }

    def analizar(self, wallet: str) -> Dict[str, Any]:
        # Detecta el tipo por patrón y construye el enlace al explorador
        wallet = wallet.strip()
        tipo = None
        for t, p in self.PATRONES.items():
            if re.match(p, wallet):
                tipo = t
                break
        
        datos = {"address": wallet, "tipo": tipo or "Desconocido", "valido": bool(tipo)}
        if tipo == "BTC":
            datos["explorer"] = f"https://www.blockchain.com/explorer/addresses/btc/{wallet}"
        elif tipo == "ETH":
            datos["explorer"] = f"https://etherscan.io/address/{wallet}"

        return {"exito": True, "datos": datos}
