async def get_whois(domain: str) -> dict:
    return {
        "domain": domain,
        "registrar": "Mock Registrar, LLC",
        "creation_date": "2020-01-01"
    }
