from backend_api.core.config import get_settings
from backend_api.ai.providers import mock_provider, llm_provider

settings = get_settings()

async def generate_analysis(data: dict) -> dict:
    """
    Generates AI analysis for the given data.
    Selects provider based on config.
    """
    provider = settings.AI_PROVIDER
    
    if provider == "mock":
        return await mock_provider.analyze(data)
    else:
        # Fallback to LLM provider (not fully implemented in this demo)
        return await llm_provider.analyze(data)
