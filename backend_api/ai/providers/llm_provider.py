async def analyze(data: dict) -> dict:
    # In a real impl, this would call OpenAI/Anthropic
    # For now, it just reuses the mock return to avoid errors if switched
    from .mock_provider import analyze as mock_analyze
    return await mock_analyze(data)
