async def search_user(username: str) -> dict:
    # Mock response for demo
    return {
        "platform": "github",
        "username": username,
        "total_count": 1,
        "items": [
            {"html_url": f"https://github.com/{username}", "description": "Mock Profile"}
        ]
    }
