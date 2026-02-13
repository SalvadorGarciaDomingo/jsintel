def calculate_risk(results: dict) -> int:
    """
    Calculates a risk score (0-100) based on findings.
    """
    score = 0
    
    # Deep Web findings are critical
    deepweb = results.get("deepweb", {})
    if deepweb.get("found", False):
        score += 50
    
    # Example: GitHub exposure
    github = results.get("github", {})
    if github.get("total_count", 0) > 0:
        score += 10
        
    return min(score, 100)
