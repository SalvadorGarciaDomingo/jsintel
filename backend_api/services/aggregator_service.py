from backend_api.services.scoring_service import calculate_risk
from backend_api.services.external_apis import github_service, deepweb_service, whois_service
import asyncio

async def run_osint_scan(query: str, type_hint: str = None):
    """
    Orchestrates the OSINT scanning process.
    1. Detects type (if not provided)
    2. Calls relevant external APIs in parallel
    3. Aggregates results
    4. Calculates risk score
    """
    detected_type = type_hint or _detect_type(query)
    
    # Define tasks based on type
    tasks = []
    
    # Global checks
    tasks.append(deepweb_service.check_deepweb(query))
    
    if detected_type == "username":
        tasks.append(github_service.search_user(query))
    elif detected_type == "domain":
        tasks.append(whois_service.get_whois(query))
    
    # Run in parallel
    results_list = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Aggregate
    agg_results = {
        "deepweb": results_list[0] if not isinstance(results_list[0], Exception) else {"error": str(results_list[0])},
        # Add other results mapping here
    }
    
    if detected_type == "username":
        agg_results["github"] = results_list[1] if len(results_list) > 1 else {}
    elif detected_type == "domain":
        agg_results["whois"] = results_list[1] if len(results_list) > 1 else {}

    # Scoring
    risk_score = calculate_risk(agg_results)
    
    return agg_results, risk_score, detected_type

def _detect_type(query: str) -> str:
    if "@" in query: return "email"
    if "." in query and not query.replace(".", "").isdigit(): return "domain"
    if query.replace(".", "").isdigit(): return "ip"
    return "username"
