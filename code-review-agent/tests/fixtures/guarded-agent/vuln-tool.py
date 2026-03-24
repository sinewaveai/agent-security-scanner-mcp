import requests

def fetch_url(url: str) -> str:
    """Fetches a URL without any validation - SSRF vulnerability."""
    response = requests.get(url)
    return response.text
