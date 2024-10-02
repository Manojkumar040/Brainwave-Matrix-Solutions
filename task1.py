import re

# Default list of common phishing keywords
default_phishing_keywords = ["login", "verify", "account", "update", "secure", "bank", "password", "signin", "confirm", "0"]

# Function to check if a URL contains phishing keywords
def contains_phishing_keywords(url, keywords):
    return any(keyword in url.lower() for keyword in keywords)

# Function to check if a URL contains suspicious patterns 
def contains_suspicious_patterns(url):
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    subdomain_pattern = re.compile(r'^(?:[a-z0-9-]+\.){2,}[a-z]{2,}$')
    return bool(ip_pattern.search(url)) or bool(subdomain_pattern.search(url))

# Main function to scan a list of URLs for phishing
def scan_for_phishing(urls, keywords=None):
    if keywords is None:
        keywords = default_phishing_keywords
    results = []
    for url in urls:
        normalized_url = url.strip().lower().rstrip('/')
        if contains_phishing_keywords(normalized_url, keywords):
            results.append(f"Potential phishing URL detected: {normalized_url}")
        elif contains_suspicious_patterns(normalized_url):
            results.append(f"Suspicious URL detected: {normalized_url}")
        else:
            results.append(f"URL seems safe: {normalized_url}")
    return results

# Example usage
urls_to_scan = [
    "http://example.com",
    "https://chatgpt.com",
    "https://www.youtube.com",
    "https://www.facebook.com",
    "http://login-bank.com",
    "http://192.168.1.1",
    "https://www.blackbox.ai",
    "https://www.drdo.gov.in/drdo/",
    "http://secure-login.example.com",
    "http://update-password.com",
    "http://google.com",
    "https://www.perplexity.ai",
    "http://examples.com"

]

scan_results = scan_for_phishing(urls_to_scan)
for result in scan_results:
    print(result)