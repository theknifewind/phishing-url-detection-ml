"""
URL feature extraction for phishing detection.
Extracts 19 URL-based features without fetching webpage content.
"""
import re
from urllib.parse import urlparse
from difflib import SequenceMatcher

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

# Feature extraction constants
COMMON_LEGIT_TLDS = {
    "com": 0.9, "org": 0.85, "net": 0.8, "edu": 0.95, "gov": 0.97,
    "co": 0.7, "uk": 0.8, "de": 0.75, "fr": 0.75, "ca": 0.8
}

SUSPICIOUS_TLDS = {"xyz", "tk", "ml", "ga", "cf", "ru", "cn", "top", "gq", "pw"}

BRANDS = [
    "paypal", "google", "facebook", "amazon", "instagram", "bank",
    "sbi", "hdfc", "icici", "apple", "microsoft", "netflix", "ebay",
    "myntra", "flipkart", "wikipedia", "github", "linkedin", "twitter"
]

PHISHING_KEYWORDS = ["login", "secure", "account", "verify", "bank", "update", "confirm"]

# Feature order expected by the trained model (19 features)
FEATURE_ORDER = [
    "URLLength", "DomainLength", "IsDomainIP", "URLSimilarityIndex",
    "CharContinuationRate", "TLDLegitimateProb", "HasBrandName", "HyphenCount",
    "SuspiciousTLD", "HasHTTPS", "TrustedBrandOnHTTP", "SubdomainLevel",
    "PathLength", "PathDepth", "DigitCount", "SpecialCharCount",
    "HasAtSymbol", "DoubleSlashRedirecting", "PrefixSuffix"
]


def simple_tld_extract(url: str) -> dict:
    """Fallback TLD extraction if tldextract is not available."""
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split('/')[0]
    domain = domain.split(':')[0]
    parts = domain.split('.')

    if len(parts) >= 2:
        return {
            'domain': parts[-2],
            'suffix': parts[-1],
            'subdomain': '.'.join(parts[:-2]) if len(parts) > 2 else ''
        }
    return {'domain': domain, 'suffix': '', 'subdomain': ''}


def _normalize_url(url: str) -> str:
    """Normalize URL so trailing slash doesn't change features (same resource)."""
    url = url.strip()
    parsed = urlparse(url)
    # Strip trailing slash when path is exactly "/" (equiv to no path)
    if parsed.path == "/" and not parsed.query and not parsed.fragment:
        url = url.rstrip("/")
    return url


def extract_features(url: str) -> dict:
    """
    Extract URL-based features for phishing detection.
    Returns 19 features that can be extracted without fetching the webpage.
    """
    if not url or not isinstance(url, str):
        url = str(url) if url else ""

    url = _normalize_url(url)

    # Parse URL
    if HAS_TLDEXTRACT:
        ext = tldextract.extract(url)
        domain = ext.domain
        tld = ext.suffix.lower()
        subdomain = ext.subdomain
    else:
        ext_dict = simple_tld_extract(url)
        domain = ext_dict['domain']
        tld = ext_dict['suffix'].lower()
        subdomain = ext_dict['subdomain']

    parsed = urlparse(url)

    # Character repetition
    repeated_chars = sum(1 for i in range(1, len(url)) if url[i] == url[i - 1])

    # Similarity to phishing keywords
    max_similarity = max(
        SequenceMatcher(None, url.lower(), kw).ratio()
        for kw in PHISHING_KEYWORDS
    )
    url_similarity_index = max_similarity * 100

    # Protocol check
    has_https = 1 if parsed.scheme == "https" else 0

    # Subdomain analysis
    subdomain_count = len(subdomain.split('.')) if subdomain else 0

    # Character analysis
    digit_count = sum(c.isdigit() for c in url)
    special_char_count = sum(c in "@?=-_&" for c in url)

    # IP address check
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain))

    # Path analysis
    path_length = len(parsed.path) if parsed.path else 0
    path_depth = parsed.path.count('/') if parsed.path else 0

    # Suspicious patterns
    has_at_symbol = 1 if '@' in url else 0
    double_slash_redirecting = 1 if url.count('//') > 1 else 0

    # Known brand check
    has_brand = int(any(b in domain.lower() for b in BRANDS))
    
    # FIXED: TrustedBrandOnHTTP - only flag suspicious subdomain usage
    # Legitimate brand domains like amazon.com should NOT be flagged
    has_suspicious_subdomain = subdomain and any(b in subdomain.lower() for b in BRANDS)
    trusted_brand_on_http = 1 if (has_suspicious_subdomain and has_https == 0) else 0

    return {
        "URLLength": len(url),
        "DomainLength": len(domain),
        "IsDomainIP": int(is_ip),
        "URLSimilarityIndex": url_similarity_index,
        "CharContinuationRate": repeated_chars / max(len(url), 1),
        "TLDLegitimateProb": COMMON_LEGIT_TLDS.get(tld, 0.05),
        "HasBrandName": has_brand,
        "HyphenCount": domain.count("-"),
        "SuspiciousTLD": int(tld in SUSPICIOUS_TLDS),
        "HasHTTPS": has_https,
        "TrustedBrandOnHTTP": trusted_brand_on_http,
        "SubdomainLevel": subdomain_count,
        "PathLength": path_length,
        "PathDepth": path_depth,
        "DigitCount": digit_count,
        "SpecialCharCount": special_char_count,
        "HasAtSymbol": has_at_symbol,
        "DoubleSlashRedirecting": double_slash_redirecting,
        "PrefixSuffix": 1 if '-' in domain else 0,
    }