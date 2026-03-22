import re
import math
import socket
import ssl
import time
import requests
import whois
from urllib.parse import urlparse
from datetime import datetime, timedelta
from typing import Tuple, List, Dict, Optional

# ── ANSI colour helpers ────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def red(t):    return f"{RED}{t}{RESET}"
def green(t):  return f"{GREEN}{t}{RESET}"
def yellow(t): return f"{YELLOW}{t}{RESET}"
def cyan(t):   return f"{CYAN}{t}{RESET}"
def bold(t):   return f"{BOLD}{t}{RESET}"

# ── Configuration ──────────────────────────────────────────────────────────────
VT_API_KEY = "d82a3ac86567805221b92cc46ccdcd8b6c80e340768eb51c59f10159ec950151"

# Suspicious/temporary hosting services (often used for phishing)
SUSPICIOUS_HOSTS = [
    "trycloudflare.com", "ngrok.io", "serveo.net", "localtunnel.me",
    "pages.dev", "github.io", "herokuapp.com", "netlify.app",
    "vercel.app", "replit.co", "glitch.me", "000webhostapp.com"
]

# Popular brands for spoofing detection
BRANDS = [
    "google", "facebook", "paypal", "amazon", "microsoft", "apple",
    "netflix", "instagram", "twitter", "linkedin", "bank", "chase",
    "wellsfargo", "paytm", "ebay", "aliexpress", "dropbox", "spotify"
]

# Sensitive keywords for URL detection
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "banking",
    "confirm", "password", "paypal", "amazon", "apple", "microsoft",
    "support", "alert", "suspended", "unlock", "ebay", "invoice",
    "signin", "authenticate", "validation", "security", "credential"
]

# ── 1. URL Extraction ──────────────────────────────────────────────────────────
def extract_urls(text: str) -> List[str]:
    """Extract all http/https URLs from free text."""
    pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2})|[/?=#&@!$\'()*+,;:~%-])+'
    return list(set(re.findall(pattern, text)))

# ── 2. Enhanced Suspicious Pattern Detection ────────────────────────────────
def check_url_patterns(url: str) -> Tuple[List[str], int]:
    """Check URL for suspicious patterns and return warnings + risk score."""
    warnings = []
    risk_score = 0
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    # Sensitive keywords anywhere in the URL
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in domain or kw in path:
            warnings.append(f"Suspicious keyword '{kw}' found in URL.")
            risk_score += 20
            break

    # Raw IP address instead of domain
    if re.match(r'https?://\d{1,3}(\.\d{1,3}){3}', url):
        warnings.append("IP-based URL (no domain name).")
        risk_score += 30

    # Excessive subdomains (>3 labels before TLD)
    labels = domain.split(".")
    if len(labels) > 4:
        warnings.append(f"Excessive subdomains ({len(labels) - 2} levels).")
        risk_score += 15

    # Special characters often used in spoofing
    if re.search(r'[@%]', domain):
        warnings.append("Special character (@ or %) in domain.")
        risk_score += 25

    # Homograph / typosquatting heuristic — long domain name
    base = labels[-2] if len(labels) >= 2 else domain
    if len(base) > 20:
        warnings.append(f"Unusually long domain name ({len(base)} chars).")
        risk_score += 10

    # High entropy → randomly generated domain
    entropy = _shannon_entropy(base)
    if entropy > 3.8:
        warnings.append(f"High domain entropy ({entropy:.2f}) — may be auto-generated.")
        risk_score += 20

    # URL shorteners
    shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
                  "buff.ly", "is.gd", "rb.gy", "shorturl.at"}
    if domain in shorteners:
        warnings.append("URL shortener detected — destination unknown.")
        risk_score += 25

    # SUSPICIOUS HOSTING DETECTION (NEW)
    for host in SUSPICIOUS_HOSTS:
        if host in domain:
            warnings.append(f"⚠️ Temporary hosting service detected ({host}) — often used for phishing.")
            risk_score += 50
            break

    # BRAND SPOOFING DETECTION (NEW)
    for brand in BRANDS:
        if brand in domain and not domain.endswith(f"{brand}.com") and not domain.endswith(f"{brand}.org"):
            # Check if it's a legitimate subdomain (like login.google.com)
            if not (f".{brand}." in domain or domain.startswith(f"{brand}.")):
                warnings.append(f"⚠️ Possible brand spoofing: '{brand}' in domain but not official domain.")
                risk_score += 40
                break

    return warnings, risk_score

def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())

# ── 3. DNS Resolution ──────────────────────────────────────────────────────────
def check_dns(url: str) -> Tuple[str, int]:
    try:
        domain = urlparse(url).netloc.split(":")[0]
        ip = socket.gethostbyname(domain)
        return f"Resolved to {ip}", 0
    except socket.gaierror:
        return "DNS resolution failed — domain may not exist.", 30

# ── 4. Fixed SSL Certificate Validation ─────────────────────────────────────
def check_ssl(url: str) -> Tuple[str, int]:
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc.split(":")[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(item[0] for item in cert["issuer"])
                issued_by = issuer.get("organizationName", "Unknown Issuer")  # FIXED
                
                # Check certificate expiry
                not_after = cert.get("notAfter", "")
                exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z") if not_after else None
                days_left = (exp_date - datetime.utcnow()).days if exp_date else None
                
                risk = 0
                expiry_str = f", expires in {days_left} day(s)" if days_left is not None else ""
                
                if days_left is not None and days_left < 15:
                    risk = 20
                    return f"SSL by {issued_by}{expiry_str} ⚠ expiring soon!", risk
                elif days_left is not None and days_left < 7:
                    risk = 40
                    return f"SSL by {issued_by}{expiry_str} 🔥 CRITICAL — expiring very soon!", risk
                
                return f"SSL by '{issued_by}'{expiry_str}", 0
                
    except ssl.SSLCertVerificationError:
        return "SSL certificate INVALID or self-signed.", 50
    except Exception as e:
        return f"SSL check error: {e}", 30

# ── 5. HTTP Redirect Chain ─────────────────────────────────────────────────────
def check_redirects(url: str) -> Tuple[str, int]:
    """Follow redirects and flag if final destination differs significantly."""
    try:
        resp = requests.get(url, allow_redirects=True, timeout=8,
                           headers={"User-Agent": "Mozilla/5.0"})
        final_url = resp.url
        hops = len(resp.history)
        risk = 0
        
        if hops == 0:
            return f"No redirects. Status {resp.status_code}.", 0
            
        original_domain = urlparse(url).netloc
        final_domain = urlparse(final_url).netloc
        cross_domain = original_domain != final_domain
        
        if cross_domain:
            risk = 25
            msg = f"{hops} redirect(s) → {final_url} ⚠ cross-domain redirect!"
        else:
            msg = f"{hops} redirect(s) → {final_url} (same domain)"
        
        # Multiple redirects increase risk
        if hops > 2:
            risk += 10
            
        return msg, risk
        
    except requests.exceptions.Timeout:
        return "Request timed out.", 30
    except Exception as e:
        return f"Redirect check failed: {e}", 20

# ── 6. WHOIS Domain Age Check (NEW) ─────────────────────────────────────────
def check_domain_age(url: str) -> Tuple[str, int]:
    """Check domain age - new domains are suspicious."""
    try:
        domain = urlparse(url).netloc.split(":")[0]
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (datetime.now() - creation_date).days
            risk = 0
            
            if age_days < 7:
                risk = 60
                return f"🔥 Domain is BRAND NEW ({age_days} days old) — HIGH RISK!", risk
            elif age_days < 30:
                risk = 40
                return f"⚠️ Domain is very new ({age_days} days old) — suspicious.", risk
            elif age_days < 90:
                risk = 15
                return f"Domain is relatively new ({age_days} days old).", risk
            else:
                return f"Domain age: {age_days} days — established.", 0
        else:
            return "WHOIS lookup incomplete.", 15
            
    except Exception as e:
        return f"WHOIS lookup failed: {str(e)[:50]}", 20

# ── 7. Page Content Scanning (NEW - GAME CHANGER) ───────────────────────────
def check_page_content(url: str) -> Tuple[str, int]:
    """Scan page content for phishing indicators."""
    try:
        r = requests.get(url, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
        text = r.text.lower()
        
        # Sensitive keywords in page
        sensitive_keywords = [
            "login", "password", "verify", "account", "credit card",
            "ssn", "social security", "bank account", "routing number",
            "username", "sign in", "authenticate", "validate", "security code"
        ]
        
        found = [k for k in sensitive_keywords if k in text]
        risk = 0
        
        if found:
            risk = min(40, len(found) * 10)  # Max 40 points from content
            return f"⚠️ Page contains sensitive keywords: {', '.join(found[:5])}", risk
        
        # Check for fake login forms
        if "form" in text and ("password" in text or "login" in text):
            risk = 20
            return "Page contains a form requesting sensitive information.", risk
            
        return "No suspicious content detected.", 0
        
    except requests.exceptions.Timeout:
        return "Content scan timeout.", 15
    except Exception as e:
        return f"Content scan failed: {e}", 10

# ── 8. VirusTotal Integration ───────────────────────────────────────────────
def check_virustotal(url: str, api_key: str = VT_API_KEY) -> Tuple[str, int]:
    """Submit URL and poll for analysis results."""
    headers = {"x-apikey": api_key}
    submit = "https://www.virustotal.com/api/v3/urls"
    try:
        # Step 1 — Submit
        r = requests.post(submit, headers=headers, json={"url": url}, timeout=10)
        if r.status_code != 200:
            return f"VT submission failed (HTTP {r.status_code}).", 20
        analysis_id = r.json()["data"]["id"]

        # Step 2 — Poll (up to 20 s)
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for _ in range(4):
            time.sleep(5)
            rp = requests.get(report_url, headers=headers, timeout=10)
            if rp.status_code == 200:
                stats = rp.json()["data"]["attributes"]["stats"]
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total = malicious + suspicious + harmless + undetected
                
                msg = f"VT: {malicious} malicious, {suspicious} suspicious / {total} engines"
                
                # Risk scoring based on VT results
                risk = 0
                if malicious > 0:
                    risk = 70 + min(30, malicious * 5)
                elif suspicious > 2:
                    risk = 50
                elif suspicious > 0:
                    risk = 30
                    
                return msg, risk
                
        return "VT analysis timed out — check manually.", 15
        
    except Exception as e:
        return f"VirusTotal error: {e}", 10

# ── 9. Comprehensive Scan with Risk Scoring ─────────────────────────────────
def scan_url(url: str, vt_api_key: str = VT_API_KEY) -> Dict:
    print(f"\n{bold(cyan('━' * 60))}")
    print(f"  {bold('Scanning:')} {url}")
    print(f"{bold(cyan('━' * 60))}")

    results = {}
    total_risk = 0
    risk_breakdown = []

    # 2a. Pattern analysis
    pattern_warnings, pattern_risk = check_url_patterns(url)
    results["Patterns"] = pattern_warnings if pattern_warnings else ["No suspicious patterns."]
    total_risk += pattern_risk
    risk_breakdown.append(("URL Pattern", pattern_risk))

    # 3. DNS
    dns_msg, dns_risk = check_dns(url)
    results["DNS"] = dns_msg
    total_risk += dns_risk
    risk_breakdown.append(("DNS", dns_risk))

    # 4. SSL
    ssl_msg, ssl_risk = check_ssl(url)
    results["SSL"] = ssl_msg
    total_risk += ssl_risk
    risk_breakdown.append(("SSL", ssl_risk))

    # 5. Redirects
    rdr_msg, rdr_risk = check_redirects(url)
    results["Redirects"] = rdr_msg
    total_risk += rdr_risk
    risk_breakdown.append(("Redirects", rdr_risk))

    # 6. WHOIS Domain Age (NEW)
    age_msg, age_risk = check_domain_age(url)
    results["Domain Age"] = age_msg
    total_risk += age_risk
    risk_breakdown.append(("Domain Age", age_risk))

    # 7. Page Content (NEW)
    content_msg, content_risk = check_page_content(url)
    results["Page Content"] = content_msg
    total_risk += content_risk
    risk_breakdown.append(("Page Content", content_risk))

    # 8. VirusTotal
    vt_msg, vt_risk = check_virustotal(url, vt_api_key)
    results["VirusTotal"] = vt_msg
    total_risk += vt_risk
    risk_breakdown.append(("VirusTotal", vt_risk))

    # Store risk info
    results["_risk_score"] = total_risk
    results["_risk_breakdown"] = risk_breakdown

    # Enhanced verdict based on risk score
    if total_risk >= 80:
        results["Verdict"] = red("⛔  CRITICAL RISK — Definitely Phishing!")
    elif total_risk >= 50:
        results["Verdict"] = red("⛔  HIGH RISK — Likely Phishing!")
    elif total_risk >= 30:
        results["Verdict"] = yellow("⚠️  MEDIUM RISK — Suspicious, proceed with caution.")
    elif total_risk >= 15:
        results["Verdict"] = yellow("⚠️  LOW RISK — Some indicators, but may be legitimate.")
    else:
        results["Verdict"] = green("✅  SAFE — No significant issues detected.")

    # Add risk score to output
    results["Risk Score"] = f"{total_risk}/100"
    
    # Force warning for suspicious hosting even if risk score is low
    if any(host in url.lower() for host in SUSPICIOUS_HOSTS):
        if total_risk < 30:
            results["Verdict"] = yellow("⚠️  SUSPICIOUS — Using temporary hosting service!")

    return results

# ── 10. Pretty Printer (Enhanced) ──────────────────────────────────────────
def print_results(results: dict) -> None:
    icons = {
        "Patterns": "🔍",
        "DNS": "🌐",
        "SSL": "🔒",
        "Redirects": "↪️",
        "Domain Age": "📅",
        "Page Content": "📄",
        "VirusTotal": "🦠",
        "Risk Score": "📊",
        "Verdict": "⚖️",
    }
    
    for key, value in results.items():
        if key.startswith("_"):
            continue
            
        icon = icons.get(key, "•")
        
        if isinstance(value, list):
            print(f"  {icon} {bold(key)}:")
            for item in value:
                # Color-code warnings
                if any(word in item.lower() for word in ["suspicious", "detected", "brand", "temporary", "high risk"]):
                    print(f"      - {red(item)}")
                elif any(word in item.lower() for word in ["new", "possible", "may be"]):
                    print(f"      - {yellow(item)}")
                else:
                    print(f"      - {item}")
        else:
            # Color-code the risk score and verdict
            if key == "Risk Score":
                score = int(value.split('/')[0])
                if score >= 50:
                    print(f"  {icon} {bold(key)}: {red(value)}")
                elif score >= 30:
                    print(f"  {icon} {bold(key)}: {yellow(value)}")
                else:
                    print(f"  {icon} {bold(key)}: {green(value)}")
            elif key == "Verdict":
                print(f"  {icon} {bold(key)}: {value}")
            else:
                # Color-code other messages based on risk indicators
                if "⚠" in str(value) or "🔥" in str(value):
                    print(f"  {icon} {bold(key)}: {yellow(value)}")
                elif "CRITICAL" in str(value) or "HIGH RISK" in str(value):
                    print(f"  {icon} {bold(key)}: {red(value)}")
                else:
                    print(f"  {icon} {bold(key)}: {value}")

# ── 11. Main Program ────────────────────────────────────────────────────────
def phishing_scanner() -> None:
    print(bold(cyan("\n╔═══════════════════════════════════════════════════╗")))
    print(bold(cyan("║   Advanced Phishing Link Scanner v3.0 🔥         ║")))
    print(bold(cyan("║   - Risk Scoring System                          ║")))
    print(bold(cyan("║   - Domain Age Check (WHOIS)                     ║")))
    print(bold(cyan("║   - Page Content Analysis                        ║")))
    print(bold(cyan("║   - Suspicious Hosting Detection                 ║")))
    print(bold(cyan("║   - Brand Spoofing Detection                     ║")))
    print(bold(cyan("╚═══════════════════════════════════════════════════╝\n")))

    # VirusTotal API key is pre-configured
    vt_key = VT_API_KEY
    print(green("✔ VirusTotal API key loaded."))
    print(yellow("ℹ New features: WHOIS age check, page content analysis, risk scoring\n"))

    print("Options:")
    print("  1. Scan URLs from typed text")
    print("  2. Scan URLs from a file")
    choice = input("Choose (1/2): ").strip()

    if choice == "2":
        filepath = input("Enter file path: ").strip()
        try:
            with open(filepath, "r") as f:
                text = f.read()
        except FileNotFoundError:
            print(red(f"File not found: {filepath}"))
            return
    else:
        text = input("Enter text or URLs to scan:\n> ")

    urls = extract_urls(text)
    if not urls:
        print(yellow("No URLs found in the input."))
        return

    print(f"\n{bold(f'Found {len(urls)} URL(s). Starting comprehensive scan...')}")
    summary = []

    for url in urls:
        results = scan_url(url, vt_key)
        print_results(results)
        summary.append((url, results["_risk_score"], results["Verdict"]))

    # Enhanced summary table
    print(f"\n{bold(cyan('━' * 60))}")
    print(bold("  SCAN SUMMARY (Risk Score 0-100)"))
    print(bold(cyan('━' * 60)))
    
    # Sort by risk score (highest first)
    summary.sort(key=lambda x: x[1], reverse=True)
    
    for url, risk_score, verdict in summary:
        short = url[:55] + "…" if len(url) > 55 else url
        # Color-code risk score
        if risk_score >= 50:
            score_display = red(f"{risk_score}/100")
        elif risk_score >= 30:
            score_display = yellow(f"{risk_score}/100")
        else:
            score_display = green(f"{risk_score}/100")
            
        print(f"  {short}")
        print(f"    → Risk: {score_display} | {verdict}\n")

if __name__ == "__main__":
    # Check for required packages
    try:
        import whois
    except ImportError:
        print(red("⚠ Missing required package: python-whois"))
        print(yellow("Install with: pip install python-whois"))
        print("Continuing without WHOIS check...\n")
    
    phishing_scanner()
