# scandetector.py
from flask import Flask, request, jsonify, render_template_string
import whois
import socket, ssl
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import tldextract

app = Flask(__name__)

# --- Heuristics config ---
SUSPICIOUS_KEYWORDS = [
    'free', 'cheap', 'discount', 'limited time', 'click here', 'buy now',
    'risk free', 'guarantee', '100% free', 'best price', 'urgent', 'offer'
]

def score_whois_age(days_old):
    if days_old is None:
        return 15
    if days_old < 30: return 25
    if days_old < 180: return 15
    if days_old < 365: return 8
    return 0

def score_ssl(valid, days_left):
    if not valid: return 20
    if days_left is None: return 5
    if days_left < 30: return 10
    return 0

def score_content(suspicious_keywords_count, has_contact):
    score = min(suspicious_keywords_count * 5, 30)
    if not has_contact:
        score += 10
    return min(score, 40)

# --- Checks ---
def whois_info(domain):
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list): creation = creation[0]
        days_old = (datetime.utcnow() - creation).days if creation else None
        return {'created_days_ago': days_old, 'raw': str(w.domain_name)[:200]}
    except Exception as e:
        return {'created_days_ago': None, 'error': str(e)}

def ssl_check(hostname, port=443, timeout=5):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expiry = datetime.strptime(cert.get('notAfter'), '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry - datetime.utcnow()).days
                return {'valid': True, 'days_left': days_left, 'issuer': cert.get('issuer')}
    except Exception as e:
        return {'valid': False, 'error': str(e)}

def analyze_content(url, timeout=7):
    try:
        r = requests.get(url, timeout=timeout, headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(r.text, 'html.parser')
        text = soup.get_text(separator=' ').lower()
        count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in text)
        has_contact = any(x in text for x in ['contact', 'about us', 'phone', 'email', 'address'])
        links = [a.get('href') for a in soup.find_all('a', href=True)]
        return {'status_code': r.status_code, 'suspicious_keywords_count': count, 'has_contact': has_contact, 'links_count': len(links)}
    except Exception as e:
        return {'error': str(e)}

# --- Orchestrator ---
from urllib.parse import urlparse

def normalize_url(url):
    return url if url.startswith('http') else 'http://' + url

def extract_domain(url):
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        ext = tldextract.extract(url)
        hostname = '.'.join(p for p in [ext.subdomain, ext.domain, ext.suffix] if p)
    return hostname

def scan_url(url):
    result = {'input': url}
    url_norm = normalize_url(url)
    hostname = extract_domain(url_norm)
    result['hostname'] = hostname

    who = whois_info(hostname)
    result['whois'] = who

    sslr = ssl_check(hostname)
    result['ssl'] = sslr

    content = analyze_content(url_norm)
    result['content'] = content

    score = score_whois_age(who.get('created_days_ago')) + \
            score_ssl(sslr.get('valid', False), sslr.get('days_left')) + \
            score_content(content.get('suspicious_keywords_count', 0), content.get('has_contact', False))

    risk_score = max(0, min(score, 100))
    verdict = 'Probably Safe' if risk_score <= 30 else 'Suspicious' if risk_score <= 60 else 'Likely Scam'

    result['risk_score'] = risk_score
    result['verdict'] = verdict
    return result

# --- Flask routes ---
INDEX_HTML = """
<!doctype html>
<title>Fake Site Detector</title>
<h2>Fake Website & Scam Store Detector</h2>
<form method="post" action="/api/scan">
  URL or domain: <input name="url" size="60" placeholder="https://example.com" required>
  <input type="submit" value="Scan">
</form>
<p>API: POST /api/scan JSON { "url": "example.com" } or GET /api/scan?url=example.com</p>
"""

@app.route("/", methods=["GET"])
def index():
    return render_template_string(INDEX_HTML)

@app.route("/api/scan", methods=["GET","POST"])
def api_scan():
    data = request.get_json(silent=True) or request.values
    url = data.get('url') or data.get('domain')
    if not url:
        return jsonify({'error': 'Provide url parameter'}), 400
    try:
        return jsonify(scan_url(url))
    except Exception as e:
        return jsonify({'error': 'internal', 'detail': str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
