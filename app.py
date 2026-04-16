from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import urllib.parse
import socket
import math
from collections import Counter
import base64
from playwright.sync_api import sync_playwright
import dns.resolver # <-- NEW: For checking DNS Infrastructure

app = Flask(__name__)
CORS(app)

print("Loading the Hybrid AI Brain...")
model = joblib.load('url_model.pkl')

def calculate_entropy(text):
    if not text: return 0
    entropy = 0
    length = len(text)
    character_counts = Counter(text)
    for count in character_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy

def get_live_features(url):
    url = str(url).lower()
    return [
        len(url), url.count('.'), url.count('-'),
        1 if "https" in url else 0,
        1 if any(w in url for w in ['login', 'update', 'free', 'verify', 'bank', 'secure', 'account']) else 0,
        url.count('/')
    ]

def check_domain(url):
    if not url.startswith('http'): url = 'http://' + url
    try:
        domain = urllib.parse.urlparse(url).netloc
        if not domain: return "Unknown Domain", False
        ip_address = socket.gethostbyname(domain)
        return domain, ip_address
    except socket.gaierror:
        return domain, "Offline / Unreachable"
    except Exception:
        return "Invalid Format", False

# --- NEW: DNS INFRASTRUCTURE CHECKER ---
def check_dns_infrastructure(domain):
    try:
        # We ask the internet if this domain has Mail Exchange (MX) records configured
        answers = dns.resolver.resolve(domain, 'MX')
        return True if answers else False
    except Exception:
        # If it errors out, it means no MX records exist
        return False

@app.route('/api/scan-url', methods=['POST'])
def scan_url():
    data = request.json
    received_url = data.get('url', '')
    if not received_url: return jsonify({"error": "No URL provided"}), 400

    features = get_live_features(received_url)
    ai_base_probability = model.predict_proba([features])[0][1] 
    risk_score = int(ai_base_probability * 100) 
    
    domain_name, ip_status = check_domain(received_url)
    is_alive = ip_status != "Offline / Unreachable" and ip_status != False

    logs = []
    
    # --- NEW: APPLY DNS HEURISTICS ---
    if is_alive:
        has_mx_records = check_dns_infrastructure(domain_name)
        if not has_mx_records:
            risk_score += 25 # Heavy penalty for lacking basic business infrastructure
            logs.append("Domain lacks email infrastructure (No MX Records). Scammers rarely configure mail servers.")
        else:
            logs.append("Domain has established email infrastructure (MX Records verified).")

    shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
    if any(s in domain_name.lower() for s in shorteners):
        risk_score += 35
        logs.append(f"URL Shortener detected ({domain_name}).")

    cheap_tlds = ['.xyz', '.top', '.pw', '.cc', '.club', '.tk']
    if any(domain_name.lower().endswith(tld) for tld in cheap_tlds):
        risk_score += 30
        logs.append("Suspicious Top-Level Domain detected.")

    domain_entropy = calculate_entropy(domain_name.split('.')[0])
    if domain_entropy > 4.0:
        risk_score += 20
        logs.append(f"High structural randomness detected (Entropy: {domain_entropy:.2f}).")

    if not is_alive:
        risk_score += 40
        logs.append(f"Domain '{domain_name}' is DEAD or UNREACHABLE.")
    else:
        logs.append(f"Domain '{domain_name}' is currently ACTIVE.")

    if features[0] > 75: risk_score += 15
    if features[2] > 1: risk_score += 20
    if features[3] == 0: risk_score += 15
    if features[4] == 1: risk_score += 25

    risk_score = min(99, risk_score)

    if risk_score >= 70: status = "malicious"
    elif risk_score >= 35: status = "suspicious"
    else: status = "safe"

    return jsonify({"status": status, "risk_score": risk_score, "logs": logs})

@app.route('/api/sandbox-scan', methods=['POST'])
def sandbox_scan():
    data = request.json
    target_url = data.get('url', '')
    if not target_url.startswith('http'):
        target_url = 'http://' + target_url

    print(f"\n[SANDBOX] 1. Request received for: {target_url}")
    requests_made = set()

    try:
        with sync_playwright() as p:
            print("[SANDBOX] 2. Waking up Playwright...")
            browser = p.chromium.launch(headless=True)
            
            print("[SANDBOX] 3. Invisible Browser launched successfully!")
            page = browser.new_page()
            page.on("request", lambda request: requests_made.add(request.url))
            
            print("[SANDBOX] 4. Navigating to the URL...")
            page.goto(target_url, timeout=8000, wait_until="domcontentloaded")
            
            print("[SANDBOX] 5. Taking evidence screenshot...")
            screenshot_bytes = page.screenshot()
            screenshot_base64 = base64.b64encode(screenshot_bytes).decode('utf-8')
            
            print("[SANDBOX] 6. Closing the browser...")
            browser.close()

            connected_domains = list(set([urllib.parse.urlparse(u).netloc for u in requests_made if urllib.parse.urlparse(u).netloc]))
            print(f"[SANDBOX] 7. Success! Found {len(connected_domains)} hidden connections.")

            return jsonify({
                "success": True,
                "screenshot": f"data:image/png;base64,{screenshot_base64}",
                "external_connections": connected_domains[:10]
            })

    except Exception as e:
        print(f"[SANDBOX] ERROR DETECTED: {str(e)}")
        return jsonify({"success": False, "error": str(e)})

if __name__ == '__main__':
    print("Starting isMalicious SOC Server...")
    app.run(debug=True, port=5000, threaded=False)