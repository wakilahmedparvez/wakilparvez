# Fake Site & Scam Store Detector

**Lightweight, explainable tool to quickly check whether a website looks suspicious or possibly a phishing/scam store.**  
Prototype for educational and defensive use only.

---

## 🚀 One-line summary
Give a URL → the tool checks WHOIS (domain age), SSL (validity/expiry), and page content heuristics (suspicious keywords, contact info, link count) → returns a human-readable `risk_score` and `verdict`.

---

## ⚠️ Important — Read Before You Use
This project is built for **education, awareness and defensive analysis**.  
**Do not** use it to attack, phish, probe, or otherwise harm other people or systems. Intrusive actions without explicit permission may be illegal. Use responsibly.

---

## ✅ Features
- WHOIS (domain creation age) analysis  
- SSL certificate check (valid/expired + days left)  
- Page content heuristics (suspicious keywords, presence of contact info, link count)  
- Explainable `risk_score` (0–100) and `verdict`: `Probably Safe` / `Suspicious` / `Likely Scam`  
- Simple web UI + API (`/api/scan`)  
- Lightweight — runs locally (no external data required)

---

## 📁 Repo (clone)
```bash
git clone https://github.com/wakilahmedparvez/wakilparvez.git
cd wakilparvez

🧰 Requirements

Python 3.10+

(Recommended) whois system package — improves WHOIS fallback

Internet connection for live page fetches and WHOIS/SSL checks

Install & Run (fast, step-by-step)

1.Create and activate a Python virtual environment:
      python3 -m venv venv
      source venv/bin/activate       

2.Install Python dependencies:
      pip install --upgrade pip
      pip install -r requirements.txt

3.(Optional but recommended) Install system whois:
 # Debian/Ubuntu/Kali
     sudo apt update
     sudo apt install -y whois

4.Start the server (development mode):
     python scandetector.py

5.Open in browser:
     http://127.0.0.1:5000/
Or
API (use from CLI or scripts)
   curl "http://127.0.0.1:5000/api/scan?url=https://example.com"
 


