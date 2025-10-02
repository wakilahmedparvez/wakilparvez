# Fake Site & Scam Store Detector (Python + Flask)

## Overview
Simple prototype to check if a website is potentially fake/scam based on:
- Domain age (WHOIS)
- SSL validity
- Content analysis (suspicious keywords, contact info)

---

## Requirements
- Python 3.10+
- pip (Python package manager)

---

## Setup (Local)

1. Clone or download project.
2. Create virtual environment:
```bash
python -m venv venv
# Activate:
# Windows (PowerShell): venv\Scripts\Activate.ps1
# Linux/Mac: source venv/bin/activate
