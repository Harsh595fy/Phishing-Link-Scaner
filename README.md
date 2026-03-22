# 🛡️ Advanced Phishing Link Scanner


> A powerful, multi-layered phishing URL detection tool built in Python. Combines pattern analysis, DNS/SSL validation, redirect chain inspection, entropy scoring, and optional VirusTotal API integration to assess whether a link is safe or malicious.

---

## 📋 Table of Contents
<img width="1018" height="659" alt="Screenshot From 2026-03-22 09-56-42" src="https://github.com/user-attachments/assets/04f0e94e-27f3-479d-a687-bd251780010b" />

- [Features](#-features)<img width="1018" height="659" alt="Screenshot From 2026-03-22 09-56-31" src="https://github.com/user-attachments/assets/5c1a3b13-7d8a-4255-9348-5c546094e7a9" />

- [How It Works](#-how-it-works)
- [Installation](#-installation)
- [Usage](#-usage)
- [VirusTotal Integration](#-virustotal-integration)
- [Detection Logic](#-detection-logic)
- [Example Output](#-example-output)
- [Project Structure](#-project-structure)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **Pattern Analysis** | Detects suspicious keywords, IP-based URLs, special characters, and typosquatting |
| 🎲 **Entropy Scoring** | Shannon entropy detects randomly generated (bot-created) domains |
| 🌐 **DNS Resolution** | Verifies if the domain actually resolves to a valid IP |
| 🔒 **SSL Validation** | Checks certificate validity, issuer, and expiry date |
| ↪️ **Redirect Chain Tracking** | Follows all redirects and flags cross-domain hops |
| 🔗 **URL Shortener Detection** | Identifies bit.ly, tinyurl, t.co, and other shorteners |
| 🦠 **VirusTotal API** | Submits URLs and polls for multi-engine scan results |
| 📁 **Batch Scanning** | Scan URLs from a text file in one go |
| 🎨 **Color-coded Output** | Clear red/yellow/green terminal feedback |
| 📋 **Scan Summary** | End-of-session summary table for all scanned URLs |

---

## 🔬 How It Works

The scanner runs each URL through **5 independent check layers**, each contributing a flag to a cumulative risk score:

```
URL Input
   │
   ├── 1. Pattern Analysis     → suspicious keywords, entropy, subdomains, IP
   ├── 2. DNS Resolution       → does the domain exist?
   ├── 3. SSL Validation       → valid cert? who issued it? expiring soon?
   ├── 4. Redirect Chain       → where does it actually go?
   └── 5. VirusTotal (optional)→ 90+ antivirus engine results
          │
          ▼
    Risk Score (flags)
          │
   ┌──────┴──────┐
   0-1 flags   2 flags   3+ flags
      ✅ Safe   ⚠️ Suspicious   ⛔ High Risk
```

---

## 🛠️ Installation

### Prerequisites

- Python **3.10** or higher
- pip

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/Harsh595fy/Phishing-Link-Scaner.git
cd phishing-link-scanner

# 2. (Optional) Create a virtual environment
python -m venv venv
source venv/bin/activate      # Linux/macOS
venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

### `requirements.txt`

```
requests>=2.28.0
```

> All other modules (`re`, `socket`, `ssl`, `math`, `time`, `urllib`) are part of Python's standard library.

---

## 🚀 Usage

### Run the Scanner

```bash
python Task1_updated.py
```

### Interactive Prompts

```
╔══════════════════════════════════════════╗
║   Advanced Phishing Link Scanner v2.0   ║
╚══════════════════════════════════════════╝

Enter VirusTotal API key (or press Enter to skip):

Options:
  1. Scan URLs from typed text
  2. Scan URLs from a file
Choose (1/2):
```

### Option 1 — Paste text or URLs directly

```
> Check this link: http://secure-login.verify.paypal.evil.com/update
```

### Option 2 — Scan from a file

Create a `.txt` file with URLs (one per line or in any text):

```
Found malicious link: http://bit.ly/3xAbc123
Also check https://amazon-account-update.xyz/login
```

Then choose option **2** and provide the file path.

---

## 🦠 VirusTotal Integration

To enable VirusTotal scanning:

1. Sign up at [virustotal.com](https://www.virustotal.com) (free account available)
2. Go to your **profile → API Key**
3. Copy your key and paste it when the scanner prompts you

> **Note:** The free VirusTotal API allows **4 requests/minute** and **500 requests/day**. The scanner polls results automatically (up to 20 seconds).

---

## 🧠 Detection Logic

### Suspicious Pattern Checks
- Keywords: `login`, `verify`, `secure`, `account`, `paypal`, `amazon`, `microsoft`, `password`, and more
- Raw IP address URLs (e.g. `http://192.168.1.1/login`)
- More than 4 subdomain levels
- `@` or `%` characters in the domain
- Domain name longer than 20 characters

### Shannon Entropy
Domains with entropy **> 3.8** are flagged as potentially machine-generated:
```
entropy("google")    → ~2.25  ✅ Normal
entropy("xk3f9amqz") → ~3.17  ⚠️ Suspicious
entropy("a8f3kzm9pq") → ~3.92 ⛔ Likely generated
```

### Risk Score → Verdict

| Flags | Verdict |
|-------|---------|
| 0–1 | ✅ SAFE — No significant issues |
| 2 | ⚠️ SUSPICIOUS — Proceed with caution |
| 3+ | ⛔ HIGH RISK — Likely Phishing |

---

## 📸 Example Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Scanning: http://secure-login.verify.paypal.evil.com/update
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🔍 Patterns:
      - Suspicious keyword 'login' found in URL.
      - Excessive subdomains (4 levels).
      - Suspicious keyword 'paypal' found in URL.
  🌐 DNS: Resolved to 185.220.101.34
  🔒 SSL: SSL certificate INVALID or self-signed.
  ↪️  Redirects: 2 redirect(s) → http://phish-collect.ru ⚠ cross-domain
  🦠 VirusTotal: VT: 14 malicious, 3 suspicious / 90 engines
  📋 Verdict: ⛔  HIGH RISK — Likely Phishing!
```

---

## 📁 Project Structure

```
phishing-link-scanner/
│
├── Task1_updated.py      # Main scanner script (v2.0)
├── Task1.py              # Original scanner script (v1.0)
├── requirements.txt      # Python dependencies
├── README.md             # Project documentation
└── sample_urls.txt       # Sample input file for batch scanning
```

---

## 🤝 Contributing

Contributions are welcome! Here's how to get started:

```bash
# Fork the repo, then:
git checkout -b feature/your-feature-name
git commit -m "Add: your feature description"
git push origin feature/your-feature-name
# Open a Pull Request
```

### Ideas for Contributions
- [ ] WHOIS domain age lookup
- [ ] GUI interface (Tkinter or web-based)
- [ ] Export results to JSON / CSV
- [ ] Async scanning for faster batch processing
- [ ] Integration with Google Safe Browsing API
- [ ] Docker support

---

## ⚠️ Disclaimer

This tool is intended for **educational and defensive security purposes only**. Do not use it to scan URLs without appropriate authorization. The authors are not responsible for any misuse.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">
  Made with ❤️ for cybersecurity awareness
  <br/>
  ⭐ Star this repo if you found it helpful!
</div>
