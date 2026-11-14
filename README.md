<div align="center">

# 🛡️ ClipGuard

**A privacy-first smart clipboard manager that intercepts and shields sensitive credentials, tokens, and API keys in real time.**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/)

</div>

---

## 💡 The Problem

Every developer has accidentally copied an **AWS secret key**, a **GitHub Personal Access Token**, or a **production database connection string** to their clipboard. 

From there, it gets leaked in:
- Screen sharing during Zoom/Meet calls or live streams
- Third-party clipboard history managers synching to unencrypted clouds
- Accidental pastes into Slack, Discord, public chatrooms, or AI prompts

## ⚡ What ClipGuard Does

**ClipGuard** is a lightweight, local-first terminal utility and background watcher that:
1. **Detects Secrets Instantly**: Uses high-speed regex signatures and Shannon entropy heuristics to catch AWS, OpenAI, GitHub, Stripe, SSH private keys, JWTs, and database URLs.
2. **Auto-Purges & Masks**: Optionally auto-wipes your clipboard immediately or masks credentials (`sk-proj-****...`) so raw secrets are never exposed.
3. **Smart Local History**: Retains your daily copy-paste history in a lightweight SQLite database without leaking sensitive values.
4. **Snippets & Pinning**: Pin frequently used bash commands, Docker setups, or SSH templates so they're always 1 keystroke away.
5. **100% Offline & Private**: Zero telemetry, zero external network calls. Everything stays on your local machine.

---

## 🖥️ Demo Preview

```
┌──────────────────────── SECURITY ALERT ────────────────────────┐
│ ⚠️ SECRET LEAK PREVENTED!                                      │
│ Detected: OpenAI / Anthropic API Key                           │
│ Masked Preview: sk-proj-**********************************8f9  │
│ Tip: Run 'clipguard purge' or use --auto-purge to wipe safely. │
└────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### 1. Installation

Clone and install locally:

```bash
git clone https://github.com/<your-username>/clipguard.git
cd clipguard
pip install -e .
```

Or install in a virtual environment:

```bash
python -m venv .venv
# On Windows:
.\.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

pip install -e .
```

---

## 📖 Usage & Commands

### 1. Start the Live Background Watcher

Keep ClipGuard running in a terminal pane or background service:

```bash
clipguard watch
```

To automatically wipe the clipboard the instant a secret is copied:
```bash
clipguard watch --auto-purge
```

To store only redacted previews in history:
```bash
clipguard watch --store-redacted
```

---

### 2. Inspect / Scan Text or Active Clipboard

Scan what's currently on your clipboard:
```bash
clipguard scan
```

Scan an arbitrary string or snippet:
```bash
clipguard scan "OPENAI_API_KEY=sk-proj-1234567890abcdef1234567890abcdef"
```

Output:
```
                 ⚠️ Secrets Detected                  
┌────────────────────────────┬────────────┬──────────┐
│ Type                       │ Confidence │ Position │
├────────────────────────────┼────────────┼──────────┤
│ OpenAI / Anthropic API Key │ HIGH       │ 15..63   │
└────────────────────────────┴────────────┴──────────┘

Masked Output:
OPENAI_API_KEY=sk-p*********************************cdef
```

---

### 3. Search & Browse Clipboard History

View recent clipboard history:
```bash
clipguard list
```

View only your pinned snippets:
```bash
clipguard list --pinned
```

Fuzzy search through past clips:
```bash
clipguard search "docker compose"
```

---

### 4. Pin Frequently Used Commands

Pin a snippet with an optional label:
```bash
clipguard pin 3 --label "Docker Dev Setup"
```

Copy any historical item back to your clipboard by its ID:
```bash
clipguard copy 3
```

---

### 5. Emergency Purge & Clean

Wipe all detected secrets from your database and sanitize the active clipboard:
```bash
clipguard purge
```

Clear all non-pinned history items:
```bash
clipguard clear
```

Clear everything including pinned items:
```bash
clipguard clear --all
```

---

## 🔍 Supported Secret Types

| Provider / Type | Description / Pattern | Confidence |
| :--- | :--- | :--- |
| **AWS Access Keys** | `AKIA...`, `ASIA...` | HIGH |
| **GitHub Tokens** | Classic (`ghp_`), fine-grained (`github_pat_`), OAuth tokens | HIGH |
| **OpenAI & Anthropic** | `sk-...`, `sk-proj-...`, `sk-ant-...` | HIGH |
| **Google Cloud / Gemini** | `AIza...` | HIGH |
| **Stripe Live Keys** | `sk_live_...`, `rk_live_...` | HIGH |
| **Slack Webhooks / Bots** | `xoxb-...`, `xoxp-...` | HIGH |
| **Private Keys** | PEM RSA, OpenSSH, PGP, EC private keys | HIGH |
| **Database URLs** | PostgreSQL, MySQL, MongoDB, Redis connection URIs with credentials | HIGH |
| **JSON Web Tokens** | JWT tokens with standard 3-part base64 payloads | MEDIUM |
| **High Entropy Strings** | Standalone passwords and randomized hashes (Shannon entropy > 4.5) | MEDIUM |

---

## 🛠️ Development & Testing

Run unit tests with `pytest`:

```bash
pytest -v
```

All detector rules and database operations are covered by automated unit tests under `tests/`.

---

## 🗺️ Roadmap & Continuous Commits

Ideas you can contribute or implement next:
- [ ] **Desktop System Tray Icon**: Minimal system tray icon using `pystray`.
- [ ] **Native OS Notifications**: Pop desktop push alerts when secrets are intercepted.
- [ ] **Encrypted Storage**: Encrypt the SQLite database with SQLCipher or AES-GCM using system keychain.
- [ ] **Interactive TUI**: Full-screen fuzzy-finder navigation using `textual`.
- [ ] **Custom Rules YAML**: Allow users to specify custom regex rules in `~/.clipguard/rules.yaml`.

---

## 📄 License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
