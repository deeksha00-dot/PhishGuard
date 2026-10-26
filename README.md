# PhishGuard - AI Phishing & Scam Detector

A college hackathon prototype that analyses suspicious emails, SMS messages and URLs and explains the warning signs it finds.

> **Honest note:** the detector is a **rule-based engine** (regular expressions + URL checks). It does **not** use a trained AI/ML model. The score is a heuristic estimate, not a verified probability.

## 1. Problem statement
Phishing and scam messages (fake bank alerts, OTP theft, prize scams, parcel fees) cause large financial losses, and most people cannot tell why a message is suspicious. Existing tools are often black boxes or need cloud services.

## 2. Objectives
- Give a 0-100 risk score and a Low / Medium / High / Critical level.
- Explain every warning sign and how many points it added.
- Work offline, with no API keys or paid services.
- Keep a local history of analyses.

## 3. Features
- Dashboard UI (dark navy, responsive, keyboard accessible)
- Explainable detection: urgency, credential theft, financial scams, suspicious links, impersonation, secrecy, attachments
- Static URL inspection (links are never opened)
- Highlighted suspicious phrases, score breakdown, safety recommendations
- SQLite history: open old results, clear with confirmation
- Flask JSON API and 29 automated tests (`unittest`)

## 4. Technology stack
HTML5, CSS3, vanilla JavaScript | Python 3 + Flask | SQLite (`sqlite3`) | `unittest`. Nothing else.

## 5. System architecture
```
Browser (index.html + script.js)
   |  fetch() JSON
   v
Flask routes (app.py) --> detector.py (rules, scoring)
   |
   v
database.py --> phishguard.db (SQLite, created automatically)
```

## 6. Folder structure
```
PhishGuard/
    app.py            Flask app + API routes
    detector.py       Rule engine and scoring
    database.py       SQLite functions
    requirements.txt  Flask
    README.md  .gitignore
    templates/index.html
    static/style.css, static/script.js
    tests/test_detector.py, tests/test_api.py
```

## 7. How the detection engine works
`analyze_content(text, input_type)` in `detector.py`:
1. **Normalize** the text (Unicode NFKC, remove hidden characters, straight quotes, tidy whitespace).
2. **Blank out safety advice** such as "Never share your OTP", so real bank notices are not flagged.
3. **Run text rules** (case-insensitive regex). Each rule fires **at most once**, so repeating a word does not add points.
4. **Extract URLs** with regex and inspect each with `urllib.parse`: shorteners, raw IP hosts, brand names in non-official domains (e.g. `paypal.account-verify.xyz`), `@` tricks, punycode, excessive subdomains, hyphen/keyword-stuffed hosts, abused TLDs, heavy percent-encoding. HTTP alone is only a weak signal (+3).
5. **Add combination bonuses** when strong signals appear together (e.g. credential request + suspicious link).
6. **Impersonation** (claiming to be a bank, courier, etc.) is only counted if other warning signs exist, so an ordinary message that mentions "bank" scores 0.

## 8. How scoring works
Each indicator has a fixed weight (for example OTP request 28, shortened URL 20, HTTP 3). Each category has a cap so the total cannot be inflated: urgency 25, credential 40, financial 35, links 35, other 25, combined evidence 30. The final score is the sum, limited to 100.

| Score | Level |
|---|---|
| 0-24 | Low |
| 25-49 | Medium |
| 50-74 | High |
| 75-100 | Critical |

The same input always gives the same result (deterministic).

## 9. API
| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Dashboard |
| POST | `/api/analyze` | Analyze and save (max 10,000 chars) |
| GET | `/api/history` | Last 20 analyses, newest first |
| GET | `/api/history/<id>` | One saved analysis (404 if missing) |
| DELETE | `/api/history` | Delete all history |
| GET | `/api/health` | `{"status": "ok"}` |

Request:
```json
{ "text": "Share your OTP at http://bit.ly/abc", "input_type": "auto" }
```
`input_type` is `auto`, `email_sms` or `url`. Response (shortened):
```json
{ "id": 1, "risk_score": 63, "risk_level": "High",
  "detected_indicators": [ { "id": "otp_request", "description": "...", "points": 28, "evidence": ["Share your OTP"] } ],
  "recommendations": ["..."], "summary": "...", "input_type": "email_sms" }
```
Errors return `{"error": "message"}` with status 400, 404, 413 or 500.

## 10. Install and run (Windows PowerShell)
Install Python 3.10+ from python.org (tick "Add python.exe to PATH"). Then, inside the `PhishGuard` folder:
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests
python app.py
```
Open **http://127.0.0.1:5000** in your browser. Stop the server with `Ctrl + C`.

**If PowerShell blocks activation** (execution-policy error), you do not need to change any system setting. Use either:
- Command Prompt (`cmd`) instead: `.venv\Scripts\activate.bat`, or
- Skip activation and call the venv's Python directly: `.venv\Scripts\python.exe -m pip install -r requirements.txt` and `.venv\Scripts\python.exe app.py`, or
- Allow scripts for this one window only: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`.

Optional: `$env:PHISHGUARD_DEBUG = "1"` before `python app.py` turns on Flask debug mode (local development only; it is off by default).

## 11. Sample test messages
| Message | Expected outcome |
|---|---|
| `ALERT: Your bank account is suspended. Urgent action required within 24 hours. Reply with your OTP and click http://bit.ly/secure-bank-verify to avoid account closure.` | Critical |
| `Congratulations! You have won a lottery prize of $50,000. Pay a small processing fee and keep this confidential. Claim your prize at http://claim-prize-now.xyz/win` | High |
| `Your parcel is on hold. Confirm your delivery address and pay the customs fee here: http://192.168.4.23/track/login` | Medium |
| `http://example.com/help` | Low (HTTP is only a weak signal) |
| `Hi Riya, are we still meeting for lunch tomorrow? I went to the bank this morning.` | Low |
| `Your OTP is 482913. Never share it with anyone, including bank staff.` | Low |

(Levels above were observed from the real engine; exact scores are shown in the app.)

## 12. Limitations
- Rules can miss new scam wording and can raise false alarms on unusual legitimate messages.
- English-focused patterns only.
- Static URL inspection only: no live reputation, no page content, no redirect following.
- History is local and shared (no user accounts). Message text is stored unencrypted in SQLite.
- Not a replacement for professional security tools.

## 13. Future improvements
Multi-language rules, trained ML classifier trained on a labelled dataset (with evaluation), email header analysis, user accounts, browser extension, optional reputation lookups (opt-in), PDF report export.

## 14. Presentation summary
"PhishGuard is a Flask web app that checks emails, SMS and links for phishing using a transparent rule engine. It gives a 0-100 risk score, shows exactly which warning signs were found and how many points each added, never opens links, stores history in SQLite, and works fully offline. It is a prototype: the score is a heuristic estimate, not a guarantee."

## Viva questions and answers
1. **What problem does it solve?** It helps ordinary users understand why a message looks like phishing, instead of just saying "spam".
2. **Is it AI?** No. It is a rule-based expert system (regex + URL checks). We state this honestly; ML is future work.
3. **Why rules instead of ML?** They are explainable, deterministic, need no dataset or training, and are easy to demonstrate and debug.
4. **Describe the architecture.** Browser JS calls Flask JSON routes; Flask calls `detector.py` and `database.py`; SQLite stores history.
5. **Why Flask?** Lightweight, beginner-friendly, built-in templates/static serving, easy JSON APIs.
6. **Why SQLite?** Built into Python, no server, one file, ideal for a single-user prototype.
7. **How do you prevent SQL injection?** All queries use `?` parameters; user text is never concatenated into SQL (there is a test for it).
8. **How is the score calculated?** Weighted indicator points, per-category caps, combination bonuses, clamped to 0-100.
9. **How do you stop repeated words inflating the score?** Each rule fires once and categories are capped; a test proves repetition does not change the score.
10. **How do you avoid false positives like "bank"?** Words alone never score. Rules need request patterns, and "Never share your OTP" safety advice is removed first.
11. **How are URLs checked safely?** Only string analysis with `urllib.parse` and `ipaddress`. We never connect, resolve, or download.
12. **What are the main limitations?** Evasion by new wording, English only, no live reputation checks, shared local history.
13. **How did you test it?** 29 `unittest` tests cover rules, thresholds, API validation and history, using a temporary database and no internet.
14. **What security measures exist?** Input length limit, JSON validation, escaped output via `textContent`, no external calls, no logging of message bodies, debug off by default.
15. **Future scope?** Trained ML model with evaluation, multilingual support, browser extension, header analysis, user accounts.
