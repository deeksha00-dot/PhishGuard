"""
detector.py - PhishGuard's explainable, rule-based phishing/scam detector.

IMPORTANT: This is NOT machine learning. It is a deterministic set of regular
expressions and URL checks. Each rule has a fixed weight, every category has a
cap (so repeated keywords can't inflate the score), and every point added to the
score is explained to the user. The same input always gives the same output.

The detector performs STATIC inspection only. It never visits, resolves or
downloads anything from a URL.
"""

import ipaddress
import re
import unicodedata
from urllib.parse import urlparse

# --------------------------------------------------------------------------
# Risk thresholds (single source of truth - the UI and README use the same)
# --------------------------------------------------------------------------
RISK_THRESHOLDS = [  # (minimum score, label), checked from the top
    (75, "Critical"),
    (50, "High"),
    (25, "Medium"),
    (0, "Low"),
]

VALID_INPUT_TYPES = ("auto", "email_sms", "url")

CATEGORY_LABELS = {
    "urgency": "Urgency and threats",
    "credential": "Credential theft",
    "financial": "Financial scams",
    "links": "Suspicious links",
    "other": "Other suspicious language",
    "combination": "Combined evidence",
}

# Maximum points one category may contribute, so repetition can't inflate scores.
CATEGORY_CAPS = {
    "urgency": 25,
    "credential": 40,
    "financial": 35,
    "links": 35,
    "other": 25,
    "combination": 30,
}


def get_risk_level(score):
    """Map a 0-100 score to Low / Medium / High / Critical."""
    for minimum, label in RISK_THRESHOLDS:
        if score >= minimum:
            return label
    return "Low"


# --------------------------------------------------------------------------
# Text normalisation
# --------------------------------------------------------------------------
_ZERO_WIDTH = re.compile("[\u200b-\u200f\u2060\ufeff]")


def normalize_text(text):
    """Clean text so patterns match reliably (NFKC, no hidden characters,
    straight quotes, tidy whitespace). Case is preserved for display."""
    text = unicodedata.normalize("NFKC", text)
    text = _ZERO_WIDTH.sub("", text)
    text = text.replace("\u2019", "'").replace("\u2018", "'")
    text = text.replace("\u201c", '"').replace("\u201d", '"')
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t\f\v]+", " ", text)
    return text.strip()


# Phrases like "Never share your OTP" are SAFETY ADVICE, not a request for an
# OTP. We blank them out before running credential rules.
_SAFE_ADVICE = re.compile(
    r"\b(?:do not|don't|dont|never|not)\s+(?:ever\s+)?(?:share|disclose|reveal|give|provide|tell)\b[^.!?\n]{0,60}"
    r"|\b(?:will|would)\s+never\s+(?:ask|request|call)\b[^.!?\n]{0,60}",
    re.IGNORECASE,
)

# --------------------------------------------------------------------------
# Text rules: (id, category, points, description, regex)
# --------------------------------------------------------------------------
_ASK = r"(?:share|send|reply(?: with)?|provide|enter|give|tell|forward|submit|disclose|type|read out)"
_CONFIRM = r"(?:confirm|verify|validate|re-?enter)"
_OTP = (r"(?:otp|one[- ]time (?:password|passcode|pin|code)|verification code|"
        r"security code|authentication code|auth code|2fa code)")
_GAP = r"[^.!?\n]{0,40}"

TEXT_RULES = [
    # ---- A. Urgency and threats ----
    ("urgent_action", "urgency", 8, "The message pressures you to act immediately.",
     r"\b(?:act (?:now|immediately|fast|quickly)|immediate(?:ly)? (?:action|response)|"
     r"urgent(?:ly)? (?:action|attention|response)(?: is)?(?: required| needed)?|"
     r"action required|respond (?:now|immediately|urgently))\b"),
    ("account_threat", "urgency", 12, "The message threatens that an account or service will be blocked or suspended.",
     r"\b(?:account|card|access|service|number|profile|wallet)\b" + _GAP +
     r"\b(?:(?:will|shall|may|might) (?:be|get)|has been|have been|is|was|been)\s+"
     r"(?:blocked|suspended|locked|closed|deactivated|terminated|disabled|restricted|limited)\b"),
    ("deadline", "urgency", 6, "The message sets a short deadline or says it is your last chance.",
     r"\bwithin (?:the next )?(?:\d+|one|two|twelve|twenty[- ]four|forty[- ]eight) (?:hours?|hrs?|minutes?|mins?)\b"
     r"|\b(?:expires?|expiring) (?:today|soon|tonight|in \d+)"
     r"|\b(?:last|final) (?:warning|chance|notice)\b"),

    # ---- B. Credential theft ----
    ("otp_request", "credential", 28, "The message asks you to share or enter an OTP / verification code.",
     r"\b" + _ASK + r"\b" + _GAP + r"\b" + _OTP + r"\b"),
    ("password_request", "credential", 28, "The message asks for a password, PIN or login credentials.",
     r"\b(?:" + _ASK + r"|" + _CONFIRM + r")\b" + _GAP +
     r"\b(?:password|passcode|passwd|login (?:details|credentials)|credentials|pin(?: number)?)\b"),
    ("bank_credentials", "credential", 25, "The message asks for banking or identity details (card number, CVV, account number...).",
     r"\b(?:" + _ASK + r"|" + _CONFIRM + r")\b" + _GAP +
     r"\b(?:card number|debit card|credit card|cvv|cvc|net ?banking|bank (?:login|credentials|details|account details)|"
     r"account number|aadhaar|ssn|social security)\b"),
    ("confirm_login", "credential", 12, "The message asks you to confirm or update login, identity or account details.",
     r"\b(?:verify|confirm|validate|re-?enter|update)\b[^.!?\n]{0,30}\b(?:login|log-in|sign[- ]?in|identity|"
     r"account (?:details|information)|billing (?:details|information)|kyc)\b"),

    # ---- C. Financial scams ----
    ("prize_claim", "financial", 18, "The message claims you won a prize or were 'selected' unexpectedly.",
     r"\byou(?: have|'ve)? (?:won|been selected|are (?:the |a )?(?:lucky )?winner)\b"
     r"|\bcongratulations\b[^.!?\n]{0,50}\b(?:won|prize|winner|selected|reward)\b"
     r"|\bclaim your (?:prize|reward|gift|winnings)\b|\blucky (?:winner|draw)\b"),
    ("lottery", "financial", 16, "The message mentions winning a lottery or sweepstakes.",
     r"\b(?:lottery|sweepstakes?|jackpot)\b" + r"[^.!?\n]{0,60}\b(?:won|win|winner|prize|claim|selected)\b"
     r"|\b(?:won|win|winner|claim)\b[^.!?\n]{0,40}\b(?:lottery|sweepstakes?|jackpot)\b"),
    ("fake_refund", "financial", 10, "The message offers a refund, rebate or cashback you may not be expecting.",
     r"\b(?:refund|reimbursement|tax rebate|cashback)\b[^.!?\n]{0,60}\b(?:pending|approved|available|claim|waiting|eligible|ready)\b"
     r"|\bclaim (?:your|the) (?:refund|rebate)\b"),
    ("payment_request", "financial", 12, "The message asks for an unexpected fee, fine or charge.",
     r"\b(?:pay|payment|send|deposit|remit)\b[^.!?\n]{0,30}\b(?:fee|fees|fine|charges?|processing|clearance|customs|release|registration|tax)\b"),
    ("money_transfer", "financial", 18, "The message asks you to transfer money, crypto or gift cards.",
     r"\b(?:transfer|wire|send|remit)\b[^.!?\n]{0,30}"
     r"(?:\b(?:money|funds|amount|bitcoin|crypto(?:currency)?|gift ?cards?|upi|western union)\b"
     r"|(?:\$|rs\.?|\u20b9|\u00a3|usd |inr |eur )\s?\d[\d,]*)"),
    ("payment_verification", "financial", 8, "The message asks you to verify or approve a payment or transaction.",
     r"\b(?:verify|confirm|authori[sz]e|approve)\b[^.!?\n]{0,30}\b(?:payment|transaction|purchase|charge)\b"),

    # ---- E. Other suspicious language ----
    ("click_to_prevent", "other", 12, "The message tells you to click a link to avoid account closure or restore access.",
     r"\b(?:click|tap|follow|visit|open|use)\b[^.!?\n]{0,40}(?:\blink\b|\bhere\b|\bbelow\b|\burl\b|\bbutton\b|\bwebsite\b|https?://\S+|www\.\S+)"
     r"[^.!?\n]{0,80}\b(?:avoid|prevent|restore|unlock|verify|confirm|secure|reactivate|update|stop)\b"
     r"|\b(?:avoid|prevent|stop)\b[^.!?\n]{0,50}\b(?:closure|suspension|blocking|termination|deactivation|restriction|penalty)\b"
     r"[^.!?\n]{0,60}\b(?:click|tap|follow|visit|log ?in)\b"),
    ("risky_attachment", "other", 10, "The message urges you to open or install an attachment or program.",
     r"\b(?:open|download|run|install|enable)\b[^.!?\n]{0,25}\b(?:attachment|attached (?:file|document|invoice|form|pdf)|macros?|apk)\b"
     r"|\b[\w-]+\.(?:exe|apk|scr|bat|docm|xlsm)\b"),
    ("secrecy", "other", 15, "The message asks you to keep the transaction secret.",
     r"\bkeep (?:this|it)(?: a)? (?:secret|confidential)\b|\b(?:don't|do not) (?:tell|inform)\b|"
     r"\bbetween us\b|\bconfidential transaction\b"),
]

# Impersonation is only reported when OTHER warning signs are present, because
# mentioning "your bank" in an ordinary message is perfectly normal.
IMPERSONATION_RULE = (
    "impersonation", "other", 8,
    "The message claims to come from a bank, government body, delivery company or tech support, alongside other warning signs.",
    r"\b(?:this is|we are|we're|calling from|message from|notice from|alert from|from the|official)\b[^.!?\n]{0,30}"
    r"\b(?:bank|sbi|hdfc|icici|axis|paypal|amazon|irs|income tax|police|customs|government|fedex|dhl|ups|usps|"
    r"india post|royal mail|microsoft|apple|google|netflix|tech(?:nical)? support|help ?desk|security team|"
    r"fraud (?:department|team)|customer (?:care|support))\b",
)

# --------------------------------------------------------------------------
# URL handling
# --------------------------------------------------------------------------
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly",
    "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc", "rebrand.ly", "t.ly", "s.id",
}
SUSPICIOUS_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "zip",
                   "work", "loan", "icu", "monster", "country", "support"}
SENSITIVE_WORDS = {"login", "signin", "verify", "secure", "update", "account",
                   "wallet", "banking", "confirm", "support", "billing"}
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu"}
# brand token -> domains that really belong to that brand
BRAND_DOMAINS = {
    "paypal": ["paypal.com"], "amazon": ["amazon.com", "amazon.in", "amazon.co.uk"],
    "google": ["google.com"], "microsoft": ["microsoft.com", "live.com", "office.com"],
    "apple": ["apple.com", "icloud.com"], "netflix": ["netflix.com"],
    "facebook": ["facebook.com"], "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"], "sbi": ["sbi.co.in", "onlinesbi.sbi"],
    "hdfcbank": ["hdfcbank.com"], "icicibank": ["icicibank.com"],
    "paytm": ["paytm.com"], "fedex": ["fedex.com"], "dhl": ["dhl.com"],
    "irs": ["irs.gov"],
}

URL_RULES = {  # id -> (points, description)
    "shortened": (20, "The message contains a shortened URL that hides its real destination."),
    "ip_host": (15, "A link uses a raw IP address instead of a normal domain name."),
    "brand_mismatch": (18, "A link's hostname contains a well-known brand name but is not that brand's real domain."),
    "userinfo": (15, "A link contains '@', which can disguise the real destination."),
    "excess_subdomains": (8, "A link has an unusually large number of subdomains."),
    "suspicious_host": (8, "A link's hostname is built from many hyphens or sensitive words (e.g. login, verify, secure)."),
    "punycode": (10, "A link uses punycode (xn--), which can imitate look-alike characters."),
    "suspicious_tld": (6, "A link uses a top-level domain that is frequently abused."),
    "encoded": (6, "A link contains a lot of percent-encoded characters."),
    "malformed": (5, "A link has an unusual or invalid hostname structure."),
    "http": (3, "A link uses HTTP instead of HTTPS (a weak signal only; many harmless sites also lack HTTPS)."),
}

_SCHEME_URL = re.compile(r"(?:https?://|www\.)[^\s<>\"'`]+", re.IGNORECASE)
_BARE_URL = re.compile(
    r"(?<![@\w./-])(?:[a-z0-9-]+\.)+(?:com|net|org|in|xyz|top|info|co|io|ru|tk|ml|ga|cf|gq|click|online|site|link|biz|us|uk)"
    r"(?:/[^\s<>\"'`]*)?(?![\w@-])",
    re.IGNORECASE,
)
_HOST_OK = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_-]{1,63}\.)+[a-z0-9-]{2,63}$")
_TRAILING = ".,;:!?)]}>'\""


def extract_urls(text):
    """Find URL-looking strings in text (no network access). Order preserved, no duplicates."""
    found = []
    spans = []
    for pattern in (_SCHEME_URL, _BARE_URL):
        for m in pattern.finditer(text):
            if any(m.start() < e and m.end() > s for s, e in spans):
                continue  # already captured by the other pattern
            spans.append((m.start(), m.end()))
            candidate = m.group(0).rstrip(_TRAILING)
            if candidate and candidate not in found:
                found.append(candidate)
    return found


def _registered_domain(host):
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def inspect_url(url):
    """Statically inspect one URL. Returns {'url', 'host', 'issues': [ids]}."""
    issues = []
    host = ""
    has_scheme = re.match(r"^https?://", url, re.IGNORECASE) is not None
    try:
        parsed = urlparse(url if has_scheme else "http://" + url)
        host = (parsed.hostname or "").lower().rstrip(".")
        has_userinfo = parsed.username is not None
        parsed.port  # raises ValueError on an invalid port
    except ValueError:
        return {"url": url, "host": "", "issues": ["malformed"]}

    # Only flag HTTP when the user actually wrote "http://"
    if url.lower().startswith("http://"):
        issues.append("http")
    if has_userinfo:
        issues.append("userinfo")

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = host.isdigit()  # e.g. http://3232235777 (decimal IP trick)

    if is_ip:
        issues.append("ip_host")
    elif not host or not _HOST_OK.match(host):
        issues.append("malformed")
    else:
        registered = _registered_domain(host)
        labels = host.split(".")
        tokens = [t for t in re.split(r"[.\-_]", host) if t]

        if host in SHORTENERS or registered in SHORTENERS:
            issues.append("shortened")
        if len(labels) - len(registered.split(".")) >= 3:
            issues.append("excess_subdomains")
        if host.count("-") >= 3 or len({t for t in tokens if t in SENSITIVE_WORDS}) >= 2:
            issues.append("suspicious_host")
        if any(label.startswith("xn--") for label in labels):
            issues.append("punycode")
        if labels[-1] in SUSPICIOUS_TLDS:
            issues.append("suspicious_tld")
        for brand, official in BRAND_DOMAINS.items():
            brand_in_host = any(t == brand or (len(brand) >= 5 and brand in t) for t in tokens)
            is_official = any(host == d or host.endswith("." + d) for d in official)
            if brand_in_host and not is_official:
                issues.append("brand_mismatch")
                break

    if len(re.findall(r"%[0-9a-fA-F]{2}", url)) >= 4:
        issues.append("encoded")
    return {"url": url, "host": host, "issues": issues}


# --------------------------------------------------------------------------
# Recommendations
# --------------------------------------------------------------------------
def _build_recommendations(found_ids, has_links, level):
    recs = []
    if has_links or "link" in found_ids:
        recs.append("Do not click suspicious links. Type the organization's official address into your browser yourself.")
    if found_ids & {"otp_request", "password_request", "bank_credentials", "confirm_login"}:
        recs.append("Never share OTPs, passwords, PINs or card details. Real banks and companies do not ask for them by message.")
    if found_ids & {"prize_claim", "lottery", "fake_refund", "payment_request", "money_transfer", "payment_verification"}:
        recs.append("Be sceptical of unexpected prizes, refunds or payment demands. Never pay a 'fee' to receive money.")
    if "risky_attachment" in found_ids:
        recs.append("Do not open or install unexpected attachments or apps.")
    if found_ids & {"urgent_action", "account_threat", "deadline"}:
        recs.append("Slow down. Scammers use pressure and short deadlines to stop you from thinking.")
    if level in ("Medium", "High", "Critical"):
        recs.append("Verify the request using the organization's official website or verified contact details, not details in the message.")
        recs.append("Report the message through the appropriate official channel if it appears fraudulent.")
    if level in ("High", "Critical"):
        recs.append("Delete the message. If you already shared information or money, contact your bank or provider right away.")
    if not recs:
        recs.append("No strong warning signs were found, but stay alert. If anything feels off, verify through official channels.")
    return recs


# --------------------------------------------------------------------------
# Main entry point
# --------------------------------------------------------------------------
def _resolve_input_type(text, input_type, urls):
    if input_type in ("email_sms", "url"):
        return input_type
    # auto: a single URL-looking token is treated as a URL
    if urls and len(text.split()) == 1:
        return "url"
    return "email_sms"


def analyze_content(text, input_type="auto"):
    """
    Analyse text/URL and return a dictionary:
      risk_score, risk_level, detected_indicators, suspicious_phrases,
      detected_urls, recommendations, input_type, summary, score_breakdown, disclaimer
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if input_type not in VALID_INPUT_TYPES:
        raise ValueError("input_type must be one of: " + ", ".join(VALID_INPUT_TYPES))

    clean = normalize_text(text)
    urls = extract_urls(clean)
    if input_type == "url" and not urls and clean and not re.search(r"\s", clean):
        urls = [clean]  # user pasted a bare host such as "example"; inspect it anyway
    resolved_type = _resolve_input_type(clean, input_type, urls)

    disclaimer = ("This score is a heuristic estimate from static rules, not a verified probability. "
                  "PhishGuard does not visit links or check live reputation, and a low score does not guarantee safety.")

    if not clean:
        return {
            "risk_score": 0, "risk_level": "Low", "detected_indicators": [],
            "suspicious_phrases": [], "detected_urls": [], "recommendations": _build_recommendations(set(), False, "Low"),
            "input_type": resolved_type, "summary": "There was no content to analyse.",
            "score_breakdown": [], "disclaimer": disclaimer,
        }

    indicators = []  # each: id, category, description, points, evidence
    phrases = []

    def add(ind_id, category, points, description, evidence):
        indicators.append({"id": ind_id, "category": category, "category_label": CATEGORY_LABELS[category],
                           "description": description, "points": points, "evidence": evidence})
        for e in evidence:
            if e and e not in phrases:
                phrases.append(e)

    # 1. Text rules (each rule fires at most once -> no keyword-repetition inflation)
    searchable = _SAFE_ADVICE.sub(" ", clean)
    for rule_id, category, points, description, pattern in TEXT_RULES:
        match = re.search(pattern, searchable, re.IGNORECASE)
        if match:
            add(rule_id, category, points, description, [match.group(0).strip()])

    # 2. Impersonation (only alongside other warning signs)
    imp_id, imp_cat, imp_pts, imp_desc, imp_pattern = IMPERSONATION_RULE
    match = re.search(imp_pattern, searchable, re.IGNORECASE)
    if match and indicators:
        add(imp_id, imp_cat, imp_pts, imp_desc, [match.group(0).strip()])

    # 3. URL rules: one indicator per issue type, listing every URL affected
    url_details = [inspect_url(u) for u in urls]
    issue_urls = {}
    for detail in url_details:
        for issue in detail["issues"]:
            issue_urls.setdefault(issue, []).append(detail["url"])
    for issue, (points, description) in URL_RULES.items():
        if issue in issue_urls:
            indicators.append({"id": "url_" + issue, "category": "links", "category_label": CATEGORY_LABELS["links"],
                               "description": description, "points": points, "evidence": issue_urls[issue]})
    for detail in url_details:
        detail["issue_descriptions"] = [URL_RULES[i][1] for i in detail["issues"]]

    # 4. Combination bonuses (strong signals reinforcing each other)
    ids = {i["id"] for i in indicators}
    cats = {i["category"] for i in indicators}
    bad_link = any(i["id"].startswith("url_") and i["id"] != "url_http" for i in indicators)
    any_link = bool(urls)
    combos = []
    if "credential" in cats and bad_link:
        combos.append(("combo_cred_link", 15, "A request for sensitive information appears together with a suspicious link."))
    if "credential" in cats and "urgency" in cats:
        combos.append(("combo_cred_urgency", 10, "A request for sensitive information is combined with urgency or threats."))
    if "urgency" in cats and any_link:
        combos.append(("combo_urgency_link", 6, "Urgency or threats come with a link to click."))
    if "financial" in cats and bad_link:
        combos.append(("combo_money_link", 8, "A money-related claim appears together with a suspicious link."))
    for combo_id, points, description in combos:
        indicators.append({"id": combo_id, "category": "combination", "category_label": CATEGORY_LABELS["combination"],
                           "description": description, "points": points, "evidence": []})

    # 5. Weighted score with per-category caps
    breakdown = []
    total = 0
    for category, label in CATEGORY_LABELS.items():
        raw = sum(i["points"] for i in indicators if i["category"] == category)
        if raw == 0:
            continue
        awarded = min(raw, CATEGORY_CAPS[category])
        breakdown.append({"category": label, "points": awarded, "raw_points": raw, "capped": raw > awarded})
        total += awarded
    score = max(0, min(100, total))
    level = get_risk_level(score)

    # 6. Friendly summary and recommendations
    found_ids = ids | ({"link"} if bad_link else set())
    if not indicators:
        summary = "No common phishing or scam warning signs were found. This does not guarantee the content is safe."
    else:
        top = sorted(indicators, key=lambda i: -i["points"])[:2]
        reasons = " ".join(i["description"] for i in top)
        summary = f"{level} risk ({score}/100). Main reasons: {reasons}"

    return {
        "risk_score": score, "risk_level": level, "detected_indicators": indicators,
        "suspicious_phrases": phrases, "detected_urls": url_details,
        "recommendations": _build_recommendations(found_ids, bad_link, level),
        "input_type": resolved_type, "summary": summary,
        "score_breakdown": breakdown, "disclaimer": disclaimer,
    }
