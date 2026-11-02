"""
Non-ML security intelligence layer for AI Phishing & Impersonation Defense.
Purely structural / static analysis. It NEVER opens, fetches or resolves a URL.
Output is JSON-serialisable so the ML / UI / Slack / extension members can consume it.
"""
import json, re
from pathlib import Path
from urllib.parse import urlparse, unquote

HERE = Path(__file__).parent

# ----------------------------------------------------------------- Task 1: indicators
# id, category, why it matters, regex (detection), weight
INDICATORS = [
    ("URG-01", "Urgency / pressure",
     "Attackers rush victims so they skip verification.",
     r"\b(urgent(ly)?|immediately|act now|within \d+ ?(hours?|hrs?|minutes?)|last warning|final notice|expires? (today|soon)|right away)\b", 15),
    ("URG-02", "Urgency / pressure",
     "Threats of loss or punishment create fear.",
     r"\b(account (will be |has been )?(suspended|blocked|closed|locked|deactivated)|legal action|penalty|arrest|permanently (deleted|disabled))\b", 15),
    ("INFO-01", "Sensitive-information request",
     "Legitimate organisations do not ask for secrets over email/chat.",
     r"\b(password|otp|one[- ]time (password|code)|\bpin\b|cvv|card number|aadhaar|pan (number|card)|login (details|credentials)|verify your (account|identity|details)|confirm your (account|identity|details))\b", 25),
    ("PAY-01", "Unusual payment request",
     "Gift cards, crypto, wire/UPI 'fees' are hard to reverse and favoured by scammers.",
     r"\b(gift ?cards?|wire transfer|crypto(currency)?|bitcoin|western union|processing fee|refund fee|send money|pay (a |the )?fee|upi (id|request))\b", 20),
    ("ID-01", "Unverified identity claim",
     "Authority is claimed but cannot be verified from the message itself.",
     r"\b(i am from|this is (the )?(security|support|it|fraud|risk) (team|department)|official notice|bank manager|customer care executive|on behalf of)\b", 10),
    ("INS-01", "Suspicious instruction",
     "Pushes the user to take an unsafe action (click, download, scan, keep secret).",
     r"\b(click (on )?(the |this )?(link|button)|download (the )?attach(ment|ed)|open (the )?attach(ment|ed)|scan (the |this )?qr|install (the |this )?(app|software|update)|do not (tell|share)|keep (this )?confidential|reply with)\b", 15),
    ("LURE-01", "Too-good-to-be-true lure",
     "Prizes and rewards are a classic bait to collect data or fees.",
     r"\b(you (have )?won|lottery|prize|claim your (reward|gift|prize)|cashback offer|free (gift|iphone))\b", 12),
    ("GEN-01", "Generic greeting",
     "Real providers usually address you by name.",
     r"\bdear (customer|user|sir|madam|account holder|valued member)\b", 5),
]
_COMPILED = [(i, c, w_, re.compile(rx, re.I), wt) for i, c, w_, rx, wt in INDICATORS]

# ----------------------------------------------------------------- Task 3: trusted reference
def load_entities(path=HERE / "trusted_entities.json"):
    return json.loads(Path(path).read_text(encoding="utf-8"))["entities"]

ENTITIES = load_entities()

# ----------------------------------------------------------------- Task 2: URL analyzer
MULTI_TLD = {"co.in", "gov.in", "org.in", "ac.in", "net.in", "co.uk", "org.uk", "com.au", "co.jp", "bank.in"}
SUSPICIOUS_TLDS = {"xyz", "top", "click", "icu", "tk", "ml", "ga", "cf", "gq", "work", "support", "zip", "mov", "rest", "buzz"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "shorturl.at"}
URL_KEYWORDS = {"login", "signin", "verify", "secure", "account", "update", "confirm", "banking", "wallet", "password", "support", "billing"}
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "@": "a"})
URL_RE = re.compile(r"(https?://[^\s<>\"')]+|www\.[^\s<>\"')]+)", re.I)

def registered_domain(host):
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_TLD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host

def levenshtein(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]

def _normalise_label(label):
    return label.lower().translate(HOMOGLYPHS).replace("rn", "m").replace("vv", "w")

def is_official(domain):
    return any(domain == d or domain.endswith("." + d) for e in ENTITIES for d in e["official_domains"])

def lookalike_of(domain):
    """Return (entity_name, official_domain) if `domain` imitates a trusted domain, else None."""
    if is_official(domain):
        return None
    label = domain.split(".")[0]
    norm = _normalise_label(label)
    for e in ENTITIES:
        for off in e["official_domains"]:
            off_label = off.split(".")[0]
            if len(off_label) < 4:
                continue
            if norm == off_label or (levenshtein(norm, off_label) <= 1 and len(off_label) >= 5):
                return e["name"], off
    return None

def extract_urls(text):
    return [u.rstrip(".,;") for u in URL_RE.findall(text or "")]

def analyze_url(url):
    raw = url if "://" in url else "http://" + url
    p = urlparse(raw)
    host = (p.hostname or "").lower()
    reg = registered_domain(host)
    sub_labels = host[: -len(reg)].strip(".").split(".") if host.endswith(reg) and host != reg else []
    sub_count = len([s for s in sub_labels if s])
    tokens = set(re.split(r"[^a-z0-9]+", (host + " " + unquote(p.path)).lower()))
    signals = []

    def add(code, desc, w):
        signals.append({"code": code, "description": desc, "weight": w})

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        add("URL-IP", "Host is a raw IP address instead of a domain name", 25)
    if "@" in p.netloc:
        add("URL-AT", "Contains '@' - text before it is ignored by browsers and hides the real host", 20)
    if "xn--" in host:
        add("URL-PUNY", "Punycode domain (possible lookalike characters)", 20)
    if len(url) > 75:
        add("URL-LEN", f"Unusually long URL ({len(url)} chars)", 8)
    if sub_count >= 3:
        add("URL-SUB", f"{sub_count} subdomain levels - used to bury the real domain", 10)
    if host.count("-") >= 3:
        add("URL-HYPH", "Many hyphens in host name", 8)
    if reg.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        add("URL-TLD", f"Top-level domain '.{reg.rsplit('.', 1)[-1]}' is frequently abused", 10)
    if reg in SHORTENERS:
        add("URL-SHORT", "URL shortener hides the final destination", 10)
    if p.scheme == "http":
        add("URL-HTTP", "Not using HTTPS", 8)
    if sum(c.isdigit() for c in host) / max(len(host), 1) > 0.3 and "URL-IP" not in [s["code"] for s in signals]:
        add("URL-DIGITS", "High share of digits in host name", 6)
    if len(tokens & URL_KEYWORDS) >= 2:
        add("URL-KW", "Several credential/security words in URL: " + ", ".join(sorted(tokens & URL_KEYWORDS)), 8)
    if "%" in p.path and re.search(r"%[0-9a-f]{2}", p.path, re.I):
        add("URL-ENC", "Percent-encoded characters in path", 5)

    off_flag = False
    look = lookalike_of(reg)
    if look:
        add("URL-LOOK", f"Domain '{reg}' imitates {look[0]} ({look[1]})", 30)
        off_flag = True
    if not off_flag and not is_official(reg):
        for e in ENTITIES:
            hit = [a for a in e["aliases"] if " " not in a and a in tokens]
            if hit:
                add("URL-BRAND", f"Mentions '{hit[0]}' ({e['name']}) but registered domain is '{reg}', not official", 25)
                break

    score = min(100, sum(s["weight"] for s in signals))
    return {"url": url, "host": host, "registered_domain": reg, "subdomains": sub_count,
            "length": len(url), "signals": signals, "score": score, "level": level(score)}

# ----------------------------------------------------------------- Task 3: impersonation logic
def claimed_entities(text, sender_name=""):
    blob = f"{sender_name}\n{text}".lower()
    found = []
    for e in ENTITIES:
        for a in e["aliases"]:
            if re.search(r"\b" + re.escape(a) + r"\b", blob):
                found.append(e)
                break
    return found

def analyze_impersonation(text, sender_email="", sender_name="", urls=None):
    urls = urls if urls is not None else extract_urls(text)
    sender_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
    sender_reg = registered_domain(sender_domain) if sender_domain else ""
    findings = []
    for e in claimed_entities(text, sender_name):
        off = set(e["official_domains"])
        if sender_reg and not any(sender_reg == d or sender_reg.endswith("." + d) for d in off):
            findings.append({"code": "IMP-01", "entity": e["name"], "weight": 30,
                             "description": f"Claims to be {e['name']} but sender domain '{sender_reg}' is not in trusted list ({', '.join(sorted(off))})"})
        bad = [registered_domain(urlparse(u if '://' in u else 'http://' + u).hostname or "") for u in urls]
        bad = sorted({d for d in bad if d and not any(d == o or d.endswith("." + o) for o in off)})
        if bad:
            findings.append({"code": "IMP-02", "entity": e["name"], "weight": 25,
                             "description": f"Mentions {e['name']} but links point to non-official domain(s): {', '.join(bad)}"})
    if sender_reg:
        look = lookalike_of(sender_reg)
        if look:
            findings.append({"code": "IMP-03", "entity": look[0], "weight": 25,
                             "description": f"Sender domain '{sender_reg}' looks like {look[1]}"})
    return findings

# ----------------------------------------------------------------- scoring
# Risk bands (recommended): 0-24 Low | 25-49 Medium | 50-74 High | 75-100 Critical
def level(score):
    return "Low" if score < 25 else "Medium" if score < 50 else "High" if score < 75 else "Critical"

ACTIONS = {
    "Low": "No strong warning signs. Still avoid sharing secrets and use the official app/site if unsure.",
    "Medium": "Be careful. Do not click links or reply; verify through the organisation's official website or app.",
    "High": "Likely phishing. Do not click, reply or share anything. Report it and delete the message.",
    "Critical": "Almost certainly malicious. Do not interact. Report/block the sender; if you already clicked or shared details, change passwords and contact your bank/provider now.",
}

def analyze_message(text, sender_email="", sender_name="", urls=None):
    urls = urls if urls is not None else extract_urls(text)
    ind = [{"id": i, "category": c, "why": w_, "weight": wt} for i, c, w_, rx, wt in _COMPILED if rx.search(text or "")]
    url_res = [analyze_url(u) for u in urls]
    imp = analyze_impersonation(text, sender_email, sender_name, urls)
    msg_score = sum(i["weight"] for i in ind)
    url_score = max((u["score"] for u in url_res), default=0)
    imp_score = sum(f["weight"] for f in imp)
    total = min(100, msg_score + url_score + imp_score)
    return {"score": total, "level": level(total), "recommended_action": ACTIONS[level(total)],
            "breakdown": {"message_indicators": msg_score, "url": url_score, "impersonation": imp_score},
            "indicators": ind, "urls": url_res, "impersonation": imp}

if __name__ == "__main__":
    import sys
    print(json.dumps(analyze_message(sys.stdin.read()), indent=2))
