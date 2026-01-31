import re
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DOMAIN_RE = re.compile(r'@([A-Za-z0-9.-]+)')


def _extract_domain(header_value: str) -> str:
    m = _DOMAIN_RE.search(header_value)
    if m:
        return m.group(1).lower().rstrip(".")
    return ""


_IP_HOST_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

_URGENCY_WORDS = [
    "urgent", "immediately", "verify", "suspend", "expire",
    "confirm", "unauthorized", "alert", "locked", "restricted",
    "action required", "account", "click here", "update your",
    "within 24 hours", "limited time",
    "xrp", "bitcoin", "crypto",
    "disabled", "temporary",
]

_DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js",
    ".vbs", ".wsf", ".msi", ".jar", ".zip", ".rar", ".7z",
    ".html", ".htm", ".iso", ".img",
}

_KNOWN_BRANDS = {
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.co.jp"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com"],
    "google": ["google.com", "gmail.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "wells fargo": ["wellsfargo.com"],
    "bank of america": ["bankofamerica.com"],
    "citi": ["citi.com", "citibank.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "meta": ["meta.com", "facebook.com"],
    "instagram": ["instagram.com"],
    "ups": ["ups.com"],
    "fedex": ["fedex.com"],
    "dhl": ["dhl.com"],
    "usps": ["usps.com"],
    "whatsapp": ["whatsapp.com"],
    "telegram": ["telegram.org"],
    "discord": ["discord.com"],
    "steam": ["steampowered.com"],
    "dropbox": ["dropbox.com"],
    "linkedin": ["linkedin.com"],
    "tether": ["tether.to"],
    "ripple": ["ripple.com"],
}

# Brands whose names are common English words. These require nearby context
# keywords to confirm the text is referencing the company, not the word.
# Brands NOT in this dict are unambiguous and always flagged.
_AMBIGUOUS_BRANDS = {
    "apple": [
        "apple id", "icloud", "iphone", "ipad", "macbook", "imac", "itunes",
        "app store", "apple pay", "apple account", "apple support",
    ],
    "chase": [
        "chase bank", "chase account", "credit card", "debit card",
        "chase online", "chase login", "chase verify",
    ],
    "steam": [
        "steam account", "steam guard", "steam wallet", "steam login",
        "steam community", "steam gift", "steampowered", "steam trade",
    ],
    "ups": [
        "ups package", "ups tracking", "ups delivery", "ups shipment",
        "ups shipping", "ups driver", "ups label", "ups freight",
    ],
    "discord": [
        "discord server", "discord account", "discord nitro", "discord login",
        "discord token", "discord invite", "discord verify",
    ],
    "meta": [
        "meta account", "meta business", "meta verify", "meta support",
        "facebook", "instagram", "meta ad", "meta platform",
    ],
    "citi": [
        "citi bank", "citibank", "citi account", "citi card",
        "citi credit", "citi login", "citi online",
    ],
    "telegram": [
        "telegram account", "telegram app", "telegram group", "telegram bot",
        "telegram login", "telegram code", "telegram verify",
    ],
    "ripple": [
        "ripple xrp", "ripple wallet", "ripple token", "ripple account",
        "ripple coin", "ripple crypto", "ripple exchange",
    ],
    "tether": [
        "tether usdt", "tether wallet", "tether token", "tether account",
        "tether crypto", "tether exchange", "tether coin",
    ],
}

_SUSPICIOUS_TLDS = {
    "shop", "xyz", "click", "beauty", "top", "buzz", "live", "life",
    "online", "site", "club", "icu", "fun", "work", "rest", "fit",
    "surf", "quest", "sbs", "tk", "ml", "ga", "cf", "gq",
}

_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "shorturl.at", "cutt.ly", "rb.gy",
    "trib.al", "v.gd",
}

# Patterns indicating a hacked CMS site being used for phishing
_HACKED_CMS_RE = re.compile(
    r'/(?:'
    r'wp-(?:content|includes|admin|track|login|config)'
    r'|wp-[a-z]+-?[a-z]*\.php'          # wp-*.php variants
    r'|xmlrpc\.php'
    r'|administrator/'
    r'|joomla/'
    r'|drupal/'
    r'|sites/default/files/'
    r'|misc/.*\.php'
    r'|modules/.*\.php'
    r'|components/com_'
    r'|magento/'
    r'|skin/frontend/'
    r'|downloader/'
    r'|cgi-bin/.*\.php'
    r')',
    re.IGNORECASE,
)

# Well-known mail provider domains and their expected HELO IP ranges/hostnames.
# Maps the domain a HELO might claim to hostnames that should appear in the
# reverse DNS lookup (the parenthesized name in Received headers).
_KNOWN_HELO_DOMAINS = {
    "smtp.gmail.com": ["google.com"],
    "gmail-smtp": ["google.com"],
    "mail.yahoo.com": ["yahoo.com"],
    "smtp.office365.com": ["outlook.com", "microsoft.com"],
    "smtp-mail.outlook.com": ["outlook.com", "microsoft.com"],
    "smtp.mail.me.com": ["apple.com", "icloud.com", "me.com"],
    "smtp.zoho.com": ["zoho.com"],
    "smtp.aol.com": ["aol.com"],
    "smtp.protonmail.ch": ["protonmail.ch", "proton.me"],
    "smtp.fastmail.com": ["fastmail.com", "messagingengine.com"],
}

# Regex to parse a Received header into HELO name, reverse-DNS, and IP.
# Matches patterns like: from smtp.gmail.com (unknown [43.230.161.16])
# or: from smtp.gmail.com (mail-wr1-f54.google.com [209.85.221.54])
_RECEIVED_FROM_RE = re.compile(
    r'from\s+(\S+)\s+\(([^)]*)\)',
    re.IGNORECASE,
)

# Feature weights for final score
_WEIGHTS = {
    "sender_integrity": 0.20,      # merged sender_mismatch + reply_to_mismatch
    "auth_headers": 0.18,
    "suspicious_urls": 0.14,
    "brand_impersonation": 0.10,
    "image_only_email": 0.08,
    "gibberish_text": 0.08,
    "urgency_language": 0.06,
    "header_anomalies": 0.06,
    "attachment_risk": 0.06,
    "html_forms": 0.04,
}

# Common English words used to measure whether text is real language
_COMMON_WORDS = {
    "the", "be", "to", "of", "and", "a", "in", "that", "have", "i",
    "it", "for", "not", "on", "with", "he", "as", "you", "do", "at",
    "this", "but", "his", "by", "from", "they", "we", "say", "her",
    "she", "or", "an", "will", "my", "one", "all", "would", "there",
    "their", "what", "so", "up", "out", "if", "about", "who", "get",
    "which", "go", "me", "when", "make", "can", "like", "time", "no",
    "just", "him", "know", "take", "people", "into", "year", "your",
    "good", "some", "could", "them", "see", "other", "than", "then",
    "now", "look", "only", "come", "its", "over", "think", "also",
    "back", "after", "use", "two", "how", "our", "work", "first",
    "well", "way", "even", "new", "want", "because", "any", "these",
    "give", "day", "most", "us", "is", "are", "was", "were", "been",
    "has", "had", "did", "does", "am", "being", "here", "more",
    "please", "dear", "hello", "thank", "thanks", "best", "regards",
}

# ---------------------------------------------------------------------------
# Individual analyzers — each returns {"score": float, "details": ...}
# ---------------------------------------------------------------------------


def check_sender_integrity(parsed: dict) -> dict:
    """Check consistency of From, Return-Path, and Reply-To domains.

    Sub-checks:
    1. Return-Path domain vs From domain (0.5 contribution).
    2. Reply-To domain vs From domain (0.5 contribution).
    Both mismatches together produce a score of 1.0.
    """
    from_domain = _extract_domain(parsed["from"])
    issues = []

    if not from_domain:
        return {"score": 0.5, "details": "Could not extract From domain"}

    # Sub-check 1: Return-Path mismatch
    rp_domain = _extract_domain(parsed["return_path"])
    rp_score = 0.0
    if rp_domain and rp_domain != from_domain:
        issues.append(f"Return-Path domain '{rp_domain}' differs from From domain '{from_domain}'")
        rp_score = 0.5
    elif not rp_domain:
        pass  # No Return-Path is not suspicious on its own

    # Sub-check 2: Reply-To mismatch
    reply_to = parsed.get("reply_to", "")
    rt_score = 0.0
    if reply_to:
        rt_domain = _extract_domain(reply_to)
        if rt_domain and rt_domain != from_domain:
            issues.append(f"Reply-To domain '{rt_domain}' differs from From domain '{from_domain}'")
            rt_score = 0.5

    if not issues:
        return {"score": 0.0, "details": "Sender headers are consistent"}

    score = min(1.0, rp_score + rt_score)
    return {"score": score, "details": issues}


def check_suspicious_urls(parsed: dict) -> dict:
    urls = parsed.get("urls", [])
    if not urls:
        return {"score": 0.0, "details": "No URLs found"}

    major_issues: list[str] = []
    minor_issues: list[str] = []
    for entry in urls:
        href = entry["href"]
        text = entry.get("text", "")
        try:
            p = urlparse(href)
        except Exception:
            continue

        hostname = (p.hostname or "").lower()

        # IP address as host
        if _IP_HOST_RE.match(hostname):
            major_issues.append(f"URL uses IP address: {href}")

        # Excessive subdomains (more than 3 levels)
        if hostname.count(".") > 3:
            major_issues.append(f"Excessive subdomains: {hostname}")

        # Anchor text looks like a different domain
        if text:
            text_domain = _extract_domain("@" + text) if "." in text else ""
            if text_domain and hostname and text_domain != hostname:
                # text itself looks like a domain/URL
                if re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', text.strip().lower()):
                    major_issues.append(f"Anchor text '{text}' links to '{hostname}'")

        # Suspicious TLD
        if hostname:
            tld = hostname.rsplit(".", 1)[-1]
            if tld in _SUSPICIOUS_TLDS:
                minor_issues.append(f"Suspicious TLD '.{tld}': {hostname}")

        # URL shortener
        if hostname in _URL_SHORTENERS:
            minor_issues.append(f"URL shortener: {hostname}")

        # Hacked CMS site
        path = (p.path or "").lower()
        if path and _HACKED_CMS_RE.search(path):
            minor_issues.append(f"Possible hacked CMS path: {hostname}{p.path}")

    if not major_issues and not minor_issues:
        return {"score": 0.0, "details": "URLs look normal"}

    score = min(1.0, len(major_issues) * 0.4 + len(minor_issues) * 0.2)
    return {"score": score, "details": major_issues + minor_issues}


def check_urgency_language(parsed: dict) -> dict:
    text = (parsed.get("subject", "") + " " + parsed.get("plain_body", "")).lower()
    if parsed.get("html_body"):
        text += " " + parsed["html_body"].lower()

    found = [w for w in _URGENCY_WORDS if w in text]
    if not found:
        return {"score": 0.0, "details": "No urgency language detected"}

    score = min(1.0, len(found) * 0.15)
    return {"score": round(score, 2), "details": found}


def check_auth_headers(parsed: dict) -> dict:
    auth = parsed.get("auth_results", "").lower()
    spf = parsed.get("received_spf", "").lower()
    combined = auth + " " + spf

    parts = []
    spf_status = "missing"
    dkim_status = "missing"
    dmarc_status = "missing"

    if "spf=pass" in combined or "pass" in spf:
        spf_status = "pass"
    elif "spf=fail" in combined or "spf=softfail" in combined or "fail" in spf:
        spf_status = "fail"

    if "dkim=pass" in combined:
        dkim_status = "pass"
    elif "dkim=fail" in combined:
        dkim_status = "fail"

    if "dmarc=pass" in combined:
        dmarc_status = "pass"
    elif "dmarc=fail" in combined:
        dmarc_status = "fail"

    parts.append(f"SPF: {spf_status}")
    parts.append(f"DKIM: {dkim_status}")
    parts.append(f"DMARC: {dmarc_status}")

    fail_count = sum(1 for s in [spf_status, dkim_status, dmarc_status] if s in ("fail", "missing"))
    # If no auth headers at all, moderate signal
    if not auth.strip() and not spf.strip():
        return {"score": 0.5, "details": "No authentication headers present"}

    # SPF alone is insufficient — attackers can pass SPF by controlling
    # their own domain's DNS.  If SPF passes but both DKIM and DMARC are
    # missing, the email has no cryptographic or policy verification.
    if spf_status == "pass" and dkim_status == "missing" and dmarc_status == "missing":
        return {"score": 1.0, "details": ", ".join(parts) + " (SPF pass alone is insufficient)"}

    score = round(fail_count / 3, 2)
    return {"score": score, "details": ", ".join(parts)}


def check_attachment_risk(parsed: dict) -> dict:
    attachments = parsed.get("attachments", [])
    if not attachments:
        return {"score": 0.0, "details": "No attachments"}

    risky = []
    for att in attachments:
        fn = att.get("filename", "").lower()
        for ext in _DANGEROUS_EXTENSIONS:
            if fn.endswith(ext):
                risky.append(fn)
                break

    if not risky:
        return {"score": 0.0, "details": "Attachments appear safe"}

    score = min(1.0, len(risky) * 0.5)
    return {"score": score, "details": [f"Risky attachment: {f}" for f in risky]}


def check_html_forms(parsed: dict) -> dict:
    if parsed.get("has_forms"):
        return {"score": 1.0, "details": "HTML <form> tag detected"}
    if parsed.get("has_inputs"):
        return {"score": 0.7, "details": "HTML <input> tag detected without <form>"}
    return {"score": 0.0, "details": "No forms detected"}


def check_header_anomalies(parsed: dict) -> dict:
    issues: list[str] = []

    if not parsed.get("message_id"):
        issues.append("Missing Message-ID")

    if not parsed.get("date"):
        issues.append("Missing Date header")

    x_mailer = parsed.get("x_mailer", "")
    if x_mailer:
        suspicious_mailers = ["phpmailer", "swiftmailer", "king mailer", "leaf mailer"]
        if any(s in x_mailer.lower() for s in suspicious_mailers):
            issues.append(f"Suspicious X-Mailer: {x_mailer}")

    # HELO spoofing: check if any Received header claims a well-known mail
    # provider HELO but the connecting host doesn't match that provider.
    for received in parsed.get("received_headers", []):
        m = _RECEIVED_FROM_RE.search(received)
        if not m:
            continue
        helo_name = m.group(1).lower().strip()
        paren_info = m.group(2).lower().strip()

        for known_helo, legit_suffixes in _KNOWN_HELO_DOMAINS.items():
            if known_helo not in helo_name:
                continue
            # Check if the parenthesized reverse-DNS contains a legitimate suffix
            is_legit = any(suffix in paren_info for suffix in legit_suffixes)
            if not is_legit:
                issues.append(
                    f"HELO spoofing: claims '{helo_name}' but connecting host is '{paren_info}'"
                )
            break

    if not issues:
        return {"score": 0.0, "details": "Headers look normal"}

    score = min(1.0, len(issues) * 0.3)
    return {"score": round(score, 2), "details": issues}


def check_gibberish_text(parsed: dict) -> dict:
    """Detect random/gibberish text used to pad emails and bypass spam filters.

    Uses five signals:
    1. Low ratio of real English words to total words (nonsense padding).
    2. High ratio of long consonant clusters (random character strings).
    3. Very low word length variance (uniform random strings).
    4. Subject line obfuscation (heavy MIME encoding, trailing gibberish, excessive special chars).
    5. Homoglyph/non-ASCII characters in From or Subject headers.
    """
    # Combine plain text and strip HTML tags from HTML body for analysis
    text = parsed.get("plain_body", "")
    html = parsed.get("html_body", "")
    if html:
        # Crude tag stripping for analysis purposes
        stripped = re.sub(r'<[^>]+>', ' ', html)
        # Remove HTML entities
        stripped = re.sub(r'&[a-zA-Z]+;', ' ', stripped)
        text = text + " " + stripped

    # Extract words (sequences of alpha characters)
    words = re.findall(r'[a-zA-Z]{2,}', text.lower())

    issues = []

    if len(words) >= 10:
        # Signal 1: What fraction of words are recognizable English?
        recognized = sum(1 for w in words if w in _COMMON_WORDS)
        real_word_ratio = recognized / len(words)
        # In normal email, at least 15-20% of words are common English words.
        # Gibberish text will have near 0%.
        if real_word_ratio < 0.05:
            issues.append(f"Very low real-word ratio: {real_word_ratio:.1%} of {len(words)} words")
        elif real_word_ratio < 0.10:
            issues.append(f"Low real-word ratio: {real_word_ratio:.1%} of {len(words)} words")

        # Signal 2: Consonant cluster density — random strings produce long
        # runs of consonants that don't appear in natural language.
        consonant_runs = re.findall(r'[bcdfghjklmnpqrstvwxyz]{5,}', text.lower())
        cluster_ratio = len(consonant_runs) / len(words) if words else 0
        if cluster_ratio > 0.15:
            issues.append(f"High consonant-cluster density: {len(consonant_runs)} clusters in {len(words)} words")
        elif cluster_ratio > 0.08:
            issues.append(f"Elevated consonant-cluster density: {len(consonant_runs)} clusters in {len(words)} words")

        # Signal 3: Average word length for non-common words. Gibberish tends
        # toward uniformly long random strings.
        non_common = [w for w in words if w not in _COMMON_WORDS]
        if len(non_common) > 10:
            avg_len = sum(len(w) for w in non_common) / len(non_common)
            long_words = sum(1 for w in non_common if len(w) > 12)
            long_ratio = long_words / len(non_common)
            if long_ratio > 0.3:
                issues.append(f"High ratio of very long words: {long_ratio:.0%} over 12 chars")
            elif avg_len > 10:
                issues.append(f"Unusually high average word length: {avg_len:.1f} chars")

    # Signal 4: Subject line obfuscation
    subject = parsed.get("subject", "")
    if subject:
        # Heavy MIME encoding — flag if over 50% of subject is encoded content
        mime_pattern = re.compile(r'=\?[^?]+\?[BbQq]\?[^?]*\?=')
        mime_matches = mime_pattern.findall(subject)
        total_encoded_len = sum(len(m) for m in mime_matches)
        if len(subject) > 0 and total_encoded_len / len(subject) > 0.5:
            issues.append(f"Heavy MIME encoding in subject ({total_encoded_len}/{len(subject)} chars)")

        # Trailing non-word gibberish after real text
        trailing_gibberish = re.search(r'\w{3,}\s+[^\w\s]{3,}\s*$', subject)
        if trailing_gibberish:
            issues.append("Trailing gibberish characters in subject")

        # Excessive emoji/special characters
        special_chars = re.findall(r'[^\w\s.,!?;:\'"()\-/]', subject)
        if len(subject) > 5 and len(special_chars) / len(subject) > 0.3:
            issues.append(f"Excessive special characters in subject: {len(special_chars)} in {len(subject)} chars")

    # Signal 5: Homoglyph/non-ASCII in headers
    from_header = parsed.get("from", "")
    if from_header:
        non_ascii_from = [c for c in from_header if ord(c) > 127]
        if non_ascii_from:
            issues.append(f"Non-ASCII characters in From address ({len(non_ascii_from)} chars)")

    if subject:
        # Strip out MIME encoding headers before checking for non-ASCII
        subject_stripped = re.sub(r'=\?[^?]+\?[BbQq]\?[^?]*\?=', '', subject)
        non_ascii_subj = [c for c in subject_stripped if ord(c) > 127]
        if non_ascii_subj:
            issues.append(f"Non-ASCII characters in Subject ({len(non_ascii_subj)} chars)")

    if not issues:
        return {"score": 0.0, "details": "Text appears normal"}

    # Signals 1-3 contribute 0.35 each, signals 4-5 contribute 0.25 each
    body_signal_count = 0
    header_signal_count = 0
    for issue in issues:
        if any(kw in issue for kw in ("real-word ratio", "consonant-cluster", "long words", "word length")):
            body_signal_count += 1
        else:
            header_signal_count += 1

    score = min(1.0, body_signal_count * 0.35 + header_signal_count * 0.25)
    return {"score": round(score, 2), "details": issues}


def check_image_only_email(parsed: dict) -> dict:
    """Detect image-only phishing emails.

    Phishers commonly send emails whose entire visible content is a single
    image (often base64-encoded inline) wrapped in a link.  This bypasses
    text-based spam filters since there are no words to analyze.  We flag
    emails where:
    1. The HTML body contains <img> tags but almost no readable text.
    2. The images use base64 data URIs (embedded directly, not hosted).
    3. The image is wrapped in a link (clickable image phishing).
    """
    html = parsed.get("html_body", "")
    if not html:
        return {"score": 0.0, "details": "No HTML body"}

    issues = []

    # Count <img> tags and base64 data URI images
    img_tags = re.findall(r'<img\b[^>]*>', html, re.IGNORECASE)
    base64_imgs = [t for t in img_tags if 'base64,' in t.lower()]

    if not img_tags:
        return {"score": 0.0, "details": "No images in HTML body"}

    # Strip all tags to get visible text
    visible_text = re.sub(r'<[^>]+>', ' ', html)
    visible_text = re.sub(r'&[a-zA-Z]+;', ' ', visible_text)
    visible_words = re.findall(r'[a-zA-Z]{2,}', visible_text)

    # Signal 1: Very little readable text relative to image content
    if len(visible_words) < 5 and len(img_tags) >= 1:
        issues.append(
            f"Image-heavy email: {len(img_tags)} image(s) with only "
            f"{len(visible_words)} readable word(s)"
        )

    # Signal 2: Base64 embedded images (avoids external hosting/tracking)
    if base64_imgs:
        issues.append(
            f"Base64 embedded image(s): {len(base64_imgs)} inline data URI image(s)"
        )

    # Signal 3: Image wrapped in a link (<a><img></a> pattern)
    linked_images = re.findall(
        r'<a\b[^>]*href\s*=\s*["\'][^"\']+["\'][^>]*>\s*<img\b',
        html, re.IGNORECASE,
    )
    if linked_images:
        issues.append(
            f"Clickable image(s): {len(linked_images)} image(s) wrapped in links"
        )

    if not issues:
        return {"score": 0.0, "details": "Images appear normal"}

    score = min(1.0, len(issues) * 0.4)
    return {"score": round(score, 2), "details": issues}


def _brand_in_context(brand: str, text: str) -> bool:
    """Return True if *brand* appears in *text* with brand-company intent.

    Unambiguous brand names (not in _AMBIGUOUS_BRANDS) always return True
    when found in the text.  Ambiguous names (e.g. "apple", "steam") require
    at least one context keyword nearby in the same text to confirm the
    reference is to the company rather than the common English word.
    """
    if brand not in text:
        return False
    if brand not in _AMBIGUOUS_BRANDS:
        return True  # unambiguous brand — always flag
    # Ambiguous brand — require a context keyword somewhere in the text
    return any(ctx in text for ctx in _AMBIGUOUS_BRANDS[brand])


def check_brand_impersonation(parsed: dict) -> dict:
    """Detect brand impersonation in display name, body text, and URLs.

    For ambiguous brand names that are also common English words (e.g.
    "apple", "chase", "steam"), context keywords must be present to confirm
    the text is referencing the company rather than the generic word.
    """
    from_header = parsed.get("from", "")
    from_domain = _extract_domain(from_header)
    display_name = from_header.split("<")[0].strip().strip('"').lower() if "<" in from_header else ""

    # Build full text corpus once for context lookups
    body_text = (parsed.get("plain_body", "") + " " + parsed.get("subject", "")).lower()
    html = parsed.get("html_body", "")
    if html:
        body_text += " " + re.sub(r'<[^>]+>', ' ', html).lower()
    # Combine display name + body for context — a display name saying "Apple"
    # alongside body text mentioning "iCloud" confirms brand intent.
    full_text = display_name + " " + body_text

    issues = []
    score = 0.0

    # Sub-check 1: Display name impersonation
    for brand, legit_domains in _KNOWN_BRANDS.items():
        if brand in display_name and from_domain not in legit_domains:
            if _brand_in_context(brand, full_text):
                issues.append(f"Display name contains '{brand}' but sender domain is '{from_domain}'")
                score = max(score, 0.9)
                break

    # Sub-check 2: Body brand mentions
    body_brand_score = 0.0
    for brand, legit_domains in _KNOWN_BRANDS.items():
        if brand in body_text and from_domain not in legit_domains:
            if _brand_in_context(brand, full_text):
                issues.append(f"Body mentions '{brand}' but sender domain is '{from_domain}'")
                body_brand_score += 0.3

    # Sub-check 3: URL brand mimicry (URLs are unambiguous — a hostname
    # containing "apple" or "chase" is always intentional brand usage)
    urls = parsed.get("urls", [])
    url_brand_score = 0.0
    for entry in urls:
        href = entry.get("href", "")
        try:
            p = urlparse(href)
        except Exception:
            continue
        hostname = (p.hostname or "").lower()
        if not hostname:
            continue
        for brand, legit_domains in _KNOWN_BRANDS.items():
            if brand in hostname and not any(hostname == d or hostname.endswith("." + d) for d in legit_domains):
                issues.append(f"URL hostname '{hostname}' contains '{brand}' but is not a legitimate domain")
                url_brand_score += 0.3
                break  # one issue per URL

    if not issues:
        return {"score": 0.0, "details": "No brand impersonation detected"}

    # Weighted combination: display name is strongest signal
    score = min(1.0, score + body_brand_score * 0.5 + url_brand_score * 0.5)
    return {"score": round(score, 2), "details": issues}


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

def analyze(parsed: dict) -> dict:
    features = {
        "sender_integrity": check_sender_integrity(parsed),
        "suspicious_urls": check_suspicious_urls(parsed),
        "urgency_language": check_urgency_language(parsed),
        "auth_headers": check_auth_headers(parsed),
        "attachment_risk": check_attachment_risk(parsed),
        "html_forms": check_html_forms(parsed),
        "header_anomalies": check_header_anomalies(parsed),
        "gibberish_text": check_gibberish_text(parsed),
        "image_only_email": check_image_only_email(parsed),
        "brand_impersonation": check_brand_impersonation(parsed),
    }

    weighted_sum = sum(
        features[k]["score"] * _WEIGHTS[k] for k in _WEIGHTS
    )
    total_weight = sum(_WEIGHTS.values())
    phishing_score = round(weighted_sum / total_weight, 2) if total_weight else 0.0

    # If any single feature scores above 0.7, enforce minimum 0.30 (suspicious)
    max_feature = max(f["score"] for f in features.values())
    if max_feature > 0.7 and phishing_score < 0.3:
        phishing_score = 0.30

    # If 3 or more features score above 0.3, enforce minimum 0.30 —
    # multiple moderate signals together indicate a suspicious email even
    # if no single feature dominates the weighted average.
    if phishing_score < 0.3:
        features_above_03 = sum(1 for f in features.values() if f["score"] > 0.3)
        if features_above_03 >= 3:
            phishing_score = 0.30

    if phishing_score < 0.3:
        verdict = "not suspicious"
    elif phishing_score <= 0.6:
        verdict = "suspicious"
    else:
        verdict = "phishing or spam"

    return {
        "phishing_score": phishing_score,
        "verdict": verdict,
        "features": features,
    }
