from __future__ import annotations

import email
import email.policy
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse
from typing import List, Dict, Optional, Tuple


class _LinkExtractor(HTMLParser):
    """Extract URLs and form elements from HTML."""

    def __init__(self):
        super().__init__()
        self.urls: List[Dict] = []
        self.has_forms = False
        self.has_inputs = False
        self._current_anchor_href: Optional[str] = None
        self._current_anchor_text: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        attr_dict = dict(attrs)
        if tag == "a" and "href" in attr_dict:
            self._current_anchor_href = attr_dict["href"]
            self._current_anchor_text = []
        if tag == "form":
            self.has_forms = True
        if tag == "input":
            self.has_inputs = True

    def handle_data(self, data: str):
        if self._current_anchor_href is not None:
            self._current_anchor_text.append(data)

    def handle_endtag(self, tag: str):
        if tag == "a" and self._current_anchor_href is not None:
            self.urls.append({
                "href": self._current_anchor_href,
                "text": "".join(self._current_anchor_text).strip(),
            })
            self._current_anchor_href = None
            self._current_anchor_text = []


_URL_RE = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)


def _extract_plain_urls(text: str) -> List[Dict]:
    return [{"href": u, "text": ""} for u in _URL_RE.findall(text)]


def _get_attachments(msg: email.message.Message) -> List[Dict]:
    attachments = []
    for part in msg.walk():
        try:
            disp = part.get_content_disposition()
        except Exception:
            disp = None
        if disp == "attachment":
            try:
                filename = part.get_filename() or ""
            except Exception:
                filename = ""
            attachments.append({
                "filename": filename,
                "content_type": part.get_content_type(),
            })
    return attachments


def _safe_header(msg: email.message.Message, name: str) -> str:
    try:
        val = msg.get(name)
        if val is None:
            return ""
        return str(val)
    except Exception:
        return ""


def _safe_get_payload(part: email.message.Message) -> str:
    try:
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        # Try common encodings
        for enc in ("utf-8", "latin-1", "ascii"):
            try:
                return payload.decode(enc)
            except (UnicodeDecodeError, LookupError):
                continue
        return payload.decode("utf-8", errors="replace")
    except Exception:
        return ""


def parse_eml(path: Path) -> dict:
    raw = path.read_bytes()
    # Use compat32 policy — it is lenient with malformed headers found in
    # real-world phishing samples, unlike email.policy.default which raises
    # on non-conformant Message-ID, From, etc.
    msg = email.message_from_bytes(raw)

    # Headers
    subject = _safe_header(msg, "Subject")
    from_header = _safe_header(msg, "From")
    return_path = _safe_header(msg, "Return-Path")
    reply_to = _safe_header(msg, "Reply-To")
    date = _safe_header(msg, "Date")
    message_id = _safe_header(msg, "Message-ID")
    x_mailer = _safe_header(msg, "X-Mailer")
    auth_results = _safe_header(msg, "Authentication-Results")
    received_spf = _safe_header(msg, "Received-SPF")

    # Received header chain (multiple values)
    try:
        received_headers = msg.get_all("Received") or []
        received_headers = [str(r) for r in received_headers]
    except Exception:
        received_headers = []

    # Body
    plain_body = ""
    html_body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain" and not plain_body:
                plain_body = _safe_get_payload(part)
            elif ct == "text/html" and not html_body:
                html_body = _safe_get_payload(part)
    else:
        ct = msg.get_content_type()
        if ct == "text/plain":
            plain_body = _safe_get_payload(msg)
        elif ct == "text/html":
            html_body = _safe_get_payload(msg)

    # URL and form extraction from HTML
    urls: list[dict] = []
    has_forms = False
    has_inputs = False
    if html_body:
        extractor = _LinkExtractor()
        try:
            extractor.feed(html_body)
        except Exception:
            pass
        urls = extractor.urls
        has_forms = extractor.has_forms
        has_inputs = extractor.has_inputs

    # Also grab URLs from plain text
    if plain_body:
        urls.extend(_extract_plain_urls(plain_body))

    # Attachments
    attachments = _get_attachments(msg)

    return {
        "subject": subject,
        "from": from_header,
        "return_path": return_path,
        "reply_to": reply_to,
        "date": date,
        "message_id": message_id,
        "x_mailer": x_mailer,
        "auth_results": auth_results,
        "received_spf": received_spf,
        "received_headers": received_headers,
        "plain_body": plain_body if isinstance(plain_body, str) else "",
        "html_body": html_body if isinstance(html_body, str) else "",
        "urls": urls,
        "has_forms": has_forms,
        "has_inputs": has_inputs,
        "attachments": attachments,
    }
