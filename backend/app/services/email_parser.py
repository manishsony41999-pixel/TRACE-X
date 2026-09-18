"""
TRACE-X RFC 822 / MIME Email Parser & Metadata Extractor
Parses raw email bytes into structured metadata, headers, body parts, and attachments.
"""

import email
import email.policy
import hashlib
from email.message import EmailMessage
from typing import Dict, Any, List, Optional


def parse_email_bytes(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Parses raw RFC 822 email bytes and returns structured metadata.
    """
    msg: EmailMessage = email.message_from_bytes(raw_bytes, policy=email.policy.default)

    # 1. Extract standard headers
    headers: Dict[str, Any] = {}
    for key, value in msg.items():
        headers[key.lower()] = str(value)

    # 2. Extract specific routing and authentication headers
    received_headers = msg.get_all("Received", [])
    auth_results = msg.get_all("Authentication-Results", [])
    dkim_signatures = msg.get_all("DKIM-Signature", [])

    # 3. Extract plain text and HTML bodies
    plain_text_parts: List[str] = []
    html_parts: List[str] = []
    attachments: List[Dict[str, Any]] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            # Handle attachments
            if "attachment" in content_disposition or part.get_filename():
                filename = part.get_filename() or "attachment.dat"
                payload = part.get_payload(decode=True) or b""
                sha256_hash = hashlib.sha256(payload).hexdigest()
                size_bytes = len(payload)

                is_suspicious_ext = False
                ext = filename.split(".")[-1].lower() if "." in filename else ""
                suspicious_extensions = ["exe", "vbs", "bat", "cmd", "scr", "js", "ps1", "hta", "jar", "iso", "dll", "wsf"]
                if ext in suspicious_extensions:
                    is_suspicious_ext = True

                attachments.append({
                    "filename": filename,
                    "content_type": content_type,
                    "size_bytes": size_bytes,
                    "sha256": sha256_hash,
                    "extension": ext,
                    "is_suspicious_extension": is_suspicious_ext
                })
            else:
                # Handle text body
                if content_type == "text/plain":
                    try:
                        text = part.get_content()
                        if isinstance(text, str):
                            plain_text_parts.append(text)
                    except Exception:
                        pass
                elif content_type == "text/html":
                    try:
                        html = part.get_content()
                        if isinstance(html, str):
                            html_parts.append(html)
                    except Exception:
                        pass
    else:
        # Non-multipart message
        content_type = msg.get_content_type()
        try:
            content = msg.get_content()
            if isinstance(content, str):
                if content_type == "text/html":
                    html_parts.append(content)
                else:
                    plain_text_parts.append(content)
        except Exception:
            pass

    full_plain_text = "\n".join(plain_text_parts).strip()
    full_html = "\n".join(html_parts).strip()

    return {
        "headers": headers,
        "received_hops": received_headers,
        "authentication_headers": auth_results,
        "dkim_signatures": dkim_signatures,
        "body": {
            "plain_text": full_plain_text,
            "html": full_html,
            "has_html": bool(full_html)
        },
        "attachments": attachments,
        "attachment_count": len(attachments)
    }
