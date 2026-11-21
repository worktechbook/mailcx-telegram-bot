import os
from http.server import BaseHTTPRequestHandler
import json
import re
import random
import string
import requests
import hmac
import hashlib
import base64
import struct
import time

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
TG_API = f"https://api.telegram.org/bot{BOT_TOKEN}"
MAILCX_API = "https://mail.cx"
DOMAIN = os.environ.get("MAILCX_DOMAIN", "uqu.me")

KB_GET_MAIL = {
    "keyboard": [[{"text": "✉️ Get Mail"}]],
    "resize_keyboard": True,
    "one_time_keyboard": False,
    "is_persistent": True
}

def make_active_keyboard(email_addr):
    return {
        "keyboard": [
            [{"text": f"🔑 Get Code ({email_addr})"}],
            [{"text": "⬅️ Back"}]
        ],
        "resize_keyboard": True,
        "one_time_keyboard": False,
        "is_persistent": True
    }

def send_reply(chat_id, text, keyboard=None):
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML"
    }
    if keyboard:
        payload["reply_markup"] = keyboard
    try:
        requests.post(f"{TG_API}/sendMessage", json=payload, timeout=10)
    except Exception:
        pass

def delete_mailcx_inbox(address):
    headers = {
        "X-Client-ID": "vercel-bot",
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0"
    }
    try:
        requests.delete(f"{MAILCX_API}/v1/inbox/{address}", headers=headers, timeout=5)
    except Exception:
        pass

def generate_address():
    c = string.ascii_lowercase
    alias = "".join(random.choices(c, k=3)) + "cx" + "".join(random.choices(c, k=4))
    return f"{alias}@{DOMAIN}"

def extract_otp(raw):
    if not raw:
        return None
    clean = re.sub(r"(?s)<style[^>]*>.*?</style>", " ", raw)
    clean = re.sub(r"(?s)<script[^>]*>.*?</script>", " ", clean)
    clean = re.sub(r"(?s)<[^>]+>", " ", clean)
    clean = re.sub(r"&nbsp;", " ", clean)
    clean = re.sub(r"&#8203;|&zwnj;", "", clean)

    patterns = [
        r"(?i)(?:bestätigungscode|confirmation\s*code|verification\s*code|security\s*code)[^\d]{0,40}?([0-9]{5,6})",
        r"(?i)(?:lautet|code)[^\d]{1,30}?([0-9]{5,6})",
        r"(?i)>\s*([0-9]{5,6})\s*<",
    ]
    for p in patterns:
        m = re.search(p, clean)
        if m:
            return m.group(1)

    sm = re.search(r"\b([0-9]\s+[0-9]\s+[0-9]\s+[0-9]\s+[0-9](?:\s+[0-9])?)\b", clean)
    if sm:
        c = re.sub(r"\s+", "", sm.group(1))
        if len(c) in (5, 6):
            return c

    nums = re.findall(r"\b([0-9]{5,6})\b", clean)
    if nums:
        return nums[0]
    return None

def check_otp(address):
    headers = {
        "X-Client-ID": "vercel-bot",
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0"
    }
    try:
        r = requests.get(f"{MAILCX_API}/v1/inbox/{address}", headers=headers, timeout=8)
        if r.status_code == 200:
            data = r.json()
            emails = data.get("emails", [])
            for item in emails:
                code = extract_otp(item.get("subject", "")) or extract_otp(item.get("preview_text", ""))
                if code:
                    return code
                eid = item.get("id")
                fr = requests.get(f"{MAILCX_API}/v1/email/{eid}", headers=headers, timeout=8)
                if fr.status_code == 200:
                    fd = fr.json()
                    body = fd.get("html_body") or fd.get("text_body") or fd.get("html") or fd.get("text") or ""
                    code = extract_otp(body)
                    if code:
                        return code
    except Exception:
        pass
    return None

# --- RFC 6238 Standard TOTP 2FA Generator ---
def generate_totp_code(secret_input):
    """
    Detects and calculates a standard 6-digit TOTP code from a secret key or otpauth URI.
    Returns 6-digit string or None if invalid secret.
    """
    if not secret_input:
        return None
    raw = secret_input.strip()

    # Handle otpauth:// URI (e.g. otpauth://totp/...?secret=XXXXX)
    if "secret=" in raw:
        match = re.search(r'secret=([A-Za-z2-7=]+)', raw)
        if match:
            raw = match.group(1)

    # Clean spaces, dashes, convert to uppercase
    clean_secret = re.sub(r'[\s\-_]', '', raw).upper()

    # Base32 strings typically contain characters A-Z and 2-7, length >= 8
    if not clean_secret or not re.fullmatch(r'[A-Z2-7=]{8,}', clean_secret):
        return None

    # Pad Base32 string if needed
    missing_padding = len(clean_secret) % 8
    if missing_padding:
        clean_secret += '=' * (8 - missing_padding)

    try:
        key = base64.b32decode(clean_secret, casefold=True)
        # 30-second time step interval
        time_step = int(time.time() // 30)
        time_bytes = struct.pack(">Q", time_step)
        
        # HMAC-SHA1
        h = hmac.new(key, time_bytes, hashlib.sha1).digest()
        
        # Dynamic truncation (RFC 4226)
        offset = h[-1] & 0x0F
        binary = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
        
        totp = str(binary % 1000000).zfill(6)
        return totp
    except Exception:
        return None

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({"status": "Mail.cx + 2FA TOTP Webhook Active"}).encode('utf-8'))

    def do_POST(self):
        if WEBHOOK_SECRET and self.headers.get("X-Telegram-Bot-Api-Secret-Token") != WEBHOOK_SECRET:
            self.send_response(403)
            self.end_headers()
            return
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)

        try:
            update = json.loads(body.decode('utf-8'))
            msg = update.get("message")
            if msg and "text" in msg:
                chat_id = msg["chat"]["id"]
                text = msg["text"].strip()

                # --- 1. GLOBAL 2FA TOTP SECRET CHECK (ANY TIME) ---
                totp_code = generate_totp_code(text)
                if totp_code:
                    # Send ONLY the 6-digit TOTP code in <code> format for one-tap copy
                    send_reply(chat_id, f"<code>{totp_code}</code>")
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"ok": True}).encode('utf-8'))
                    return

                # --- 2. MAIL WORKFLOW BUTTONS ---
                if text == "✉️ Get Mail" or text == "/getmail":
                    new_email = generate_address()
                    send_reply(chat_id, f"<code>{new_email}</code>", make_active_keyboard(new_email))

                elif "🔑 Get Code" in text:
                    em_match = re.search(r'([a-z0-9]+@uqu\.me)', text)
                    if em_match:
                        addr = em_match.group(1)
                        code = check_otp(addr)
                        if code:
                            delete_mailcx_inbox(addr)
                            send_reply(chat_id, f"<code>{code}</code>", KB_GET_MAIL)
                        else:
                            send_reply(chat_id, "<code>Waiting for code...</code>", make_active_keyboard(addr))
                    else:
                        send_reply(chat_id, "<code>No active mail</code>", KB_GET_MAIL)

                elif text == "⬅️ Back":
                    send_reply(chat_id, "<code>Ready</code>", KB_GET_MAIL)

                else:
                    send_reply(chat_id, "<code>Ready</code>", KB_GET_MAIL)

        except Exception:
            pass

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({"ok": True}).encode('utf-8'))
