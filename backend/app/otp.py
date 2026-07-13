import os
import random
import time
from typing import Optional

import httpx

# In-memory OTP store: {email: {"code": str, "expires": float, "user_data": dict}}
_otp_store: dict = {}

OTP_EXPIRY_SECONDS = 600  # 10 minutes

# Email configuration
# Option 1: Resend API (recommended for Railway - uses HTTP, not SMTP)
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")

# Option 2: SMTP fallback (for environments that allow outbound SMTP)
SMTP_HOST = os.getenv("SMTP_HOST", "fleetxsolutions.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))
SMTP_PORT_STARTTLS = int(os.getenv("SMTP_PORT_STARTTLS", "587"))
SMTP_USER = os.getenv("SMTP_USER", "zayn.sales@fleetxsolutions.com")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "Pakistan@1122")

# From email address
FROM_EMAIL = os.getenv("FROM_EMAIL", SMTP_USER)


def generate_otp() -> str:
    """Generate a 6-digit OTP code."""
    return str(random.randint(100000, 999999))


def store_otp(email: str, code: str, user_data: dict) -> None:
    """Store OTP with expiry and associated user data."""
    _otp_store[email] = {
        "code": code,
        "expires": time.time() + OTP_EXPIRY_SECONDS,
        "user_data": user_data,
    }


def verify_otp(email: str, code: str) -> Optional[dict]:
    """Verify OTP code. Returns user_data if valid, None otherwise."""
    entry = _otp_store.get(email)
    if not entry:
        return None
    if time.time() > entry["expires"]:
        del _otp_store[email]
        return None
    if entry["code"] != code:
        return None
    user_data = entry["user_data"]
    del _otp_store[email]
    return user_data


def cleanup_expired() -> None:
    """Remove expired OTP entries."""
    now = time.time()
    expired_keys = [k for k, v in _otp_store.items() if now > v["expires"]]
    for k in expired_keys:
        del _otp_store[k]


def _build_html_content(otp_code: str) -> str:
    """Build the HTML email template."""
    return f"""
    <html>
    <body style="font-family: 'Segoe UI', Arial, sans-serif; background-color: #f8fafc; padding: 40px;">
        <div style="max-width: 480px; margin: 0 auto; background: white; border-radius: 16px; padding: 40px; box-shadow: 0 4px 24px rgba(0,0,0,0.08);">
            <div style="text-align: center; margin-bottom: 32px;">
                <h1 style="color: #1e293b; font-size: 24px; margin: 0;">FreightIntel</h1>
                <p style="color: #64748b; font-size: 14px; margin-top: 8px;">Email Verification</p>
            </div>
            <p style="color: #334155; font-size: 15px; line-height: 1.6;">
                Your verification code is:
            </p>
            <div style="text-align: center; margin: 24px 0;">
                <span style="display: inline-block; background: linear-gradient(135deg, #7C5CFC, #9B7EFD); color: white; font-size: 32px; font-weight: 700; letter-spacing: 8px; padding: 16px 32px; border-radius: 12px;">
                    {otp_code}
                </span>
            </div>
            <p style="color: #64748b; font-size: 13px; text-align: center;">
                This code expires in 10 minutes. Do not share it with anyone.
            </p>
            <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 24px 0;" />
            <p style="color: #94a3b8; font-size: 12px; text-align: center;">
                If you didn't request this code, please ignore this email.
            </p>
        </div>
    </body>
    </html>
    """


async def _send_via_resend(to_email: str, otp_code: str) -> bool:
    """Send email via Resend HTTP API (works on Railway since it uses HTTPS, not SMTP)."""
    html_content = _build_html_content(otp_code)

    payload = {
        "from": FROM_EMAIL,
        "to": [to_email],
        "subject": "FreightIntel - Verify Your Email",
        "html": html_content,
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {RESEND_API_KEY}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )

        if response.status_code in (200, 201):
            print(f"[OTP] Email sent to {to_email} via Resend API. Response: {response.json()}")
            return True
        else:
            print(f"[OTP] Resend API failed for {to_email}: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"[OTP] Resend API error for {to_email}: {type(e).__name__}: {e}")
        return False


async def _send_via_smtp(to_email: str, otp_code: str) -> bool:
    """Send email via SMTP (fallback for environments that allow outbound SMTP)."""
    import ssl
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    import asyncio
    from concurrent.futures import ThreadPoolExecutor

    html_content = _build_html_content(otp_code)
    text_content = f"Your FreightIntel verification code is: {otp_code}\n\nThis code expires in 10 minutes."

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "FreightIntel - Verify Your Email"
    msg["From"] = FROM_EMAIL
    msg["To"] = to_email
    msg.attach(MIMEText(text_content, "plain"))
    msg.attach(MIMEText(html_content, "html"))

    def _send_sync():
        context = ssl.create_default_context()
        # Try SSL on port 465
        try:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=30) as server:
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.sendmail(SMTP_USER, to_email, msg.as_string())
            return True
        except Exception as e1:
            print(f"[OTP] SMTP SSL (port {SMTP_PORT}) failed: {e1}")

        # Try STARTTLS on port 587
        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT_STARTTLS, timeout=30) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.sendmail(SMTP_USER, to_email, msg.as_string())
            return True
        except Exception as e2:
            print(f"[OTP] SMTP STARTTLS (port {SMTP_PORT_STARTTLS}) failed: {e2}")

        return False

    loop = asyncio.get_event_loop()
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        result = await loop.run_in_executor(executor, _send_sync)
        if result:
            print(f"[OTP] Email sent to {to_email} via SMTP")
        return result
    except Exception as e:
        print(f"[OTP] SMTP executor error: {e}")
        return False


async def send_otp_email(to_email: str, otp_code: str) -> bool:
    """Send OTP verification email.
    
    Strategy:
    1. If RESEND_API_KEY is set, use Resend HTTP API (works on Railway/cloud platforms)
    2. Otherwise, fall back to SMTP (works on VPS/dedicated servers)
    """
    if not SMTP_USER and not RESEND_API_KEY:
        print(f"[OTP] No email provider configured. OTP for {to_email}: {otp_code}")
        return True  # Allow development without email

    # Prefer Resend API (HTTP-based, works everywhere including Railway)
    if RESEND_API_KEY:
        print(f"[OTP] Using Resend API for {to_email}")
        return await _send_via_resend(to_email, otp_code)

    # Fallback to SMTP
    print(f"[OTP] Using SMTP for {to_email} (no RESEND_API_KEY set)")
    return await _send_via_smtp(to_email, otp_code)
