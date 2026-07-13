import os
import random
import time
import asyncio
import smtplib
import ssl
from concurrent.futures import ThreadPoolExecutor
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

# In-memory OTP store: {email: {"code": str, "expires": float, "user_data": dict}}
_otp_store: dict = {}

OTP_EXPIRY_SECONDS = 600  # 10 minutes

SMTP_HOST = os.getenv("SMTP_HOST", "fleetxsolutions.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))
SMTP_PORT_STARTTLS = int(os.getenv("SMTP_PORT_STARTTLS", "587"))
SMTP_USER = os.getenv("SMTP_USER", "zayn.sales@fleetxsolutions.com")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "Pakistan@1122")

# Thread pool for non-blocking SMTP operations
_smtp_executor = ThreadPoolExecutor(max_workers=2)


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


def _send_email_sync(to_email: str, msg_string: str) -> bool:
    """Synchronous email sending - runs in thread pool to avoid blocking the event loop."""
    context = ssl.create_default_context()

    # Method 1: Try SMTP_SSL on port 465 (implicit SSL) with 30s timeout
    try:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=30) as server:
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, to_email, msg_string)
        print(f"[OTP] Verification email sent to {to_email} via SSL (port {SMTP_PORT})")
        return True
    except Exception as e1:
        print(f"[OTP] SSL (port {SMTP_PORT}) failed for {to_email}: {e1}")

    # Method 2: Try STARTTLS on port 587
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT_STARTTLS, timeout=30) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, to_email, msg_string)
        print(f"[OTP] Verification email sent to {to_email} via STARTTLS (port {SMTP_PORT_STARTTLS})")
        return True
    except Exception as e2:
        print(f"[OTP] STARTTLS (port {SMTP_PORT_STARTTLS}) failed for {to_email}: {e2}")

    # Method 3: Try plain SMTP on port 25 as last resort
    try:
        with smtplib.SMTP(SMTP_HOST, 25, timeout=30) as server:
            server.ehlo()
            try:
                server.starttls(context=context)
                server.ehlo()
            except Exception:
                pass  # Continue without TLS if not supported
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, to_email, msg_string)
        print(f"[OTP] Verification email sent to {to_email} via port 25")
        return True
    except Exception as e3:
        print(f"[OTP] Port 25 also failed for {to_email}: {e3}")

    print(f"[OTP] ALL SMTP methods failed for {to_email}. The hosting environment may block outbound SMTP.")
    return False


async def send_otp_email(to_email: str, otp_code: str) -> bool:
    """Send OTP verification email via SMTP in a background thread (non-blocking).
    
    Uses run_in_executor to prevent blocking the asyncio event loop while
    performing synchronous SMTP operations.
    """
    if not SMTP_USER or not SMTP_PASSWORD:
        print(f"[OTP] SMTP not configured. OTP for {to_email}: {otp_code}")
        return True  # Allow development without SMTP

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "FreightIntel - Verify Your Email"
    msg["From"] = SMTP_USER
    msg["To"] = to_email

    html_content = f"""
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

    text_content = f"Your FreightIntel verification code is: {otp_code}\n\nThis code expires in 10 minutes."

    msg.attach(MIMEText(text_content, "plain"))
    msg.attach(MIMEText(html_content, "html"))

    msg_string = msg.as_string()

    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(
            _smtp_executor, _send_email_sync, to_email, msg_string
        )
        return result
    except Exception as e:
        print(f"[OTP] Executor error for {to_email}: {e}")
        return False
