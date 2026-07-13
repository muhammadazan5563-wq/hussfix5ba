import os
import random
import time
from typing import Optional

import httpx

# In-memory OTP store: {email: {"code": str, "expires": float, "user_data": dict}}
_otp_store: dict = {}

OTP_EXPIRY_SECONDS = 600  # 10 minutes

# Resend API configuration (HTTP-based, works on Railway)
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
FROM_EMAIL = os.getenv("FROM_EMAIL", "zayn.sales@aykatc.com")


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


async def send_otp_email(to_email: str, otp_code: str) -> bool:
    """Send OTP verification email via Resend HTTP API.
    
    Uses HTTPS (port 443) which is not blocked by Railway or any cloud platform.
    """
    if not RESEND_API_KEY:
        print(f"[OTP] WARNING: RESEND_API_KEY not set. OTP for {to_email}: {otp_code}")
        return False

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

    payload = {
        "from": FROM_EMAIL,
        "to": [to_email],
        "subject": "FreightIntel - Verify Your Email",
        "html": html_content,
    }

    try:
        print(f"[OTP] Sending email to {to_email} via Resend API...")
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
            print(f"[OTP] SUCCESS: Email sent to {to_email}. Response: {response.json()}")
            return True
        else:
            print(f"[OTP] FAILED: Resend API returned {response.status_code} for {to_email}: {response.text}")
            return False
    except Exception as e:
        print(f"[OTP] ERROR: Failed to send email to {to_email}: {type(e).__name__}: {e}")
        return False
