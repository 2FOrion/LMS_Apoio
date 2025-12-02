import os, base64
try:
    import pyotp
except Exception:
    pyotp = None

APP_NAME = os.getenv("APP_NAME","LMS APOIO")

def ensure_secret(existing=None):
    if existing:
        return existing
    raw = os.urandom(20)
    return base64.b32encode(raw).decode("utf-8").replace("=", "")

def otpauth_uri(user_name, secret):
    issuer = APP_NAME.replace(" ", "%20")
    label = f"{issuer}:{user_name}".replace(" ", "%20")
    return f"otpauth://totp/{label}?secret={secret}&issuer={issuer}&digits=6&algorithm=SHA1&period=30"

def verify_otp(secret, code):
    if not pyotp:
        return False  # require dependency
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(str(code), valid_window=1)
    except Exception:
        return False

def qr_via_google_charts(otpauth_url):
    # Simple QR using Google Charts
    import urllib.parse
    data = urllib.parse.quote(otpauth_url, safe="")
    return f"https://chart.googleapis.com/chart?cht=qr&chs=240x240&chl={data}"
