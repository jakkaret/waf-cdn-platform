"""Environment the shield modules need at import (N6: no secret, no start)."""
import os

os.environ.setdefault("CAPTCHA_HMAC_SECRET", "test-captcha-hmac-secret-0123456789abcdef")
os.environ.setdefault("OTP_HMAC_SECRET", "test-otp-hmac-secret-0123456789abcdef0123")
# TestClient's peer address is "testclient": treat it as the WAF's nginx so
# the X-Original-IP header the tests send is believed.
os.environ.setdefault("SHIELD_TRUSTED_PROXIES", "testclient")
