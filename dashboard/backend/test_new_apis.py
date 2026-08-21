import sys
import os
import requests

sys.path.insert(0, os.path.dirname(__file__))

from services.auth_service import AuthService

auth = AuthService()
users = auth.list_users()

if users:
    admin_user = next((u for u in users if u.get("role") == "admin"), users[0])
    token = auth.create_access_token({
        "sub": admin_user["user_id"],
        "role": admin_user["role"],
        "email": admin_user["email"],
    })
    headers = {"Authorization": f"Bearer {token}"}

    # Test Settings API
    r_set = requests.get("http://localhost:8000/api/settings/", headers=headers)
    print("Settings GET status:", r_set.status_code)
    settings_data = r_set.json().get("settings", {})
    print("WAF Mode:", settings_data.get("waf_mode"))
    print("Telegram Bot Masked:", settings_data.get("telegram_bot_token_masked"))
    assert "slack_webhook_url" not in settings_data, "Slack is still in settings!"
    print("SUCCESS: Slack completely removed and verified!")
