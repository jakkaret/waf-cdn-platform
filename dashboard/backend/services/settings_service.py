import os
import json
import logging
import httpx
from pathlib import Path
from typing import Dict, Any
from services.rule_manager import RuleManager
from services.captcha_config import _client as _redis_client

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
SETTINGS_FILE = DATA_DIR / "system_settings.json"

# Gen3 roadmap 1.3 (Adaptive Action Policy): global, not per-origin, because
# ML enforcement is a cross-cutting decision across every dynamic origin --
# unlike CAPTCHA/OTP shield's per-origin opt-in. Defaults OFF: the promotion
# gate for a model that hits the roadmap's own accuracy bar (Benign Recall
# >=98.5%, Attack Recall >=85-90%) has not passed as of this writing (see
# WAF_GEN3_ROADMAP.md Phase 2 -- best real candidate: ~65% attack recall at
# the required benign recall). Flipping this True with the current
# production model would mean blocking/challenging real traffic on a model
# below its own accuracy bar. Rollback is exactly this flag back to False --
# a single settings write, no redeploy.
ML_POLICY_REDIS_KEY = "waf:ml:policy"

DEFAULT_SETTINGS = {
    "waf_mode": "blocking",                      # "blocking" or "detection_only"
    "paranoia_level": 1,                         # 1 to 4
    "inbound_anomaly_threshold": 10,             # default CRS inbound limit
    "outbound_anomaly_threshold": 10,            # default CRS outbound limit
    "auto_purge_edge_cache": True,               # purge cache on rule update
    "real_ip_header": "X-Forwarded-For",         # header for client IP extraction
    "telegram_notifications": True,
    "telegram_bot_token": os.getenv("TELEGRAM_BOT_TOKEN", ""),
    "telegram_chat_id": os.getenv("TELEGRAM_CHAT_ID", ""),
    "edge_sync_interval_seconds": 5,
    "ml_enforcement_enabled": False,              # keep False until Phase 2's promotion gate passes
    "ml_block_threshold": 0.95,                   # attack_probability >= this -> 403 block
    "ml_challenge_threshold": 0.70,               # attack_probability >= this -> native PoW challenge
}


class SettingsService:
    def __init__(self):
        self.rule_manager = RuleManager()
        self._ensure_settings_file()
        # Self-heal Redis on service restart, in case Redis was flushed
        # independently of this file (control-api's ml_policy reads only
        # Redis, never this file directly -- see below).
        self._sync_ml_policy(self.get_settings())

    def _ensure_settings_file(self):
        if not SETTINGS_FILE.exists():
            SETTINGS_FILE.write_text(json.dumps(DEFAULT_SETTINGS, indent=2), encoding="utf-8")

    def _sync_ml_policy(self, settings: Dict[str, Any]):
        """Mirror the 3 ml_* keys to Redis as one JSON document.

        control-api (cdn/control-api/ml_policy.py) runs in a separate
        container/process and has no line to this file or dashboard-backend's
        sqlite/JSON state -- Redis is the one store both sides already share
        (same pattern as captcha/otp shield config). Missing key on the
        control-api side defaults to disabled, so a Redis outage fails safe.
        """
        try:
            payload = {
                "ml_enforcement_enabled": bool(settings.get("ml_enforcement_enabled", False)),
                "ml_block_threshold": float(settings.get("ml_block_threshold", 0.95)),
                "ml_challenge_threshold": float(settings.get("ml_challenge_threshold", 0.70)),
            }
            _redis_client().set(ML_POLICY_REDIS_KEY, json.dumps(payload))
        except Exception as e:
            logger.warning(f"Failed to sync ML policy to Redis: {e}")

    def get_settings(self) -> Dict[str, Any]:
        self._ensure_settings_file()
        try:
            raw_data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
            # Filter only valid keys in DEFAULT_SETTINGS
            data = {k: raw_data.get(k, v) for k, v in DEFAULT_SETTINGS.items()}
            # Mask secret tokens before returning to UI
            masked = dict(data)
            token = masked.get("telegram_bot_token", "")
            if token and len(token) > 8:
                masked["telegram_bot_token_masked"] = f"{token[:4]}...{token[-4:]}"
            else:
                masked["telegram_bot_token_masked"] = ""
            return masked
        except Exception as e:
            logger.error(f"Error reading settings: {e}")
            return DEFAULT_SETTINGS

    def update_settings(self, new_settings: Dict[str, Any]) -> Dict[str, Any]:
        current = self.get_settings()
        for k, v in new_settings.items():
            if k in DEFAULT_SETTINGS:
                # If secret token was sent empty, keep old token unless explicitly set
                if k == "telegram_bot_token" and (not v or v.startswith("***") or "..." in v):
                    continue
                current[k] = v

        # Write to JSON
        clean_save = {k: v for k, v in current.items() if not k.endswith("_masked")}
        SETTINGS_FILE.write_text(json.dumps(clean_save, indent=2), encoding="utf-8")

        # Sync ModSecurity configuration override if WAF mode changed
        self._apply_modsecurity_settings(clean_save)
        self._sync_ml_policy(clean_save)

        return self.get_settings()

    def _apply_modsecurity_settings(self, settings: Dict[str, Any]):
        """Write modsecurity-override.conf to dynamically update SecRuleEngine and CRS thresholds."""
        try:
            override_dir = Path(__file__).resolve().parent.parent.parent.parent / "modsecurity" / "custom-rules"
            override_file = override_dir / "00-modsecurity-override.conf"
            
            engine_val = "On" if settings.get("waf_mode") == "blocking" else "DetectionOnly"
            paranoia = settings.get("paranoia_level", 1)
            inbound = settings.get("inbound_anomaly_threshold", 10)
            outbound = settings.get("outbound_anomaly_threshold", 10)

            content = (
                f"# Dynamic Settings Override (Generated by CloudWAF Control Plane)\n"
                f"SecRuleEngine {engine_val}\n"
                f"SecAction \\\n"
                f" \"id:900000,\\\n"
                f"  phase:1,\\\n"
                f"  nolog,\\\n"
                f"  pass,\\\n"
                f"  t:none,\\\n"
                f"  setvar:tx.paranoia_level={paranoia},\\\n"
                f"  setvar:tx.inbound_anomaly_score_threshold={inbound},\\\n"
                f"  setvar:tx.outbound_anomaly_score_threshold={outbound}\"\n"
            )
            override_file.write_text(content, encoding="utf-8")
            self.rule_manager.reload_nginx()
        except Exception as e:
            logger.warning(f"Failed to apply dynamic ModSecurity override: {e}")

    async def send_test_notification(self, channel: str = "telegram") -> Dict[str, Any]:
        settings = self.get_settings()
        if channel == "telegram":
            bot_token = settings.get("telegram_bot_token")
            chat_id = settings.get("telegram_chat_id")
            if not bot_token or not chat_id:
                raise ValueError("Telegram Bot Token and Chat ID must be configured first")

            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            msg = (
                "🛡️ *CloudWAF Test Alert*\n\n"
                "✅ Integration verified successfully!\n"
                "Your alert channel is active and ready to receive real-time threat notifications."
            )
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(url, json={
                    "chat_id": chat_id,
                    "text": msg,
                    "parse_mode": "Markdown"
                })
                if resp.status_code == 200:
                    return {"status": "success", "message": "Test alert sent to Telegram successfully"}
                else:
                    raise RuntimeError(f"Telegram API error: {resp.text}")

        raise ValueError(f"Unknown alert channel: {channel}")
