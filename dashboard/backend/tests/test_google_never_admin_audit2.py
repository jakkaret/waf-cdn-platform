"""Re-audit 2026-10-17: Google sign-in never creates a platform admin, even
if the old ADMIN_EMAIL_DOMAIN variable is still set in an environment."""
import services.auth_service as auth_service


def test_no_admin_email_domain_rule_left():
    assert not hasattr(auth_service, "ADMIN_EMAIL_DOMAIN")


def test_google_signup_on_any_domain_is_viewer(monkeypatch):
    monkeypatch.setenv("ADMIN_EMAIL_DOMAIN", "example.edu")
    svc = auth_service.AuthService()
    user = svc.login_or_register_google({
        "email": "student@example.edu", "email_verified": True,
        "name": "Student", "sub": "g-audit-1", "picture": "",
    })
    assert user["role"] == "viewer"
