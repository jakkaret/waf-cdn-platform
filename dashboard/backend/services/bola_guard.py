"""
Context-Aware BOLA / IDOR Guard Engine (Enterprise Edition)
Enterprise Traffic-Level Object Authorization & Tenant Isolation Gate
Protects against OWASP API1:2023 - Broken Object Level Authorization (BOLA/IDOR)

Features:
1. Cryptographic JWT Verification (HMAC-SHA256, RS256) preventing Forged Token Admin Elevation.
2. Multi-stage Path Canonicalization (URL unquote, posixpath.normpath) preventing Path Traversal Desync.
3. Public Endpoints Whitelisting (e.g. /users/register, /users/login) preventing False Positives.
4. Header Anti-Spoofing Gate (Cross-checks X-User-ID / X-Tenant-ID against cryptographically verified claims).
"""

import os
import re
import json
import base64
import logging
import posixpath
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple, Set

logger = logging.getLogger(__name__)

# System JWT Secret Key for signature verification
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-this-secret-in-production")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
RSA_PUBLIC_KEY = os.getenv("JWT_RSA_PUBLIC_KEY", "")
ALLOWED_JWT_ALGORITHMS = ["HS256", "RS256"]

# Method-Aware Public unauthenticated actions that should not be blocked by BOLA object policies
# Strictly mapped to exact non-identifying action endpoints without sub-resources
PUBLIC_USER_METHOD_MAP: Dict[str, Set[str]] = {
    "register": {"GET", "POST", "HEAD", "OPTIONS"},
    "signup": {"GET", "POST", "HEAD", "OPTIONS"},
    "login": {"GET", "POST", "HEAD", "OPTIONS"},
    "signin": {"GET", "POST", "HEAD", "OPTIONS"},
    "forgot-password": {"GET", "POST", "HEAD", "OPTIONS"},
    "reset-password": {"GET", "POST", "HEAD", "OPTIONS"},
    "verify-email": {"GET", "HEAD", "OPTIONS"},
    "verify": {"GET", "HEAD", "OPTIONS"},
    "health": {"GET", "HEAD", "OPTIONS"},
    "status": {"GET", "HEAD", "OPTIONS"},
    "callback": {"GET", "POST", "HEAD", "OPTIONS"},
    "oauth": {"GET", "POST", "HEAD", "OPTIONS"},
}
PUBLIC_USER_ACTIONS: Set[str] = set(PUBLIC_USER_METHOD_MAP.keys())

# Default Built-in BOLA Protection Policies (with email, phone (+), and special char support)
DEFAULT_BOLA_POLICIES = [
    {
        "id": "BOLA-001",
        "name": "User Profile & Settings Guard",
        "path_pattern": r"^/api/(?:v[0-9]+/)?users/(?P<resource_id>[a-zA-Z0-9_\-\.@\+~%]+)(?:/.*)?$",
        "claim_key": "sub",
        "resource_type": "user_id",
        "action": "BLOCK",
        "allow_admin": True,
        "priority": 100,
        "description": "Prevents unauthorized users from reading or altering another user's profile/data."
    },
    {
        "id": "BOLA-002",
        "name": "Multi-Tenant Isolation Guard",
        "path_pattern": r"^/api/(?:v[0-9]+/)?tenants/(?P<resource_id>[a-zA-Z0-9_\-\.@\+~%]+)(?:/.*)?$",
        "claim_key": "tenant_id",
        "resource_type": "tenant_id",
        "action": "BLOCK",
        "allow_admin": True,
        "priority": 100,
        "description": "Enforces strict tenant isolation preventing cross-tenant data access."
    },
    {
        "id": "BOLA-003",
        "name": "Organization Resource Boundary",
        "path_pattern": r"^/api/(?:v[0-9]+/)?(?:orgs|organizations)/(?P<resource_id>[a-zA-Z0-9_\-\.@\+~%]+)(?:/.*)?$",
        "claim_key": "org_id",
        "resource_type": "org_id",
        "action": "BLOCK",
        "allow_admin": True,
        "priority": 100,
        "description": "Restricts organization-level resources to verified organization members."
    },
    {
        "id": "BOLA-004",
        "name": "Account & Financial Records Guard",
        "path_pattern": r"^/api/(?:v[0-9]+/)?accounts/(?P<resource_id>[a-zA-Z0-9_\-\.@\+~%]+)(?:/.*)?$",
        "claim_key": "account_id",
        "resource_type": "account_id",
        "action": "BLOCK",
        "allow_admin": True,
        "priority": 100,
        "description": "Protects private account and financial transaction resources."
    }
]


def canonicalize_request_path(path: str) -> Tuple[str, bool]:
    """
    Perform rigorous path canonicalization to prevent Path Desync / Traversal / Matrix Parameter attacks:
    1. Strip query string and fragments.
    2. Multi-layer URL decoding (up to 3 rounds) to defeat %252e%252e and %3b obfuscation.
    3. Null-byte stripping.
    4. Strip Matrix Parameters / Semicolons (;param=val) from each path segment.
    5. POSIX path normalization (resolves '/../', '/./', and double slashes).
    Returns: (canonical_path, has_traversal_or_desync_detected)
    """
    if not path:
        return "/", False

    clean = path.split("?")[0].split("#")[0].strip()
    if not clean:
        clean = "/"

    decoded = clean
    for _ in range(3):
        try:
            new_decoded = urllib.parse.unquote(decoded)
            if new_decoded == decoded:
                break
            decoded = new_decoded
        except Exception:
            break

    if chr(0) in decoded:
        decoded = decoded.replace(chr(0), "")

    has_traversal = (
        ".." in clean or ".." in decoded or
        "/./" in decoded or "//" in decoded or
        ";" in clean or ";" in decoded or
        "%2e" in clean.lower() or "%3b" in clean.lower()
    )

    # Strip matrix parameters from each path segment (e.g. /users/victim;foo=bar/profile -> /users/victim/profile)
    segments = decoded.split("/")
    cleaned_segments = [seg.split(";")[0] for seg in segments]
    decoded_stripped = "/".join(cleaned_segments)

    normalized = posixpath.normpath(decoded_stripped)
    if not normalized.startswith("/"):
        normalized = "/" + normalized

    return normalized, has_traversal


def decode_jwt_unverified_claims(token: str) -> Dict[str, Any]:
    """Legacy helper kept for backward compatibility (extracts payload without signature check)"""
    if not token or not isinstance(token, str):
        return {}
    parts = token.strip().split(".")
    if len(parts) < 2:
        return {}
    payload_b64 = parts[1]
    rem = len(payload_b64) % 4
    if rem > 0:
        payload_b64 += "=" * (4 - rem)
    try:
        payload_bytes = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
        return json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        return {}


def verify_and_decode_jwt(token: str, secret_key: str = JWT_SECRET_KEY) -> Tuple[Dict[str, Any], bool, Optional[str]]:
    """
    Cryptographically verify and decode JWT claims.
    Rejects 'alg: none', algorithm confusion (HMAC vs RSA key mismatch), and forged signatures.
    Returns: (claims_dict, is_cryptographically_verified, error_reason)
    """
    if not token or not isinstance(token, str):
        return {}, False, "EMPTY_TOKEN"

    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        return {}, False, "MALFORMED_JWT_STRUCTURE"

    # Extract payload for auditing forged content
    unverified_payload = {}
    try:
        payload_b64 = parts[1]
        rem = len(payload_b64) % 4
        if rem > 0:
            payload_b64 += "=" * (4 - rem)
        unverified_payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode("ascii")).decode("utf-8"))
    except Exception:
        pass

    # Fast header check for 'none' algorithm and unsupported algs
    try:
        header_b64 = parts[0]
        rem = len(header_b64) % 4
        if rem > 0:
            header_b64 += "=" * (4 - rem)
        header_json = json.loads(base64.urlsafe_b64decode(header_b64.encode("ascii")).decode("utf-8"))
        alg = str(header_json.get("alg", "")).upper()
        if not alg or alg == "NONE" or alg not in ALLOWED_JWT_ALGORITHMS:
            return unverified_payload, False, f"UNSUPPORTED_OR_FORBIDDEN_ALGORITHM_{alg}"
    except Exception:
        return unverified_payload, False, "INVALID_HEADER_ENCODING"

    # Cryptographic verification using jose with strict key-algorithm alignment
    try:
        from jose import jwt as jose_jwt
        if alg.startswith("HS"):
            verification_key = secret_key
            allowed_algs = [alg]
        elif alg.startswith("RS"):
            if not RSA_PUBLIC_KEY:
                return unverified_payload, False, f"RSA_PUBLIC_KEY_NOT_CONFIGURED_FOR_{alg}"
            verification_key = RSA_PUBLIC_KEY
            allowed_algs = [alg]
        else:
            return unverified_payload, False, f"UNSUPPORTED_ALGORITHM_FAMILY_{alg}"

        payload = jose_jwt.decode(
            token,
            verification_key,
            algorithms=allowed_algs,
            options={"verify_signature": True, "verify_aud": False}
        )
        return payload, True, None
    except Exception as e:
        return unverified_payload, False, f"SIGNATURE_VERIFICATION_FAILED: {str(e)}"


def validate_policy_regex(pattern: str) -> Tuple[bool, str]:
    """
    Validate BOLA regex pattern:
    1. Checks syntax and compilability.
    2. Ensures named group 'resource_id' exists or regex has at least one capture group.
    3. ReDoS safety verification.
    """
    if not pattern or not pattern.strip():
        return False, "Pattern cannot be empty"
    try:
        from services.safe_regex import validate_regex_safety
        is_safe, reason = validate_regex_safety(pattern)
        if not is_safe:
            return False, f"ReDoS Safety Failure: {reason}"
    except Exception:
        pass

    try:
        compiled = re.compile(pattern, re.IGNORECASE)
        if "resource_id" not in compiled.groupindex and compiled.groups < 1:
            return False, "Pattern must contain named capture group (?P<resource_id>...) or at least 1 capture group"
        return True, "OK"
    except re.error as e:
        return False, f"Invalid regex syntax: {str(e)}"


class BOLAGuard:
    """
    Context-Aware BOLA / IDOR Inspection and Policy Enforcement Service (Enterprise Edition)
    """

    def __init__(self, policies: Optional[List[Dict[str, Any]]] = None, secret_key: str = JWT_SECRET_KEY):
        self.policies: List[Dict[str, Any]] = []
        self.secret_key = secret_key
        raw_policies = DEFAULT_BOLA_POLICIES if policies is None else policies
        for p in raw_policies:
            self.add_policy(p, persist=False)
        if policies is None:
            self._load_persisted_policies()

    def _get_db(self):
        try:
            from services.dynamodb_service import DynamoDBService
            return DynamoDBService()
        except Exception:
            return None

    def _load_persisted_policies(self):
        """Attempts to load custom BOLA policies from DynamoDB"""
        try:
            db = self._get_db()
            if db and hasattr(db, "rules_table"):
                from boto3.dynamodb.conditions import Attr
                resp = db.rules_table.scan(
                    FilterExpression=Attr("type").eq("bola_policy")
                )
                items = resp.get("Items", [])
                for item in items:
                    self.add_policy(item, persist=False)
        except Exception as e:
            logger.debug("Could not load persisted BOLA policies from DynamoDB: %s", e)

    def _persist_policy(self, policy: Dict[str, Any]):
        """Persists a BOLA policy to DynamoDB if available"""
        try:
            db = self._get_db()
            if db and hasattr(db, "rules_table"):
                item = {
                    "id": policy["id"],
                    "type": "bola_policy",
                    "name": policy["name"],
                    "path_pattern": policy["path_pattern"],
                    "claim_key": policy["claim_key"],
                    "resource_type": policy["resource_type"],
                    "action": policy["action"],
                    "allow_admin": policy["allow_admin"],
                    "description": policy["description"],
                    "enabled": policy.get("enabled", True),
                    "methods": policy.get("methods", ["ALL"]),
                    "updated_at": str(int(time.time()))
                }
                db.rules_table.put_item(Item=item)
        except Exception as e:
            logger.debug("Failed to persist BOLA policy to DynamoDB: %s", e)

    def _delete_persisted_policy(self, policy_id: str):
        """Removes a BOLA policy from DynamoDB"""
        try:
            db = self._get_db()
            if db and hasattr(db, "rules_table"):
                db.rules_table.delete_item(Key={"id": policy_id})
        except Exception as e:
            logger.debug("Failed to delete persisted BOLA policy from DynamoDB: %s", e)

    def add_policy(self, policy_dict: Dict[str, Any], persist: bool = False) -> bool:
        """Add or update a BOLA protection policy."""
        try:
            pattern = str(policy_dict.get("path_pattern", "")).strip()
            if not pattern:
                return False

            compiled_re = re.compile(pattern, re.IGNORECASE)
            methods_raw = policy_dict.get("methods") or ["ALL"]
            if isinstance(methods_raw, str):
                methods = [m.strip().upper() for m in methods_raw.split(",") if m.strip()]
            else:
                methods = [str(m).strip().upper() for m in methods_raw if str(m).strip()]

            policy = {
                "id": policy_dict.get("id") or f"BOLA-{len(self.policies)+1:03d}",
                "name": policy_dict.get("name", "Custom BOLA Policy"),
                "path_pattern": pattern,
                "compiled_re": compiled_re,
                "claim_key": policy_dict.get("claim_key", "sub"),
                "resource_type": policy_dict.get("resource_type", "user_id"),
                "action": policy_dict.get("action", "BLOCK").upper(),
                "allow_admin": bool(policy_dict.get("allow_admin", True)),
                "description": policy_dict.get("description", ""),
                "enabled": policy_dict.get("enabled", True),
                "priority": int(policy_dict.get("priority", 100)),
                "methods": methods if methods else ["ALL"]
            }
            # Maintain evaluation order / in-place replacement to prevent policy shadowing
            existing_index = next((i for i, p in enumerate(self.policies) if p["id"] == policy["id"]), None)
            if existing_index is not None:
                self.policies[existing_index] = policy
            else:
                self.policies.append(policy)
            # Stable sort by priority (higher priority evaluated first)
            self.policies.sort(key=lambda p: p.get("priority", 100), reverse=True)
            if persist:
                self._persist_policy(policy)
            return True
        except Exception as e:
            logger.error("Failed to compile BOLA policy: %s", e)
            return False

    def update_policy(self, policy_id: str, updates: Dict[str, Any], persist: bool = True) -> bool:
        """Update fields of an existing BOLA policy."""
        target = self.get_policy(policy_id)
        if not target:
            return False
        merged = {**target, **updates, "id": policy_id}
        return self.add_policy(merged, persist=persist)

    def toggle_policy(self, policy_id: str, enabled: bool, persist: bool = True) -> bool:
        """Enable or disable a BOLA policy."""
        return self.update_policy(policy_id, {"enabled": enabled}, persist=persist)

    def remove_policy(self, policy_id: str, persist: bool = False) -> bool:
        """Remove a policy by ID."""
        initial_len = len(self.policies)
        self.policies = [p for p in self.policies if p["id"] != policy_id]
        if persist:
            self._delete_persisted_policy(policy_id)
        return len(self.policies) < initial_len

    def get_policy(self, policy_id: str) -> Optional[Dict[str, Any]]:
        """Fetch policy by ID."""
        for p in self.policies:
            if p["id"] == policy_id:
                return {
                    "id": p["id"],
                    "name": p["name"],
                    "path_pattern": p["path_pattern"],
                    "claim_key": p["claim_key"],
                    "resource_type": p["resource_type"],
                    "action": p["action"],
                    "allow_admin": p["allow_admin"],
                    "description": p["description"],
                    "enabled": p.get("enabled", True),
                    "methods": p.get("methods", ["ALL"])
                }
        return None

    def list_policies(self) -> List[Dict[str, Any]]:
        """Return list of active policies without compiled objects."""
        return [
            {
                "id": p["id"],
                "name": p["name"],
                "path_pattern": p["path_pattern"],
                "claim_key": p["claim_key"],
                "resource_type": p["resource_type"],
                "action": p["action"],
                "allow_admin": p["allow_admin"],
                "description": p["description"],
                "enabled": p.get("enabled", True),
                "methods": p.get("methods", ["ALL"])
            }
            for p in self.policies
        ]

    def extract_token_claims(self, headers: Dict[str, Any]) -> Tuple[Dict[str, Any], bool, Optional[str]]:
        """
        Extracts JWT token from headers and cryptographically verifies claims.
        Returns: (claims, is_verified, verify_error)
        """
        h_lower = {str(k).lower(): str(v) for k, v in headers.items()}
        auth_header = h_lower.get("authorization", "")
        token = ""

        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()
        elif "x-access-token" in h_lower:
            token = h_lower["x-access-token"].strip()
        elif "x-auth-token" in h_lower:
            token = h_lower["x-auth-token"].strip()

        if not token:
            return {}, False, "NO_TOKEN_PRESENT"

        claims, is_verified, err = verify_and_decode_jwt(token, self.secret_key)

        if "user_id" in claims and "sub" not in claims:
            claims["sub"] = claims["user_id"]
        elif "sub" in claims and "user_id" not in claims:
            claims["user_id"] = claims["sub"]

        return claims, is_verified, err

    def inspect_request(
        self,
        path: str,
        headers: Dict[str, Any],
        method: str = "GET",
        verified_user: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Inspects an HTTP request against active BOLA policies with cryptographic
        integrity and path canonicalization.
        """
        # 1. Rigorous Path Canonicalization (Anti-Desync & Path Traversal Normalization)
        canonical_path, had_traversal = canonicalize_request_path(path)
        h_lower = {str(k).lower(): str(v) for k, v in headers.items()}

        # 2. Extract & Verify Token Claims
        if verified_user:
            claims = {
                "sub": verified_user.get("user_id") or verified_user.get("sub", ""),
                "user_id": verified_user.get("user_id") or verified_user.get("sub", ""),
                "tenant_id": verified_user.get("tenant_id", ""),
                "org_id": verified_user.get("org_id", ""),
                "account_id": verified_user.get("account_id", ""),
                "role": verified_user.get("role", "viewer")
            }
            is_cryptographically_verified = True
            verify_error = None
        else:
            claims, is_cryptographically_verified, verify_error = self.extract_token_claims(headers)

        role = claims.get("role", "viewer")

        # 3. Forged JWT / Cryptographic Failure Check
        if verify_error and verify_error != "NO_TOKEN_PRESENT":
            return {
                "is_allowed": False,
                "action": "BLOCK",
                "violation": True,
                "violation_type": "FORGED_JWT_SIGNATURE",
                "matched_policy": {"id": "BOLA-SYS-CRYPTO", "name": "Cryptographic JWT Integrity Check"},
                "claimed_identity": claims,
                "targeted_resource": {"path": canonical_path, "raw_path": path},
                "risk_score": 98,
                "message": f"🚨 Forged / Unverified JWT Signature Detected ({verify_error}). Administrative bypass rejected."
            }

        # 4. Header Anti-Spoofing
        spoofed_user_id = h_lower.get("x-user-id")
        spoofed_tenant_id = h_lower.get("x-tenant-id")

        if spoofed_user_id:
            if not is_cryptographically_verified or (claims.get("sub") and spoofed_user_id != claims.get("sub")):
                return {
                    "is_allowed": False,
                    "action": "BLOCK",
                    "violation": True,
                    "violation_type": "HEADER_SPOOFING",
                    "matched_policy": {"id": "BOLA-SYS-SPOOF", "name": "Identity Header Anti-Spoofing"},
                    "claimed_identity": claims,
                    "targeted_resource": {"resource_type": "user_id", "resource_id": spoofed_user_id, "path": canonical_path},
                    "risk_score": 95,
                    "message": f"BOLA Guard: Spoofed X-User-ID ('{spoofed_user_id}') conflicts with authenticated identity ('{claims.get('sub')}')"
                }

        if spoofed_tenant_id:
            if not is_cryptographically_verified or (claims.get("tenant_id") and spoofed_tenant_id != claims.get("tenant_id")):
                return {
                    "is_allowed": False,
                    "action": "BLOCK",
                    "violation": True,
                    "violation_type": "TENANT_HEADER_SPOOFING",
                    "matched_policy": {"id": "BOLA-SYS-SPOOF", "name": "Tenant Header Anti-Spoofing"},
                    "claimed_identity": claims,
                    "targeted_resource": {"resource_type": "tenant_id", "resource_id": spoofed_tenant_id, "path": canonical_path},
                    "risk_score": 95,
                    "message": f"BOLA Guard: Spoofed X-Tenant-ID ('{spoofed_tenant_id}') conflicts with authenticated tenant ('{claims.get('tenant_id')}')"
                }

        # 5. Evaluate Path Policies against CANONICAL path
        req_method = (method or "GET").upper().strip()
        for policy in self.policies:
            if not policy.get("enabled", True):
                continue

            policy_methods = policy.get("methods") or ["ALL"]
            if "ALL" not in policy_methods and req_method not in policy_methods:
                continue

            match = policy["compiled_re"].match(canonical_path)
            if not match:
                continue

            target_id = match.groupdict().get("resource_id", "").strip()
            if not target_id:
                # If regex has capture group 1 without named resource_id
                if match.groups():
                    target_id = match.group(1).strip()
                else:
                    continue

            # 5.1 Public Action Whitelist Check (Method-Aware & Sub-path Protected)
            # Prevents Username Shadowing: Only exact action paths without sub-resources are exempted.
            # e.g. /api/v1/users/register (POST/GET) is public, but /api/v1/users/login/profile or /users/token/data is NOT!
            if policy.get("resource_type") == "user_id":
                target_key = target_id.lower()
                allowed_methods = PUBLIC_USER_METHOD_MAP.get(target_key)
                req_method = (method or "GET").upper().strip()
                is_exact_action_path = (
                    canonical_path.rstrip("/").endswith(f"/users/{target_id}")
                    or canonical_path.rstrip("/").endswith(f"/auth/{target_id}")
                )
                if allowed_methods is not None and req_method in allowed_methods and is_exact_action_path:
                    return {
                        "is_allowed": True,
                        "action": "ALLOW",
                        "violation": False,
                        "violation_type": None,
                        "matched_policy": {"id": policy["id"], "name": policy["name"]},
                        "claimed_identity": claims,
                        "targeted_resource": {
                            "resource_type": policy["resource_type"],
                            "resource_id": target_id,
                            "path": canonical_path
                        },
                        "risk_score": 0,
                        "message": f"Public endpoint '{canonical_path}' ({req_method}) exempted from BOLA authorization check"
                    }

            # 5.2 Handle '/users/me' alias
            if target_id.lower() == "me":
                if is_cryptographically_verified and claims.get("sub"):
                    return {
                        "is_allowed": True,
                        "action": "ALLOW",
                        "violation": False,
                        "violation_type": None,
                        "matched_policy": {"id": policy["id"], "name": policy["name"]},
                        "claimed_identity": claims,
                        "targeted_resource": {
                            "resource_type": policy["resource_type"],
                            "resource_id": claims.get("sub"),
                            "path": canonical_path
                        },
                        "risk_score": 0,
                        "message": "Self identity alias '/users/me' authorized"
                    }
                else:
                    return {
                        "is_allowed": False,
                        "action": policy["action"],
                        "violation": True,
                        "violation_type": "UNAUTHENTICATED_OBJECT_ACCESS",
                        "matched_policy": {"id": policy["id"], "name": policy["name"]},
                        "claimed_identity": claims,
                        "targeted_resource": {"resource_type": "user_id", "resource_id": "me", "path": canonical_path},
                        "risk_score": 85,
                        "message": "Unauthenticated access attempt to '/users/me'"
                    }

            claim_key = policy["claim_key"]
            claim_val = str(claims.get(claim_key, "")).strip()

            # 5.3 Handle Admin Bypass (ONLY if Cryptographically Verified!)
            if is_cryptographically_verified and role == "admin" and policy.get("allow_admin", True):
                return {
                    "is_allowed": True,
                    "action": "ALLOW",
                    "violation": False,
                    "violation_type": None,
                    "matched_policy": {"id": policy["id"], "name": policy["name"]},
                    "claimed_identity": claims,
                    "targeted_resource": {
                        "resource_type": policy["resource_type"],
                        "resource_id": target_id,
                        "path": canonical_path
                    },
                    "risk_score": 0,
                    "message": f"Administrative access authorized for resource '{target_id}'"
                }

            # 5.4 If request has NO authenticated claims for protected resource
            if not is_cryptographically_verified or not claim_val:
                return {
                    "is_allowed": False,
                    "action": policy["action"],
                    "violation": True,
                    "violation_type": "UNAUTHENTICATED_OBJECT_ACCESS",
                    "matched_policy": {"id": policy["id"], "name": policy["name"]},
                    "claimed_identity": claims,
                    "targeted_resource": {
                        "resource_type": policy["resource_type"],
                        "resource_id": target_id,
                        "path": canonical_path
                    },
                    "risk_score": 85,
                    "message": f"BOLA Guard: Unauthenticated access attempt to protected {policy['resource_type']} resource '{target_id}'"
                }

            # 5.5 If Claim Value does NOT match Target Resource ID in Path
            if claim_val != target_id:
                action = policy["action"]
                is_allowed = (action != "BLOCK")
                return {
                    "is_allowed": is_allowed,
                    "action": action,
                    "violation": True,
                    "violation_type": "OBJECT_AUTHORIZATION_MISMATCH",
                    "matched_policy": {"id": policy["id"], "name": policy["name"]},
                    "claimed_identity": claims,
                    "targeted_resource": {
                        "resource_type": policy["resource_type"],
                        "resource_id": target_id,
                        "path": canonical_path
                    },
                    "risk_score": 90,
                    "message": (
                        f"🚨 BOLA / IDOR Violation Detected: Authenticated {claim_key} ('{claim_val}') "
                        f"attempted to access foreign {policy['resource_type']} ('{target_id}') on '{canonical_path}'"
                    )
                }

        # Passed all BOLA checks
        return {
            "is_allowed": True,
            "action": "ALLOW",
            "violation": False,
            "violation_type": None,
            "matched_policy": None,
            "claimed_identity": claims,
            "targeted_resource": {"path": canonical_path},
            "risk_score": 0,
            "message": "Request passed BOLA and tenant isolation validation"
        }


# Global singleton instance
bola_guard = BOLAGuard()
