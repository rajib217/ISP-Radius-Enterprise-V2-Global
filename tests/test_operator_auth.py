from datetime import UTC, datetime

from argon2 import PasswordHasher

from isp_radius.security.operator_auth import (
    csrf_matches,
    hash_token,
    issue_session_tokens,
    normalize_operator_email,
    permissions_for_role,
    verify_operator_password,
)


def test_operator_email_is_normalized_and_validated():
    assert normalize_operator_email("  Operator@Example.COM ") == "operator@example.com"

    for invalid in ("", "operator", "@example.com", "operator@", "a b@example.com"):
        try:
            normalize_operator_email(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid email was accepted")


def test_session_tokens_are_random_and_only_hashes_are_persistable():
    issued = issue_session_tokens(now=datetime(2026, 1, 1, tzinfo=UTC))
    assert len(issued.session_token) >= 40
    assert len(issued.csrf_token) >= 40
    assert issued.session_hash == hash_token(issued.session_token)
    assert issued.csrf_hash == hash_token(issued.csrf_token)
    assert issued.session_token != issued.csrf_token
    assert issued.expires_at > datetime(2026, 1, 1, tzinfo=UTC)


def test_password_verification_accepts_only_valid_argon2id_hashes():
    password = "a-long-operator-password"
    encoded = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(password)
    assert verify_operator_password(encoded, password)
    assert not verify_operator_password(encoded, "wrong-password")
    assert not verify_operator_password("plain-text", password)


def test_csrf_requires_header_cookie_and_database_hash_to_match():
    csrf = "high-entropy-csrf-token"
    digest = hash_token(csrf)
    assert csrf_matches(supplied_header=csrf, csrf_cookie=csrf, stored_hash=digest)
    assert not csrf_matches(supplied_header="wrong", csrf_cookie=csrf, stored_hash=digest)
    assert not csrf_matches(supplied_header=csrf, csrf_cookie=None, stored_hash=digest)
    assert not csrf_matches(supplied_header=csrf, csrf_cookie=csrf, stored_hash="0" * 64)


def test_role_permissions_are_explicit_and_unknown_roles_deny_all():
    assert "*" in permissions_for_role("owner")
    assert permissions_for_role("viewer") == frozenset(
        {"sessions:read", "subscribers:read", "billing:read"}
    )
    assert "sessions:disconnect" not in permissions_for_role("viewer")
    assert permissions_for_role("unrecognized") == frozenset()
