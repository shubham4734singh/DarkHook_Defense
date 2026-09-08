import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone, timedelta

from schemas.auth import UserCreate, EmailOtpVerify
from services.auth_service import AuthService
from services.otp_service import OtpService
from core.exceptions import AuthException, OTPException

@pytest.fixture
def mock_db_collections():
    users_db = {}
    pending_db = {}
    otps_db = {}

    # Mock user repository
    mock_user_repo = MagicMock()
    def find_user(email):
        return users_db.get(email.strip().lower())
    def create_user(doc):
        users_db[doc["email"].strip().lower()] = doc
    def mark_verified(email, verified_at):
        if email.strip().lower() in users_db:
            users_db[email.strip().lower()]["email_verified"] = True
            users_db[email.strip().lower()]["email_verified_at"] = verified_at
    def delete_user(email):
        users_db.pop(email.strip().lower(), None)

    mock_user_repo.find_by_email.side_effect = find_user
    mock_user_repo.create_user.side_effect = create_user
    mock_user_repo.mark_email_verified.side_effect = mark_verified
    mock_user_repo.delete_by_email.side_effect = delete_user

    # Mock pending user repository
    mock_pending_repo = MagicMock()
    def find_pending(email):
        return pending_db.get(email.strip().lower())
    def upsert_pending(email, name, hashed_password, expires_at):
        pending_db[email.strip().lower()] = {
            "name": name,
            "email": email.strip().lower(),
            "password": hashed_password,
            "expires_at": expires_at,
            "created_at": datetime.now(timezone.utc),
        }
    def delete_pending(email):
        pending_db.pop(email.strip().lower(), None)
    def extend_expiry(email, expires_at):
        if email.strip().lower() in pending_db:
            pending_db[email.strip().lower()]["expires_at"] = expires_at

    mock_pending_repo.find_by_email.side_effect = find_pending
    mock_pending_repo.upsert_pending_user.side_effect = upsert_pending
    mock_pending_repo.delete_by_email.side_effect = delete_pending
    mock_pending_repo.extend_expiry.side_effect = extend_expiry

    # Mock otp repository
    mock_otp_repo = MagicMock()
    saved_otps = []
    def create_otp(doc):
        doc["_id"] = f"otp_{len(saved_otps) + 1}"
        saved_otps.append(doc)
        return doc["_id"]
    def find_latest_unconsumed(email, purpose):
        matches = [
            d for d in saved_otps
            if d["email"] == email.strip().lower() and d["purpose"] == purpose and d.get("consumed_at") is None
        ]
        return matches[-1] if matches else None
    def delete_otp(otp_id):
        for i, d in enumerate(saved_otps):
            if d.get("_id") == otp_id:
                saved_otps.pop(i)
                break
    def increment_attempts(otp_id):
        for d in saved_otps:
            if d.get("_id") == otp_id:
                d["attempts"] = d.get("attempts", 0) + 1

    mock_otp_repo.create_otp.side_effect = create_otp
    mock_otp_repo.find_latest_unconsumed.side_effect = find_latest_unconsumed
    mock_otp_repo.delete_otp.side_effect = delete_otp
    mock_otp_repo.increment_attempts.side_effect = increment_attempts

    return {
        "users_db": users_db,
        "pending_db": pending_db,
        "saved_otps": saved_otps,
        "user_repo": mock_user_repo,
        "pending_repo": mock_pending_repo,
        "otp_repo": mock_otp_repo,
    }


def test_deferred_account_creation_flow(mock_db_collections, monkeypatch):
    """
    Verify:
    1. Calling register_user when REQUIRE_EMAIL_VERIFICATION is True does NOT create user in users collection.
    2. Pending registration is created in pending_registrations.
    3. Verifying OTP creates the user with email_verified: True.
    4. Pending registration and OTP are cleaned up.
    """
    monkeypatch.setattr("core.config.settings.REQUIRE_EMAIL_VERIFICATION", True)
    monkeypatch.setattr("core.config.settings.SECRET_KEY", "test-secret-key-12345678901234567890")

    db = mock_db_collections
    monkeypatch.setattr("services.auth_service.user_repository", db["user_repo"])
    monkeypatch.setattr("services.auth_service.pending_user_repository", db["pending_repo"])
    monkeypatch.setattr("services.otp_service.user_repository", db["user_repo"])
    monkeypatch.setattr("services.otp_service.pending_user_repository", db["pending_repo"])
    monkeypatch.setattr("services.otp_service.otp_repository", db["otp_repo"])

    captured_emails = []
    def mock_send_email(email, otp):
        captured_emails.append((email, otp))

    monkeypatch.setattr("services.otp_service.send_otp_email", mock_send_email)

    from services.auth_service import auth_service
    from services.otp_service import otp_service

    # Step 1: User registers
    test_email = "alice@example.com"
    test_name = "Alice Defender"
    test_password = "SecurePassword123"

    result = auth_service.register_user(test_name, test_email, test_password)

    # ASSERTION 1: Response indicates verification is required
    assert result["requires_verification"] is True
    assert result["email"] == test_email

    # ASSERTION 2: In MongoDB users collection, ZERO records created!
    assert test_email not in db["users_db"]
    assert len(db["users_db"]) == 0

    # ASSERTION 3: Record exists in pending_registrations
    assert test_email in db["pending_db"]
    pending = db["pending_db"][test_email]
    assert pending["name"] == test_name
    assert pending["email"] == test_email
    assert pending["password"] != test_password  # Must be hashed!

    # ASSERTION 4: OTP was generated and emailed
    assert len(captured_emails) == 1
    assert captured_emails[0][0] == test_email
    sent_otp = captured_emails[0][1]
    assert len(sent_otp) == 6

    # Step 2: Attempt verification with invalid OTP
    with pytest.raises(OTPException) as exc_info:
        otp_service.verify_email_otp(test_email, "000000" if sent_otp != "000000" else "111111")
    assert "Invalid OTP" in str(exc_info.value)
    # Still NO user in users collection
    assert test_email not in db["users_db"]

    # Step 3: Enter correct OTP code
    verify_result = otp_service.verify_email_otp(test_email, sent_otp)
    assert verify_result["message"] == "Account created and verified successfully."
    assert "access_token" in verify_result
    assert verify_result["token_type"] == "bearer"

    # ASSERTION 5: User NOW exists in users collection with email_verified: True!
    assert test_email in db["users_db"]
    created_user = db["users_db"][test_email]
    assert created_user["name"] == test_name
    assert created_user["email"] == test_email
    assert created_user["email_verified"] is True
    assert created_user["email_verified_at"] is not None

    # ASSERTION 6: Pending registration and OTP challenge cleaned up!
    assert test_email not in db["pending_db"]
    assert len(db["saved_otps"]) == 0

    # Step 4: Try registering again with same email -> Rejection!
    with pytest.raises(AuthException) as auth_err:
        auth_service.register_user("Alice Clone", test_email, test_password)
    assert "Email already registered" in str(auth_err.value)

    # Step 5: Verify login works with the newly created account
    token = auth_service.authenticate_user(test_email, test_password)
    assert token is not None


def test_abandoned_signup_does_not_block_future_registration(mock_db_collections, monkeypatch):
    """
    Verify that if a user registers but never enters OTP, no user record is created in users
    and they can re-register cleanly.
    """
    monkeypatch.setattr("core.config.settings.REQUIRE_EMAIL_VERIFICATION", True)
    monkeypatch.setattr("core.config.settings.SECRET_KEY", "test-secret-key-12345678901234567890")
    monkeypatch.setattr("core.config.settings.OTP_RESEND_COOLDOWN_SECONDS", 0)

    db = mock_db_collections
    monkeypatch.setattr("services.auth_service.user_repository", db["user_repo"])
    monkeypatch.setattr("services.auth_service.pending_user_repository", db["pending_repo"])
    monkeypatch.setattr("services.otp_service.user_repository", db["user_repo"])
    monkeypatch.setattr("services.otp_service.pending_user_repository", db["pending_repo"])
    monkeypatch.setattr("services.otp_service.otp_repository", db["otp_repo"])
    monkeypatch.setattr("services.otp_service.send_otp_email", lambda email, otp: None)

    from services.auth_service import auth_service

    test_email = "bob@example.com"
    # Registration 1 (abandoned)
    auth_service.register_user("Bob Old", test_email, "PasswordOne123")
    assert test_email not in db["users_db"]
    assert test_email in db["pending_db"]

    # Registration 2 (comes back later to register again)
    auth_service.register_user("Bob New", test_email, "PasswordTwo123")
    assert test_email not in db["users_db"]
    assert db["pending_db"][test_email]["name"] == "Bob New"


def test_resend_otp_for_pending_user(mock_db_collections, monkeypatch):
    """Verify that requesting an OTP resend works for a pending user and respects cooldown."""
    monkeypatch.setattr("core.config.settings.REQUIRE_EMAIL_VERIFICATION", True)
    monkeypatch.setattr("core.config.settings.SECRET_KEY", "test-secret-key-12345678901234567890")
    monkeypatch.setattr("core.config.settings.OTP_RESEND_COOLDOWN_SECONDS", 60)

    db = mock_db_collections
    monkeypatch.setattr("services.auth_service.user_repository", db["user_repo"])
    monkeypatch.setattr("services.auth_service.pending_user_repository", db["pending_repo"])
    monkeypatch.setattr("services.otp_service.user_repository", db["user_repo"])
    monkeypatch.setattr("services.otp_service.pending_user_repository", db["pending_repo"])
    monkeypatch.setattr("services.otp_service.otp_repository", db["otp_repo"])

    captured_emails = []
    monkeypatch.setattr("services.otp_service.send_otp_email", lambda email, otp: captured_emails.append((email, otp)))

    from services.auth_service import auth_service
    from services.otp_service import otp_service

    test_email = "charlie@example.com"
    auth_service.register_user("Charlie", test_email, "SecurePassword123")
    assert len(captured_emails) == 1

    # Resend immediately -> Cooldown should trigger
    msg = otp_service.request_email_otp(test_email)
    assert "recently sent" in msg.lower()
    assert len(captured_emails) == 1  # No second email sent during cooldown

    # Simulate cooldown passing
    monkeypatch.setattr("core.config.settings.OTP_RESEND_COOLDOWN_SECONDS", 0)
    msg2 = otp_service.request_email_otp(test_email)
    assert "sent" in msg2.lower()
    assert len(captured_emails) == 2  # Second OTP dispatched!


def test_legacy_unverified_user_verification(mock_db_collections, monkeypatch):
    """
    Verify that an existing unverified record in 'users' can still be verified,
    maintaining backward compatibility.
    """
    monkeypatch.setattr("core.config.settings.REQUIRE_EMAIL_VERIFICATION", True)
    monkeypatch.setattr("core.config.settings.SECRET_KEY", "test-secret-key-12345678901234567890")
    monkeypatch.setattr("core.config.settings.OTP_RESEND_COOLDOWN_SECONDS", 0)

    db = mock_db_collections
    monkeypatch.setattr("services.auth_service.user_repository", db["user_repo"])
    monkeypatch.setattr("services.auth_service.pending_user_repository", db["pending_repo"])
    monkeypatch.setattr("services.otp_service.user_repository", db["user_repo"])
    monkeypatch.setattr("services.otp_service.pending_user_repository", db["pending_repo"])
    monkeypatch.setattr("services.otp_service.otp_repository", db["otp_repo"])

    captured_emails = []
    monkeypatch.setattr("services.otp_service.send_otp_email", lambda email, otp: captured_emails.append((email, otp)))

    from services.otp_service import otp_service

    legacy_email = "legacy@example.com"
    # Seed legacy unverified user in users collection
    db["users_db"][legacy_email] = {
        "name": "Legacy User",
        "email": legacy_email,
        "password": "hashedpassword123",
        "email_verified": False,
        "email_verified_at": None,
    }

    # Request OTP for legacy user
    otp_service.request_email_otp(legacy_email)
    assert len(captured_emails) == 1
    sent_otp = captured_emails[0][1]

    # Verify OTP
    result = otp_service.verify_email_otp(legacy_email, sent_otp)
    assert result["message"] == "Email verified successfully."
    assert db["users_db"][legacy_email]["email_verified"] is True

