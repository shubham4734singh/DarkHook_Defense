"""Tests for email OTP verification flow.

These tests:
- do NOT require a real MongoDB instance
- do NOT send real emails (email sender is mocked)
"""

import os
import sys
from copy import deepcopy
from datetime import datetime
from pathlib import Path

import pytest


# Add Backend to path for imports and change to Backend directory for .env
backend_path = Path(__file__).resolve().parent.parent / "Backend"
sys.path.insert(0, str(backend_path))
os.chdir(backend_path)


class _InsertOneResult:
    def __init__(self, inserted_id):
        self.inserted_id = inserted_id


class FakeCollection:
    def __init__(self):
        self._docs = []
        self._next_id = 1

    def create_index(self, *args, **kwargs):
        return None

    def insert_one(self, doc):
        to_store = deepcopy(doc)
        if "_id" not in to_store:
            to_store["_id"] = self._next_id
            self._next_id += 1
        self._docs.append(to_store)
        return _InsertOneResult(to_store["_id"])

    def find_one(self, filter=None, sort=None):
        filter = filter or {}

        def matches(d):
            for k, v in filter.items():
                if d.get(k) != v:
                    return False
            return True

        candidates = [d for d in self._docs if matches(d)]
        if not candidates:
            return None

        if sort:
            # sort is list of tuples, e.g. [("created_at", -1)]
            for key, direction in reversed(sort):
                reverse = direction == -1
                candidates.sort(key=lambda x: x.get(key), reverse=reverse)

        return deepcopy(candidates[0])

    def update_one(self, filter, update):
        def matches(d):
            for k, v in (filter or {}).items():
                if d.get(k) != v:
                    return False
            return True

        for d in self._docs:
            if not matches(d):
                continue

            if "$set" in update:
                for k, v in update["$set"].items():
                    d[k] = v
            if "$inc" in update:
                for k, v in update["$inc"].items():
                    d[k] = int(d.get(k, 0)) + int(v)
            return None

        return None

    def delete_one(self, filter):
        def matches(d):
            for k, v in (filter or {}).items():
                if d.get(k) != v:
                    return False
            return True

        for i, d in enumerate(self._docs):
            if matches(d):
                self._docs.pop(i)
                return None
        return None


class FakeDb:
    def __init__(self):
        self._collections = {
            "users": FakeCollection(),
            "email_otps": FakeCollection(),
        }

    def __getitem__(self, name):
        return self._collections[name]


@pytest.fixture()
def client(monkeypatch):
    # Ensure SECRET_KEY is set before any imports that require it.
    os.environ.setdefault("SECRET_KEY", "test-secret")

    from fastapi.testclient import TestClient
    import auth.auth_routes as auth_routes
    from app import app

    fake_db = FakeDb()
    monkeypatch.setattr(auth_routes, "get_database", lambda: fake_db)

    sent = {"otp": None, "email": None}

    def _fake_send_email(to_email: str, otp: str):
        sent["email"] = to_email
        sent["otp"] = otp

    monkeypatch.setattr(auth_routes, "_send_email_otp", _fake_send_email)

    c = TestClient(app)
    c._fake_sent = sent  # type: ignore[attr-defined]
    return c


def test_request_otp_nonexistent_user_is_generic(client):
    res = client.post("/auth/email-otp/request", json={"email": "noone@example.com"})
    assert res.status_code == 200
    assert "message" in res.json()


def test_register_request_verify_otp_success(client):
    email = "user@example.com"
    password = "Passw0rd!"

    reg = client.post(
        "/auth/register",
        json={"name": "Test", "email": email, "password": password},
    )
    assert reg.status_code == 200

    req = client.post("/auth/email-otp/request", json={"email": email})
    assert req.status_code == 200

    otp = getattr(client, "_fake_sent")["otp"]
    assert otp is not None
    assert len(otp) == 6

    bad = client.post("/auth/email-otp/verify", json={"email": email, "otp": "000000"})
    assert bad.status_code in (400, 429)

    good = client.post("/auth/email-otp/verify", json={"email": email, "otp": otp})
    assert good.status_code == 200
    assert "message" in good.json()
