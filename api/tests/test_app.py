from __future__ import annotations

import re
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from io import BytesIO
from typing import Any

import pytest
from fastapi.testclient import TestClient
from PIL import Image, PngImagePlugin
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import Settings, get_settings
from app.db import Base, SharedFile, get_db
from app.main import app, serializer
from app import main as main_module


@pytest.fixture
def settings() -> Settings:
    return Settings(
        app_env="test",
        public_url="http://testserver",
        management_base_path="/manage",
        share_base_path="/public",
        auth_base_url="/auth",
        session_key="test-secret",
    )


@pytest.fixture
def client(settings: Settings) -> Generator[TestClient]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db() -> Generator[Session]:
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_db] = override_get_db
    app.state.testing_session_local = TestingSessionLocal
    app.state.skip_startup_migrate = True
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
        delattr(app.state, "skip_startup_migrate")
        delattr(app.state, "testing_session_local")


def auth_cookie(settings: Settings) -> str:
    return serializer(settings).dumps({"sub": "oauth:owner", "preferred_username": "owner"})


def test_management_page_redirects_to_oauth_when_unauthenticated(client: TestClient) -> None:
    response = client.get("/manage", follow_redirects=False)

    assert response.status_code == 307
    assert response.headers["location"].startswith("/manage/auth/oauth/login")


def test_oauth_login_uses_only_configured_auth_base_url(client: TestClient) -> None:
    response = client.get("/manage/auth/oauth/login", follow_redirects=False)

    assert response.status_code == 307
    location = response.headers["location"]
    assert location.startswith("http://testserver/auth/oauth/authorize")
    assert location.startswith("http://testserver/auth/")


def test_upload_and_management_pages_are_separate(client: TestClient, settings: Settings) -> None:
    client.cookies.set(settings.session_cookie_name, auth_cookie(settings))

    upload = client.get("/manage")
    manage = client.get("/manage/manage")

    assert upload.status_code == 200
    assert manage.status_code == 200
    assert '<section id="upload-page" class="panel upload-card">' in upload.text
    assert '<section id="manage-page" hidden>' in upload.text
    assert '<section id="upload-page" class="panel upload-card" hidden>' in manage.text
    assert '<section id="manage-page">' in manage.text
    assert "Active expiring soon" in manage.text
    assert "Hidden" in manage.text
    assert '<option value="years">Years</option>' in upload.text
    assert "event.currentTarget.reset()" not in upload.text
    assert "form.reset()" in upload.text
    assert '<span class="tile-title">' not in manage.text
    assert '<span class="tile-meta">' not in manage.text
    assert "body.manage-view .tile-grid" in manage.text
    assert "<ghwiz-federated-banner" in upload.text
    assert 'current-app-slug="file-share"' in upload.text
    assert "__BANNER_SITES_JSON__" not in upload.text


def test_federated_banner_script_is_protected(client: TestClient, settings: Settings) -> None:
    unauthenticated = client.get("/manage/static/federated-banner.js", follow_redirects=False)
    assert unauthenticated.status_code == 307

    client.cookies.set(settings.session_cookie_name, auth_cookie(settings))
    response = client.get("/manage/static/federated-banner.js")

    assert response.status_code == 200
    assert "customElements.define" in response.text


def test_public_share_serves_active_file(client: TestClient, settings: Settings) -> None:
    SessionLocal = app.state.testing_session_local
    with SessionLocal() as db:
        db.add(
            SharedFile(
                id="file-1",
                public_name="token.txt",
                original_filename="hello.txt",
                stored_extension="txt",
                content_type="text/plain",
                size_bytes=5,
                sha256="x" * 64,
                blob_data=b"hello",
                created_by_subject="owner",
                created_by_username="owner",
                created_at=datetime.now(tz=UTC),
                expires_at=datetime.now(tz=UTC) + timedelta(hours=1),
            )
        )
        db.commit()

    response = client.get("/public/token.txt")

    assert response.status_code == 200
    assert response.content == b"hello"
    assert response.headers["content-type"].startswith("text/plain")


def test_public_share_rejects_expired_file(client: TestClient) -> None:
    SessionLocal = app.state.testing_session_local
    with SessionLocal() as db:
        db.add(
            SharedFile(
                id="file-1",
                public_name="token.txt",
                original_filename="hello.txt",
                stored_extension="txt",
                content_type="text/plain",
                size_bytes=5,
                sha256="x" * 64,
                blob_data=b"hello",
                created_by_subject="owner",
                created_by_username="owner",
                created_at=datetime.now(tz=UTC) - timedelta(hours=2),
                expires_at=datetime.now(tz=UTC) - timedelta(hours=1),
            )
        )
        db.commit()

    response = client.get("/public/token.txt")

    assert response.status_code == 410


def test_upload_supports_year_lifetime_and_short_public_name(
    client: TestClient,
    settings: Settings,
) -> None:
    client.cookies.set(settings.session_cookie_name, auth_cookie(settings))

    response = client.post(
        "/manage/api/files",
        files={"file": ("note.txt", b"hello", "text/plain")},
        data={
            "lifetime_value": "1",
            "lifetime_unit": "years",
            "resize_image": "false",
            "strip_metadata": "true",
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert re.match(r"^/public/[0-9a-f]{8}\.txt$", payload["share_url"])
    created_at = datetime.fromisoformat(payload["created_at"])
    expires_at = datetime.fromisoformat(payload["expires_at"])
    assert timedelta(days=364) < expires_at - created_at < timedelta(days=366)


def test_short_public_name_avoids_token_collisions(
    client: TestClient,
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    SessionLocal = app.state.testing_session_local
    with SessionLocal() as db:
        db.add(
            SharedFile(
                id="file-1",
                public_name="deadbeef.txt",
                original_filename="hello.txt",
                stored_extension="txt",
                content_type="text/plain",
                size_bytes=5,
                sha256="x" * 64,
                blob_data=b"hello",
                created_by_subject="owner",
                created_by_username="owner",
                created_at=datetime.now(tz=UTC),
                expires_at=datetime.now(tz=UTC) + timedelta(hours=1),
            )
        )
        db.commit()
    tokens = iter(["deadbeef", "cafebabe"])
    monkeypatch.setattr(main_module.secrets, "token_hex", lambda _: next(tokens))
    client.cookies.set(settings.session_cookie_name, auth_cookie(settings))

    response = client.post(
        "/manage/api/files",
        files={"file": ("new.txt", b"new", "text/plain")},
        data={
            "lifetime_value": "24",
            "lifetime_unit": "hours",
            "resize_image": "false",
            "strip_metadata": "true",
        },
    )

    assert response.status_code == 201
    assert response.json()["share_url"] == "/public/cafebabe.txt"


def test_image_upload_can_strip_metadata_resize_and_create_thumbnail(
    client: TestClient,
    settings: Settings,
) -> None:
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("Secret", "keep-out")
    source = BytesIO()
    Image.new("RGB", (800, 400), color=(32, 80, 160)).save(source, format="PNG", pnginfo=metadata)
    client.cookies.set(settings.session_cookie_name, auth_cookie(settings))

    response = client.post(
        "/manage/api/files",
        files={"file": ("photo.png", source.getvalue(), "image/png")},
        data={
            "lifetime_value": "2",
            "lifetime_unit": "hours",
            "resize_image": "true",
            "max_image_dimension": "200",
            "strip_metadata": "true",
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["is_image"] is True
    assert payload["image_width"] == 200
    assert payload["image_height"] == 100

    SessionLocal = app.state.testing_session_local
    with SessionLocal() as db:
        row = db.get(SharedFile, payload["id"])
        assert row is not None
        stored = Image.open(BytesIO(row.blob_data))
        assert stored.size == (200, 100)
        assert "Secret" not in stored.info
        assert row.thumbnail_data is not None
