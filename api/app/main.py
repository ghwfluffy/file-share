from __future__ import annotations

import base64
import hashlib
import html
import json
import mimetypes
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated
from urllib.parse import urlencode

import httpx
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db import SharedFile, get_db, migrate
from app.image_processing import process_upload


app = FastAPI(title="File Share")


def serializer(settings: Settings) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.session_key or "", salt="file-share")


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def pkce_challenge(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def management_url(settings: Settings, path: str = "") -> str:
    suffix = path if path.startswith("/") or path == "" else f"/{path}"
    return f"{settings.normalized_management_base_path}{suffix}"


def share_url(settings: Settings, public_name: str) -> str:
    return f"{settings.normalized_share_base_path}/{public_name}"


def public_share_url(settings: Settings, public_name: str) -> str:
    return f"{settings.public_origin}{share_url(settings, public_name)}"


def generate_public_name(db: Session, extension: str) -> str:
    for _ in range(32):
        token = secrets.token_hex(4)
        exists = db.scalar(select(SharedFile.id).where(SharedFile.public_name.like(f"{token}.%")))
        if not exists:
            return f"{token}.{extension}"
    raise HTTPException(status_code=503, detail="Could not allocate a share link. Try again.")


def require_prefix(prefix_slug: str, expected_prefix: str) -> None:
    if normalize_request_prefix(prefix_slug) != expected_prefix:
        raise HTTPException(status_code=404)


def normalize_request_prefix(prefix_slug: str) -> str:
    normalized = f"/{prefix_slug.strip('/')}"
    return normalized.rstrip("/")


def safe_next(settings: Settings, next_path: str | None) -> str:
    if not next_path:
        return management_url(settings, "/")
    if next_path.startswith(settings.normalized_management_base_path):
        return next_path
    if next_path.startswith("/") and not next_path.startswith("//"):
        return management_url(settings, "/")
    return management_url(settings, "/")


def signed_cookie(value: str | None, settings: Settings, *, max_age_seconds: int) -> dict[str, object] | None:
    if not value:
        return None
    try:
        payload = serializer(settings).loads(value, max_age=max_age_seconds)
    except BadSignature:
        return None
    return payload if isinstance(payload, dict) else None


def current_user(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, str] | None:
    payload = signed_cookie(
        request.cookies.get(settings.session_cookie_name),
        settings,
        max_age_seconds=settings.session_duration_minutes * 60,
    )
    if not payload or not isinstance(payload.get("sub"), str):
        return None
    return {
        "sub": str(payload.get("sub") or ""),
        "preferred_username": str(payload.get("preferred_username") or ""),
        "name": str(payload.get("name") or ""),
    }


def require_user(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, str]:
    user = current_user(request, settings)
    if user is not None:
        return user
    raise HTTPException(
        status_code=307,
        headers={
            "Location": management_url(
                settings,
                f"/auth/oauth/login?{urlencode({'next': str(request.url.path)})}",
            )
        },
    )


def require_api_user(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, str]:
    user = current_user(request, settings)
    if user is not None:
        return user
    raise HTTPException(status_code=401, detail="Not authenticated.")


def extension_for(filename: str, content_type: str) -> str:
    suffix = Path(filename).suffix.lower().lstrip(".")
    if suffix.isalnum() and 1 <= len(suffix) <= 12:
        return suffix
    guessed = mimetypes.guess_extension(content_type.split(";")[0].strip()) or ".bin"
    return guessed.lower().lstrip(".")[:12] or "bin"


def parse_lifetime(value: int, unit: str) -> timedelta:
    if unit == "minutes":
        return timedelta(minutes=max(1, min(value, 3650)))
    if unit == "hours":
        return timedelta(hours=max(1, min(value, 3650)))
    if unit == "days":
        return timedelta(days=max(1, min(value, 3650)))
    if unit == "years":
        return timedelta(days=365 * max(1, min(value, 10)))
    raise HTTPException(status_code=400, detail="Unsupported lifetime unit.")


def as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def serialize_file(settings: Settings, row: SharedFile) -> dict[str, object]:
    now = datetime.now(tz=UTC)
    expires_at = as_utc(row.expires_at)
    return {
        "id": row.id,
        "original_filename": row.original_filename,
        "content_type": row.content_type,
        "size_bytes": row.size_bytes,
        "sha256": row.sha256,
        "share_url": share_url(settings, row.public_name),
        "public_share_url": public_share_url(settings, row.public_name),
        "created_at": as_utc(row.created_at).isoformat(),
        "expires_at": expires_at.isoformat(),
        "revoked_at": as_utc(row.revoked_at).isoformat() if row.revoked_at else None,
        "is_active": row.revoked_at is None and expires_at > now,
        "is_image": row.thumbnail_data is not None,
        "thumbnail_url": management_url(settings, f"/api/files/{row.id}/thumbnail")
        if row.thumbnail_data is not None
        else None,
        "image_width": row.image_width,
        "image_height": row.image_height,
        "thumbnail_width": row.thumbnail_width,
        "thumbnail_height": row.thumbnail_height,
    }


@app.on_event("startup")
def startup() -> None:
    if getattr(app.state, "skip_startup_migrate", False):
        return
    migrate()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/{management_slug}")
@app.get("/{management_slug}/")
def index(
    management_slug: str,
    user: Annotated[dict[str, str], Depends(require_user)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HTMLResponse:
    require_prefix(management_slug, settings.normalized_management_base_path)
    return HTMLResponse(render_index(settings, user, page="upload"))


@app.get("/{management_slug}/manage")
def manage_page(
    management_slug: str,
    user: Annotated[dict[str, str], Depends(require_user)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HTMLResponse:
    require_prefix(management_slug, settings.normalized_management_base_path)
    return HTMLResponse(render_index(settings, user, page="manage"))


@app.get("/{management_slug}/auth/oauth/login")
def oauth_login(
    management_slug: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    next: str | None = None,
) -> RedirectResponse:
    require_prefix(management_slug, settings.normalized_management_base_path)
    state = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(48)
    next_path = safe_next(settings, next or request.headers.get("referer"))
    state_payload = {
        "state": state,
        "verifier": verifier,
        "next": next_path,
        "created_at": datetime.now(tz=UTC).isoformat(),
    }
    params = {
        "response_type": "code",
        "client_id": settings.oauth_client_id,
        "redirect_uri": settings.oauth_redirect_uri,
        "scope": settings.oauth_scope,
        "state": state,
        "code_challenge": pkce_challenge(verifier),
        "code_challenge_method": "S256",
    }
    response = RedirectResponse(f"{settings.normalized_auth_base_url}/oauth/authorize?{urlencode(params)}")
    response.set_cookie(
        settings.oauth_state_cookie_name,
        serializer(settings).dumps(state_payload),
        max_age=600,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path=settings.normalized_management_base_path,
    )
    return response


@app.get("/{management_slug}/auth/oauth/callback")
async def oauth_callback(
    management_slug: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    code: str | None = None,
    state: str | None = None,
) -> RedirectResponse:
    require_prefix(management_slug, settings.normalized_management_base_path)
    state_payload = signed_cookie(
        request.cookies.get(settings.oauth_state_cookie_name),
        settings,
        max_age_seconds=600,
    )
    if not code or not state or not state_payload or state_payload.get("state") != state:
        return RedirectResponse(management_url(settings, "/?oauth_error=oauth_state"))

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            token_response = await client.post(
                f"{settings.normalized_oauth_server_base_url}/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "client_id": settings.oauth_client_id,
                    "code": code,
                    "redirect_uri": settings.oauth_redirect_uri,
                    "code_verifier": state_payload["verifier"],
                },
            )
            token_response.raise_for_status()
            access_token = token_response.json()["access_token"]
            userinfo_response = await client.get(
                f"{settings.normalized_oauth_server_base_url}/oauth/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            userinfo_response.raise_for_status()
            userinfo = userinfo_response.json()
    except Exception:
        response = RedirectResponse(management_url(settings, "/?oauth_error=oauth_failed"))
        response.delete_cookie(settings.oauth_state_cookie_name, path=settings.normalized_management_base_path)
        return response

    response = RedirectResponse(str(state_payload.get("next") or management_url(settings, "/")))
    response.delete_cookie(settings.oauth_state_cookie_name, path=settings.normalized_management_base_path)
    response.set_cookie(
        settings.session_cookie_name,
        serializer(settings).dumps(
            {
                "sub": str(userinfo.get("sub") or ""),
                "preferred_username": str(userinfo.get("preferred_username") or ""),
                "name": str(userinfo.get("name") or ""),
            }
        ),
        max_age=settings.session_duration_minutes * 60,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path=settings.normalized_management_base_path,
    )
    return response


@app.post("/{management_slug}/auth/logout")
def logout(
    management_slug: str,
    settings: Annotated[Settings, Depends(get_settings)],
) -> RedirectResponse:
    require_prefix(management_slug, settings.normalized_management_base_path)
    response = RedirectResponse(management_url(settings, "/"), status_code=302)
    response.delete_cookie(settings.session_cookie_name, path=settings.normalized_management_base_path)
    return response


@app.get("/{management_slug}/api/files")
def list_files(
    management_slug: str,
    _: Annotated[dict[str, str], Depends(require_api_user)],
    settings: Annotated[Settings, Depends(get_settings)],
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, object]:
    require_prefix(management_slug, settings.normalized_management_base_path)
    rows = db.scalars(select(SharedFile).order_by(SharedFile.created_at.desc())).all()
    return {"files": [serialize_file(settings, row) for row in rows]}


@app.post("/{management_slug}/api/files")
async def upload_file(
    management_slug: str,
    user: Annotated[dict[str, str], Depends(require_api_user)],
    settings: Annotated[Settings, Depends(get_settings)],
    db: Annotated[Session, Depends(get_db)],
    file: UploadFile = File(...),
    lifetime_value: int = Form(24),
    lifetime_unit: str = Form("hours"),
    resize_image: bool = Form(False),
    max_image_dimension: int = Form(1600),
    strip_metadata: bool = Form(True),
) -> JSONResponse:
    require_prefix(management_slug, settings.normalized_management_base_path)
    original = await file.read()
    if len(original) == 0:
        raise HTTPException(status_code=400, detail="Upload is empty.")
    if len(original) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="Upload exceeds the configured size limit.")

    content_type = file.content_type or mimetypes.guess_type(file.filename or "")[0] or "application/octet-stream"
    original_extension = extension_for(file.filename or "upload.bin", content_type)
    max_dimension = max(64, min(max_image_dimension, settings.max_image_resize_dimension))
    processed = process_upload(
        original,
        content_type,
        original_extension,
        strip_metadata=strip_metadata,
        resize_image=resize_image,
        max_image_dimension=max_dimension,
        thumbnail_max_dimension=settings.thumbnail_max_dimension,
    )
    public_name = generate_public_name(db, processed.extension)
    now = datetime.now(tz=UTC)
    row = SharedFile(
        id=str(uuid.uuid4()),
        public_name=public_name,
        original_filename=file.filename or f"upload.{processed.extension}",
        stored_extension=processed.extension,
        content_type=processed.content_type,
        size_bytes=len(processed.data),
        sha256=hashlib.sha256(processed.data).hexdigest(),
        blob_data=processed.data,
        thumbnail_data=processed.thumbnail_data,
        thumbnail_content_type=processed.thumbnail_content_type,
        created_by_subject=user["sub"],
        created_by_username=user["preferred_username"] or user["name"] or user["sub"],
        created_at=now,
        expires_at=now + parse_lifetime(lifetime_value, lifetime_unit),
        image_width=processed.width,
        image_height=processed.height,
        thumbnail_width=processed.thumbnail_width,
        thumbnail_height=processed.thumbnail_height,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return JSONResponse(serialize_file(settings, row), status_code=201)


@app.get("/{management_slug}/api/files/{file_id}/thumbnail")
def file_thumbnail(
    management_slug: str,
    file_id: str,
    _: Annotated[dict[str, str], Depends(require_api_user)],
    settings: Annotated[Settings, Depends(get_settings)],
    db: Annotated[Session, Depends(get_db)],
) -> Response:
    require_prefix(management_slug, settings.normalized_management_base_path)
    row = db.get(SharedFile, file_id)
    if row is None or row.thumbnail_data is None:
        raise HTTPException(status_code=404)
    return Response(row.thumbnail_data, media_type=row.thumbnail_content_type or "image/jpeg")


@app.post("/{management_slug}/api/files/{file_id}/extend")
def extend_file(
    management_slug: str,
    file_id: str,
    _: Annotated[dict[str, str], Depends(require_api_user)],
    settings: Annotated[Settings, Depends(get_settings)],
    db: Annotated[Session, Depends(get_db)],
    lifetime_value: int = Form(24),
    lifetime_unit: str = Form("hours"),
) -> dict[str, object]:
    require_prefix(management_slug, settings.normalized_management_base_path)
    row = db.get(SharedFile, file_id)
    if row is None:
        raise HTTPException(status_code=404)
    row.expires_at = datetime.now(tz=UTC) + parse_lifetime(lifetime_value, lifetime_unit)
    row.revoked_at = None
    db.commit()
    db.refresh(row)
    return serialize_file(settings, row)


@app.post("/{management_slug}/api/files/{file_id}/revoke")
def revoke_file(
    management_slug: str,
    file_id: str,
    _: Annotated[dict[str, str], Depends(require_api_user)],
    settings: Annotated[Settings, Depends(get_settings)],
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, object]:
    require_prefix(management_slug, settings.normalized_management_base_path)
    row = db.get(SharedFile, file_id)
    if row is None:
        raise HTTPException(status_code=404)
    row.revoked_at = datetime.now(tz=UTC)
    db.commit()
    db.refresh(row)
    return serialize_file(settings, row)


@app.delete("/{management_slug}/api/files/{file_id}")
def delete_file(
    management_slug: str,
    file_id: str,
    _: Annotated[dict[str, str], Depends(require_api_user)],
    settings: Annotated[Settings, Depends(get_settings)],
    db: Annotated[Session, Depends(get_db)],
) -> Response:
    require_prefix(management_slug, settings.normalized_management_base_path)
    row = db.get(SharedFile, file_id)
    if row is None:
        raise HTTPException(status_code=404)
    db.delete(row)
    db.commit()
    return Response(status_code=204)


@app.get("/{share_slug}/{public_name:path}")
def shared_file(
    share_slug: str,
    public_name: str,
    settings: Annotated[Settings, Depends(get_settings)],
    db: Annotated[Session, Depends(get_db)],
) -> Response:
    require_prefix(share_slug, settings.normalized_share_base_path)
    row = db.scalar(select(SharedFile).where(SharedFile.public_name == public_name))
    if row is None:
        raise HTTPException(status_code=404)
    now = datetime.now(tz=UTC)
    if row.revoked_at is not None:
        raise HTTPException(status_code=410, detail="Shared link was revoked.")
    if as_utc(row.expires_at) <= now:
        raise HTTPException(status_code=410, detail="Shared link expired.")
    headers = {
        "Content-Disposition": f'inline; filename="{row.original_filename.replace(chr(34), "")}"',
        "X-Content-Type-Options": "nosniff",
    }
    return Response(row.blob_data, media_type=row.content_type, headers=headers)


def render_index(settings: Settings, user: dict[str, str], *, page: str) -> str:
    username = html.escape(user.get("preferred_username") or user.get("name") or "Signed in")
    management_base = html.escape(settings.normalized_management_base_path)
    upload_current = ' aria-current="page"' if page == "upload" else ""
    manage_current = ' aria-current="page"' if page == "manage" else ""
    upload_hidden = "" if page == "upload" else " hidden"
    manage_hidden = "" if page == "manage" else " hidden"
    html_doc = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>File Share</title>
  <style>
    :root { color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    * { box-sizing: border-box; }
    body { margin: 0; background: #f6f7f9; color: #171717; }
    button, input, select { font: inherit; }
    .shell { max-width: 1120px; margin: 0 auto; padding: 24px; }
    .topbar { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 16px; align-items: start; margin-bottom: 18px; }
    h1 { font-size: clamp(2rem, 7vw, 3rem); line-height: 1.02; margin: 0; letter-spacing: 0; }
    h2 { margin: 0 0 14px; font-size: 1.25rem; letter-spacing: 0; }
    h3 { margin: 0 0 10px; font-size: 1rem; letter-spacing: 0; }
    .muted { color: #5f6672; }
    .nav { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 14px; }
    .nav a { border: 1px solid #b7bfcc; border-radius: 6px; color: #1f2937; padding: 0.52rem 0.75rem; text-decoration: none; }
    .nav a[aria-current="page"] { background: #1f2937; border-color: #1f2937; color: #fff; }
    .panel { background: #fff; border: 1px solid #d9dee7; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
    .upload-card { max-width: 720px; }
    .form-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
    .field { display: grid; gap: 6px; min-width: 0; }
    .field.full, .check-row.full, .btn.full { grid-column: 1 / -1; }
    label, .field-label { font-size: 0.9rem; font-weight: 700; color: #303743; }
    input, select { width: 100%; min-width: 0; border: 1px solid #b7bfcc; border-radius: 6px; padding: 0.72rem 0.75rem; background: #fff; }
    input[type="file"] { position: absolute; inline-size: 1px; block-size: 1px; opacity: 0; pointer-events: none; }
    input[type="checkbox"] { width: 1.35rem; height: 1.35rem; padding: 0; flex: 0 0 auto; }
    .file-picker { display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 10px; align-items: center; min-height: 52px; border: 1px solid #b7bfcc; border-radius: 6px; padding: 8px; cursor: pointer; background: #fff; }
    .file-picker-action { display: inline-flex; min-height: 36px; align-items: center; border: 1px solid #1f2937; border-radius: 5px; padding: 0 0.65rem; white-space: nowrap; }
    .file-picker-name { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #5f6672; }
    .check-row { display: flex; align-items: center; gap: 10px; min-height: 44px; }
    .actions { display: flex; gap: 8px; flex-wrap: wrap; }
    .btn { display: inline-flex; justify-content: center; align-items: center; border: 1px solid #1f2937; background: #1f2937; color: #fff; border-radius: 6px; min-height: 44px; padding: 0.65rem 0.9rem; cursor: pointer; text-decoration: none; }
    .btn.secondary { background: #fff; color: #1f2937; }
    .btn.danger { background: #b42318; border-color: #b42318; color: #fff; }
    .btn:disabled { opacity: 0.55; cursor: progress; }
    .status { min-height: 1.5rem; margin: 10px 0 0; color: #344054; overflow-wrap: anywhere; }
    .result { display: none; margin-top: 16px; border-top: 1px solid #e4e8ef; padding-top: 16px; }
    .result.visible { display: block; }
    .share-link { display: block; margin-top: 8px; overflow-wrap: anywhere; color: #155eef; }
    .preview { width: min(100%, 280px); max-height: 240px; object-fit: contain; border-radius: 6px; background: #e6eaf0; }
    .group { margin-bottom: 26px; }
    .group-heading { display: flex; justify-content: space-between; gap: 10px; align-items: baseline; margin-bottom: 10px; }
    .tile-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 12px; }
    .tile { appearance: none; text-align: left; border: 1px solid #d9dee7; border-radius: 8px; padding: 0; background: #fff; overflow: hidden; cursor: pointer; min-width: 0; }
    .tile:hover, .tile:focus-visible { border-color: #155eef; outline: none; box-shadow: 0 0 0 2px rgba(21, 94, 239, 0.15); }
    .tile img, .tile-placeholder { display: block; width: 100%; aspect-ratio: 1 / 1; object-fit: cover; background: #e6eaf0; }
    .tile-placeholder { display: grid; place-items: center; color: #667085; font-weight: 700; }
    .tile-body { padding: 10px; }
    .tile-title { display: block; font-weight: 700; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .tile-meta { display: block; color: #5f6672; font-size: 0.82rem; margin-top: 3px; }
    .empty { color: #667085; border: 1px dashed #c5ccd8; border-radius: 8px; padding: 14px; background: #fff; }
    .modal-backdrop { position: fixed; inset: 0; display: none; align-items: center; justify-content: center; background: rgba(15, 23, 42, 0.58); padding: 18px; z-index: 20; }
    .modal-backdrop.open { display: flex; }
    .modal { width: min(920px, 100%); max-height: min(90vh, 900px); overflow: auto; background: #fff; border-radius: 8px; padding: 18px; box-shadow: 0 20px 60px rgba(15, 23, 42, 0.35); }
    .modal-head { display: flex; align-items: start; justify-content: space-between; gap: 12px; margin-bottom: 14px; }
    .modal-grid { display: grid; grid-template-columns: minmax(220px, 360px) minmax(0, 1fr); gap: 18px; align-items: start; }
    .modal-preview { width: 100%; max-height: 520px; object-fit: contain; border-radius: 6px; background: #e6eaf0; }
    .details { display: grid; gap: 8px; margin: 12px 0; }
    .detail-row { display: grid; grid-template-columns: 110px minmax(0, 1fr); gap: 8px; font-size: 0.92rem; }
    .detail-row dt { color: #5f6672; }
    .detail-row dd { margin: 0; overflow-wrap: anywhere; }
    .extend-form { display: grid; grid-template-columns: minmax(80px, 120px) minmax(110px, 1fr) auto; gap: 8px; align-items: end; margin: 12px 0; }
    @media (max-width: 820px) {
      .shell { padding: 20px 16px; }
      .topbar { grid-template-columns: 1fr; }
      .form-grid, .modal-grid, .extend-form { grid-template-columns: 1fr; }
      .tile-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .modal { padding: 14px; }
      .btn.full, #upload-button { width: 100%; }
    }
  </style>
</head>
<body>
  <main class="shell">
    <header class="topbar">
      <div>
        <h1>File Share</h1>
        <div class="muted">Signed in as __USERNAME__</div>
        <nav class="nav" aria-label="File share navigation">
          <a href="__BASE_HTML__/"__UPLOAD_CURRENT__>Upload</a>
          <a href="__BASE_HTML__/manage"__MANAGE_CURRENT__>Manage</a>
        </nav>
      </div>
      <form method="post" action="__BASE_HTML__/auth/logout">
        <button class="btn secondary" type="submit">Sign out</button>
      </form>
    </header>

    <section id="upload-page" class="panel upload-card"__UPLOAD_HIDDEN__>
      <h2>Upload</h2>
      <form id="upload-form" class="form-grid">
        <div class="field full">
          <label for="file">File</label>
          <label class="file-picker" for="file">
            <span class="file-picker-action">Choose file</span>
            <span id="file-name" class="file-picker-name">No file selected</span>
          </label>
          <input id="file" name="file" type="file" required />
        </div>
        <div class="field">
          <label for="lifetime_value">Lifetime</label>
          <input id="lifetime_value" name="lifetime_value" type="number" min="1" max="3650" value="__DEFAULT_LIFETIME__" />
        </div>
        <div class="field">
          <label for="lifetime_unit">Unit</label>
          <select id="lifetime_unit" name="lifetime_unit">
            <option value="hours" selected>Hours</option>
            <option value="minutes">Minutes</option>
            <option value="days">Days</option>
            <option value="years">Years</option>
          </select>
        </div>
        <label class="check-row full">
          <input id="strip_metadata" name="strip_metadata" type="checkbox" checked />
          <span>Strip image metadata</span>
        </label>
        <label class="check-row full">
          <input id="resize_image" name="resize_image" type="checkbox" />
          <span>Resize image</span>
        </label>
        <div class="field full">
          <label for="max_image_dimension">Max image side</label>
          <input id="max_image_dimension" name="max_image_dimension" type="number" min="64" max="__MAX_IMAGE_DIMENSION__" value="1600" />
        </div>
        <button id="upload-button" class="btn full" type="submit">Upload</button>
      </form>
      <div id="upload-status" class="status"></div>
      <div id="upload-result" class="result" aria-live="polite"></div>
    </section>

    <section id="manage-page"__MANAGE_HIDDEN__>
      <section class="group">
        <div class="group-heading">
          <h2>Active expiring soon</h2>
          <span class="muted">Less than a month</span>
        </div>
        <div id="soon-grid" class="tile-grid"></div>
      </section>
      <section class="group">
        <div class="group-heading">
          <h2>Active</h2>
          <span class="muted">Live links</span>
        </div>
        <div id="active-grid" class="tile-grid"></div>
      </section>
      <section class="group">
        <div class="group-heading">
          <h2>Hidden</h2>
          <span class="muted">Expired or revoked links</span>
        </div>
        <div id="hidden-grid" class="tile-grid"></div>
      </section>
      <div id="manage-status" class="status"></div>
    </section>
  </main>

  <div id="file-modal" class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="modal-title">
    <section class="modal">
      <div class="modal-head">
        <h2 id="modal-title"></h2>
        <button id="modal-close" class="btn secondary" type="button">Close</button>
      </div>
      <div id="modal-body"></div>
    </section>
  </div>

  <script>
    const base = __BASE_JSON__;
    const page = __PAGE_JSON__;
    let files = [];
    let selectedFile = null;
    const uploadPage = document.querySelector("#upload-page");
    const managePage = document.querySelector("#manage-page");
    const statusEl = document.querySelector(page === "upload" ? "#upload-status" : "#manage-status");
    const uploadButton = document.querySelector("#upload-button");
    const uploadResult = document.querySelector("#upload-result");
    const modal = document.querySelector("#file-modal");
    const modalTitle = document.querySelector("#modal-title");
    const modalBody = document.querySelector("#modal-body");

    uploadPage.hidden = page !== "upload";
    managePage.hidden = page !== "manage";

    function escapeHtml(value) {
      return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
    }

    function fmtBytes(bytes) {
      if (bytes < 1024) return `${bytes} B`;
      if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
      return `${(bytes / 1048576).toFixed(1)} MB`;
    }

    function fmtDate(value) {
      return new Date(value).toLocaleString();
    }

    function status(message) {
      if (statusEl) statusEl.textContent = message || "";
    }

    async function copyText(value) {
      if (navigator.clipboard) {
        await navigator.clipboard.writeText(value);
        return;
      }
      const input = document.createElement("textarea");
      input.value = value;
      document.body.appendChild(input);
      input.select();
      document.execCommand("copy");
      input.remove();
    }

    async function api(path, options = {}) {
      const response = await fetch(`${base}/api${path}`, { credentials: "same-origin", ...options });
      if (response.status === 401) {
        window.location.assign(`${base}/auth/oauth/login`);
        throw new Error("Not authenticated");
      }
      if (!response.ok) {
        const detail = await response.json().catch(() => ({ detail: "Request failed" }));
        throw new Error(detail.detail || "Request failed");
      }
      if (response.status === 204) return null;
      return response.json();
    }

    function tileMarkup(file) {
      const thumb = file.thumbnail_url
        ? `<img src="${escapeHtml(file.thumbnail_url)}" alt="">`
        : '<span class="tile-placeholder">File</span>';
      return `
        <button class="tile" type="button" data-open="${escapeHtml(file.id)}">
          ${thumb}
          <span class="tile-body">
            <span class="tile-title">${escapeHtml(file.original_filename)}</span>
            <span class="tile-meta">${escapeHtml(fmtDate(file.expires_at))}</span>
          </span>
        </button>
      `;
    }

    function renderGroup(id, groupFiles) {
      const grid = document.querySelector(`#${id}`);
      if (!grid) return;
      if (groupFiles.length === 0) {
        grid.innerHTML = '<div class="empty">No files in this group.</div>';
        return;
      }
      grid.innerHTML = groupFiles.map(tileMarkup).join("");
    }

    function renderManagement() {
      const now = Date.now();
      const soon = now + 30 * 24 * 60 * 60 * 1000;
      const activeSoon = files.filter((file) => file.is_active && new Date(file.expires_at).getTime() < soon);
      const active = files.filter((file) => file.is_active && new Date(file.expires_at).getTime() >= soon);
      const hidden = files.filter((file) => !file.is_active);
      renderGroup("soon-grid", activeSoon);
      renderGroup("active-grid", active);
      renderGroup("hidden-grid", hidden);
    }

    async function loadFiles() {
      const payload = await api("/files");
      files = Array.isArray(payload.files) ? payload.files : [];
      renderManagement();
    }

    function renderUploadResult(file) {
      if (!uploadResult || !file) return;
      const thumb = file.thumbnail_url
        ? `<img class="preview" src="${escapeHtml(file.thumbnail_url)}" alt="">`
        : "";
      uploadResult.classList.add("visible");
      uploadResult.innerHTML = `
        <h3>Upload ready</h3>
        ${thumb}
        <a class="share-link" href="${escapeHtml(file.share_url)}" target="_blank" rel="noreferrer">${escapeHtml(file.public_share_url)}</a>
        <div class="actions" style="margin-top: 12px;">
          <button class="btn secondary" type="button" data-result-copy="${escapeHtml(file.public_share_url)}">Copy link</button>
          <a class="btn secondary" href="${escapeHtml(file.share_url)}" target="_blank" rel="noreferrer">Open</a>
          <a class="btn" href="${base}/manage">Manage files</a>
        </div>
      `;
    }

    function closeModal() {
      modal.classList.remove("open");
      selectedFile = null;
    }

    function showModal(file) {
      selectedFile = file;
      modalTitle.textContent = file.original_filename;
      const preview = file.thumbnail_url
        ? `<img class="modal-preview" src="${escapeHtml(file.thumbnail_url)}" alt="">`
        : '<div class="modal-preview tile-placeholder">File</div>';
      const dimensions = file.image_width && file.image_height
        ? `${file.image_width} x ${file.image_height}`
        : "n/a";
      modalBody.innerHTML = `
        <div class="modal-grid">
          <div>${preview}</div>
          <div>
            <a class="share-link" href="${escapeHtml(file.share_url)}" target="_blank" rel="noreferrer">${escapeHtml(file.public_share_url)}</a>
            <dl class="details">
              <div class="detail-row"><dt>Status</dt><dd>${file.is_active ? "Active" : "Hidden"}</dd></div>
              <div class="detail-row"><dt>Type</dt><dd>${escapeHtml(file.content_type)}</dd></div>
              <div class="detail-row"><dt>Size</dt><dd>${escapeHtml(fmtBytes(file.size_bytes))}</dd></div>
              <div class="detail-row"><dt>Created</dt><dd>${escapeHtml(fmtDate(file.created_at))}</dd></div>
              <div class="detail-row"><dt>Expires</dt><dd>${escapeHtml(fmtDate(file.expires_at))}</dd></div>
              <div class="detail-row"><dt>Dimensions</dt><dd>${escapeHtml(dimensions)}</dd></div>
              <div class="detail-row"><dt>SHA-256</dt><dd>${escapeHtml(file.sha256)}</dd></div>
            </dl>
            <form id="extend-form" class="extend-form">
              <div class="field">
                <label for="extend-value">Extend by</label>
                <input id="extend-value" name="lifetime_value" type="number" min="1" max="3650" value="24">
              </div>
              <div class="field">
                <label for="extend-unit">Unit</label>
                <select id="extend-unit" name="lifetime_unit">
                  <option value="hours" selected>Hours</option>
                  <option value="minutes">Minutes</option>
                  <option value="days">Days</option>
                  <option value="years">Years</option>
                </select>
              </div>
              <button class="btn secondary" type="submit">Extend</button>
            </form>
            <div class="actions">
              <button class="btn secondary" type="button" data-modal-copy>Copy link</button>
              <a class="btn secondary" href="${escapeHtml(file.share_url)}" target="_blank" rel="noreferrer">Open</a>
              <button class="btn secondary" type="button" data-modal-revoke>Revoke</button>
              <button class="btn danger" type="button" data-modal-delete>Delete</button>
            </div>
          </div>
        </div>
      `;
      modal.classList.add("open");
    }

    document.querySelector("#file")?.addEventListener("change", (event) => {
      const selected = event.target.files && event.target.files[0] ? event.target.files[0].name : "No file selected";
      document.querySelector("#file-name").textContent = selected;
    });

    document.querySelector("#upload-form")?.addEventListener("submit", async (event) => {
      event.preventDefault();
      uploadButton.disabled = true;
      status("Uploading...");
      try {
        const data = new FormData(event.currentTarget);
        if (!data.has("strip_metadata")) data.set("strip_metadata", "false");
        if (!data.has("resize_image")) data.set("resize_image", "false");
        const uploaded = await api("/files", { method: "POST", body: data });
        event.currentTarget.reset();
        document.querySelector("#strip_metadata").checked = true;
        document.querySelector("#file-name").textContent = "No file selected";
        renderUploadResult(uploaded);
        status(`Upload ready: ${uploaded.public_share_url}`);
      } catch (error) {
        status(error.message);
      } finally {
        uploadButton.disabled = false;
      }
    });

    uploadResult?.addEventListener("click", async (event) => {
      const target = event.target;
      if (!(target instanceof HTMLButtonElement) || !target.dataset.resultCopy) return;
      await copyText(target.dataset.resultCopy);
      status("Share URL copied.");
    });

    managePage?.addEventListener("click", async (event) => {
      const target = event.target;
      const tile = target instanceof Element ? target.closest("[data-open]") : null;
      if (!tile) return;
      const file = files.find((candidate) => candidate.id === tile.dataset.open);
      if (file) showModal(file);
    });

    modal?.addEventListener("click", async (event) => {
      if (event.target === modal || event.target === document.querySelector("#modal-close")) {
        closeModal();
        return;
      }
      if (!selectedFile) return;
      const target = event.target;
      try {
        if (target instanceof HTMLButtonElement && target.dataset.modalCopy !== undefined) {
          await copyText(selectedFile.public_share_url);
          status("Share URL copied.");
          return;
        }
        if (target instanceof HTMLButtonElement && target.dataset.modalRevoke !== undefined) {
          await api(`/files/${selectedFile.id}/revoke`, { method: "POST" });
          status("Share link revoked.");
          closeModal();
          await loadFiles();
          return;
        }
        if (target instanceof HTMLButtonElement && target.dataset.modalDelete !== undefined) {
          if (!window.confirm("Delete this file permanently?")) return;
          await api(`/files/${selectedFile.id}`, { method: "DELETE" });
          status("File deleted.");
          closeModal();
          await loadFiles();
        }
      } catch (error) {
        status(error.message);
      }
    });

    modal?.addEventListener("submit", async (event) => {
      if (!(event.target instanceof HTMLFormElement) || event.target.id !== "extend-form" || !selectedFile) return;
      event.preventDefault();
      try {
        await api(`/files/${selectedFile.id}/extend`, { method: "POST", body: new FormData(event.target) });
        status("Share link extended.");
        closeModal();
        await loadFiles();
      } catch (error) {
        status(error.message);
      }
    });

    const params = new URLSearchParams(window.location.search);
    if (params.has("oauth_error")) {
      status("Central sign-in could not be completed. Please try again.");
      history.replaceState(history.state, "", window.location.pathname);
    }
    if (page === "manage") {
      loadFiles().catch((error) => status(error.message));
    }
  </script>
</body>
</html>"""
    return (
        html_doc
        .replace("__USERNAME__", username)
        .replace("__BASE_HTML__", management_base)
        .replace("__BASE_JSON__", json.dumps(settings.normalized_management_base_path))
        .replace("__PAGE_JSON__", json.dumps(page))
        .replace("__UPLOAD_CURRENT__", upload_current)
        .replace("__MANAGE_CURRENT__", manage_current)
        .replace("__UPLOAD_HIDDEN__", upload_hidden)
        .replace("__MANAGE_HIDDEN__", manage_hidden)
        .replace("__DEFAULT_LIFETIME__", str(settings.default_link_lifetime_hours))
        .replace("__MAX_IMAGE_DIMENSION__", str(settings.max_image_resize_dimension))
    )
