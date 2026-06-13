from __future__ import annotations

import base64
import hashlib
import html
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
    bounded_value = max(1, min(value, 3650))
    if unit == "minutes":
        return timedelta(minutes=bounded_value)
    if unit == "hours":
        return timedelta(hours=bounded_value)
    if unit == "days":
        return timedelta(days=bounded_value)
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
    return HTMLResponse(render_index(settings, user))


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
    token = secrets.token_urlsafe(18)
    public_name = f"{token}.{processed.extension}"
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


def render_index(settings: Settings, user: dict[str, str]) -> str:
    username = html.escape(user.get("preferred_username") or user.get("name") or "Signed in")
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>File Share</title>
  <style>
    :root {{ color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
    body {{ margin: 0; background: #f6f7f9; color: #171717; }}
    button, input, select {{ font: inherit; }}
    .shell {{ max-width: 1120px; margin: 0 auto; padding: 24px; }}
    .topbar {{ display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 18px; }}
    h1 {{ font-size: 1.5rem; margin: 0; }}
    .muted {{ color: #5f6672; }}
    .panel {{ background: #fff; border: 1px solid #d9dee7; border-radius: 8px; padding: 16px; margin-bottom: 16px; }}
    .form-grid {{ display: grid; grid-template-columns: minmax(220px, 1fr) repeat(4, minmax(120px, 180px)); gap: 12px; align-items: end; }}
    .field {{ display: grid; gap: 6px; }}
    label {{ font-size: 0.82rem; font-weight: 650; color: #303743; }}
    input, select {{ border: 1px solid #b7bfcc; border-radius: 6px; padding: 0.56rem 0.65rem; background: #fff; }}
    input[type="checkbox"] {{ width: 1rem; height: 1rem; padding: 0; }}
    .check-row {{ display: flex; align-items: center; gap: 8px; min-height: 40px; }}
    .actions {{ display: flex; gap: 8px; flex-wrap: wrap; }}
    .btn {{ border: 1px solid #1f2937; background: #1f2937; color: #fff; border-radius: 6px; padding: 0.58rem 0.8rem; cursor: pointer; }}
    .btn.secondary {{ background: #fff; color: #1f2937; }}
    .btn.danger {{ background: #b42318; border-color: #b42318; }}
    .btn:disabled {{ opacity: 0.55; cursor: progress; }}
    .status {{ min-height: 1.5rem; margin: 8px 0; color: #344054; }}
    .files {{ display: grid; gap: 10px; }}
    .file-row {{ display: grid; grid-template-columns: 96px minmax(0, 1fr) auto; gap: 14px; align-items: center; background: #fff; border: 1px solid #d9dee7; border-radius: 8px; padding: 12px; }}
    .thumb {{ width: 96px; height: 72px; object-fit: cover; background: #e6eaf0; border-radius: 6px; }}
    .thumb-placeholder {{ display: grid; place-items: center; color: #667085; font-size: 0.8rem; }}
    .file-title {{ font-weight: 700; overflow-wrap: anywhere; }}
    .file-meta {{ display: flex; flex-wrap: wrap; gap: 10px; font-size: 0.84rem; color: #5f6672; margin-top: 4px; }}
    .share-link {{ display: block; margin-top: 8px; overflow-wrap: anywhere; color: #155eef; }}
    .expired {{ color: #b42318; font-weight: 700; }}
    @media (max-width: 820px) {{
      .form-grid, .file-row {{ grid-template-columns: 1fr; }}
      .topbar {{ align-items: flex-start; flex-direction: column; }}
    }}
  </style>
</head>
<body>
  <main class="shell">
    <header class="topbar">
      <div>
        <h1>File Share</h1>
        <div class="muted">Signed in as {username}</div>
      </div>
      <form method="post" action="{settings.normalized_management_base_path}/auth/logout">
        <button class="btn secondary" type="submit">Sign out</button>
      </form>
    </header>

    <section class="panel">
      <form id="upload-form" class="form-grid">
        <div class="field">
          <label for="file">File</label>
          <input id="file" name="file" type="file" required />
        </div>
        <div class="field">
          <label for="lifetime_value">Lifetime</label>
          <input id="lifetime_value" name="lifetime_value" type="number" min="1" max="3650" value="{settings.default_link_lifetime_hours}" />
        </div>
        <div class="field">
          <label for="lifetime_unit">Unit</label>
          <select id="lifetime_unit" name="lifetime_unit">
            <option value="hours" selected>Hours</option>
            <option value="minutes">Minutes</option>
            <option value="days">Days</option>
          </select>
        </div>
        <label class="check-row">
          <input id="strip_metadata" name="strip_metadata" type="checkbox" checked />
          <span>Strip image metadata</span>
        </label>
        <label class="check-row">
          <input id="resize_image" name="resize_image" type="checkbox" />
          <span>Resize image</span>
        </label>
        <div class="field">
          <label for="max_image_dimension">Max image side</label>
          <input id="max_image_dimension" name="max_image_dimension" type="number" min="64" max="{settings.max_image_resize_dimension}" value="1600" />
        </div>
        <button id="upload-button" class="btn" type="submit">Upload</button>
      </form>
      <div id="status" class="status"></div>
    </section>

    <section class="files" id="files"></section>
  </main>

  <script>
    const base = {settings.normalized_management_base_path!r};
    const filesEl = document.querySelector("#files");
    const statusEl = document.querySelector("#status");
    const uploadButton = document.querySelector("#upload-button");

    function fmtBytes(bytes) {{
      if (bytes < 1024) return `${{bytes}} B`;
      if (bytes < 1048576) return `${{(bytes / 1024).toFixed(1)}} KB`;
      return `${{(bytes / 1048576).toFixed(1)}} MB`;
    }}

    function fmtDate(value) {{
      return new Date(value).toLocaleString();
    }}

    function status(message) {{
      statusEl.textContent = message || "";
    }}

    async function api(path, options = {{}}) {{
      const response = await fetch(`${{base}}/api${{path}}`, {{ credentials: "same-origin", ...options }});
      if (response.status === 401) {{
        window.location.assign(`${{base}}/auth/oauth/login`);
        throw new Error("Not authenticated");
      }}
      if (!response.ok) {{
        const detail = await response.json().catch(() => ({{ detail: "Request failed" }}));
        throw new Error(detail.detail || "Request failed");
      }}
      if (response.status === 204) return null;
      return response.json();
    }}

    function renderFiles(files) {{
      if (!files.length) {{
        filesEl.innerHTML = '<div class="panel muted">No shared files yet.</div>';
        return;
      }}
      filesEl.innerHTML = "";
      for (const file of files) {{
        const row = document.createElement("article");
        row.className = "file-row";
        const thumb = file.thumbnail_url
          ? `<img class="thumb" src="${{file.thumbnail_url}}" alt="">`
          : '<div class="thumb thumb-placeholder">File</div>';
        const activeLabel = file.is_active ? "active" : '<span class="expired">inactive</span>';
        row.innerHTML = `
          ${{thumb}}
          <div>
            <div class="file-title">${{file.original_filename}}</div>
            <div class="file-meta">
              <span>${{fmtBytes(file.size_bytes)}}</span>
              <span>${{file.content_type}}</span>
              <span>expires ${{fmtDate(file.expires_at)}}</span>
              <span>${{activeLabel}}</span>
            </div>
            <a class="share-link" href="${{file.share_url}}" target="_blank" rel="noreferrer">${{file.public_share_url}}</a>
          </div>
          <div class="actions">
            <button class="btn secondary" data-copy="${{file.public_share_url}}">Copy</button>
            <button class="btn secondary" data-extend="${{file.id}}">Extend 24h</button>
            <button class="btn danger" data-revoke="${{file.id}}">Revoke</button>
            <button class="btn secondary" data-delete="${{file.id}}">Delete</button>
          </div>
        `;
        filesEl.appendChild(row);
      }}
    }}

    async function loadFiles() {{
      const payload = await api("/files");
      renderFiles(payload.files);
    }}

    document.querySelector("#upload-form").addEventListener("submit", async (event) => {{
      event.preventDefault();
      uploadButton.disabled = true;
      status("Uploading...");
      try {{
        const data = new FormData(event.currentTarget);
        if (!data.has("strip_metadata")) data.set("strip_metadata", "false");
        if (!data.has("resize_image")) data.set("resize_image", "false");
        await api("/files", {{ method: "POST", body: data }});
        event.currentTarget.reset();
        document.querySelector("#strip_metadata")?.setAttribute("checked", "checked");
        status("Upload ready.");
        await loadFiles();
      }} catch (error) {{
        status(error.message);
      }} finally {{
        uploadButton.disabled = false;
      }}
    }});

    filesEl.addEventListener("click", async (event) => {{
      const target = event.target;
      if (!(target instanceof HTMLButtonElement)) return;
      try {{
        if (target.dataset.copy) {{
          await navigator.clipboard.writeText(target.dataset.copy);
          status("Share URL copied.");
          return;
        }}
        if (target.dataset.extend) {{
          const data = new FormData();
          data.set("lifetime_value", "24");
          data.set("lifetime_unit", "hours");
          await api(`/files/${{target.dataset.extend}}/extend`, {{ method: "POST", body: data }});
          status("Share link extended.");
        }}
        if (target.dataset.revoke) {{
          await api(`/files/${{target.dataset.revoke}}/revoke`, {{ method: "POST" }});
          status("Share link revoked.");
        }}
        if (target.dataset.delete) {{
          await api(`/files/${{target.dataset.delete}}`, {{ method: "DELETE" }});
          status("File deleted.");
        }}
        await loadFiles();
      }} catch (error) {{
        status(error.message);
      }}
    }});

    const params = new URLSearchParams(window.location.search);
    if (params.has("oauth_error")) {{
      status("Central sign-in could not be completed. Please try again.");
      history.replaceState(history.state, "", window.location.pathname);
    }}
    loadFiles().catch((error) => status(error.message));
  </script>
</body>
</html>"""
