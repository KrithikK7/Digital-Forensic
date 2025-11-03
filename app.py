import os
import json
from urllib.parse import urlparse
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware

from dotenv import load_dotenv

# Load env before importing modules that read env vars
load_dotenv()

from google_oauth import oauth
from db import Base, engine, SessionLocal
from gmail_sync import sync_all_mail
from models import UserToken
from sqlalchemy import select

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=os.getenv("GOOGLE_CLIENT_SECRET", "secret-session"))

# Ensure tables exist (safe if DB already created)
Base.metadata.create_all(bind=engine)

_ALLOWED_REDIRECT_HOSTS = {
    host.strip()
    for host in os.getenv("ALLOWED_REDIRECT_HOSTS", "localhost,127.0.0.1").split(",")
    if host.strip()
}


def _default_streamlit_url() -> str:
    base = os.getenv("STREAMLIT_URL", "http://127.0.0.1:8501/")
    base = base.rstrip("/")
    separator = "&" if "?" in base else "?"
    return f"{base}{separator}oauth=1"


def _is_safe_redirect(url: str | None) -> bool:
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"}:
        return False
    host = parsed.hostname or ""
    if _ALLOWED_REDIRECT_HOSTS and host not in _ALLOWED_REDIRECT_HOSTS:
        return False
    return True

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    user = request.session.get("user")
    if user:
        return HTMLResponse(f"""
        <h2>Gmail Forensics – Signed in</h2>
        <p>Email: {user.get("email")}</p>
        <form action="/sync" method="post"><button type="submit">Sync All Mail (incl. Spam/Trash)</button></form>
        <p><a href="/logout">Logout</a></p>
        """)
    return HTMLResponse("""
    <h2>Gmail Forensics</h2>
    <a href="/login">Sign in with Google</a>
    """)

@app.get("/login")
async def login(request: Request):
    # Build redirect URI dynamically to match the host the user is using
    redirect_uri = str(request.url_for("auth_callback"))
    next_url = request.query_params.get("next")
    if _is_safe_redirect(next_url):
        request.session["next_url"] = next_url
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth/callback")
async def auth_callback(request: Request):
    token = await oauth.google.authorize_access_token(request)
    userinfo = token.get("userinfo")
    if not userinfo:
        # fetch explicit userinfo if not present
        resp = await oauth.google.parse_id_token(request, token)
        userinfo = resp or {}
    email = userinfo.get("email")
    request.session["user"] = {
        "email": email,
        "token": token,
    }

    if email:
        db = SessionLocal()
        try:
            token_json = json.dumps(token)
            row = db.execute(select(UserToken).where(UserToken.email == email)).scalar_one_or_none()
            if row is None:
                row = UserToken(email=email, token_json=token_json)
                db.add(row)
            else:
                row.token_json = token_json
            db.commit()
        finally:
            db.close()
    next_url = request.session.pop("next_url", None)
    if not _is_safe_redirect(next_url):
        next_url = _default_streamlit_url()
    return RedirectResponse(url=next_url)

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/")

@app.post("/sync")
async def sync_all(request: Request):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/")

    token = user.get("token")
    page_limit = int(os.getenv("PAGE_LIMIT", "0") or "0")
    db = SessionLocal()
    try:
        processed, atts = sync_all_mail(db, token, page_limit=page_limit)
        return JSONResponse({"status": "ok", "messages_processed": processed, "attachments_downloaded": atts})
    except Exception as e:
        return JSONResponse({"status": "error", "detail": str(e)}, status_code=500)
    finally:
        db.close()
