Gmail Forensics – Streamlit Setup and Run

This project lets you authenticate with Google, sync Gmail messages (including Spam/Trash) into a Postgres database for forensic analysis, and explore the data via a Streamlit UI. Streamlit now starts the FastAPI OAuth helper for you and exposes sign-in, sync, and database maintenance buttons directly in the sidebar.

Requirements
- Python 3.10+
- PostgreSQL 12+
- A Google Cloud project with an OAuth 2.0 Web client

1) Create and fill your .env
Create `.env` in the project root with at least:

```
# App database URL (SQLAlchemy)
APP_DB_URL=postgresql+psycopg2://gmail_app:gmail_app@localhost:5432/gmail_forensics

# Superuser connection URL to create DB/user (for create_db.py)
POSTGRES_SUPER_URL=postgresql://postgres:postgres@localhost:5432/postgres

# App DB identifiers (create_db.py uses these)
APP_DB_NAME=gmail_forensics
APP_DB_USER=gmail_app
APP_DB_PASS=gmail_app

# Google OAuth Web client (create in Google Cloud Console)
GOOGLE_CLIENT_ID=your_client_id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_client_secret

# Optional: limit sync page count during testing (0 = no limit)
PAGE_LIMIT=2

# Optional: override the Streamlit URL used for post-login redirects
STREAMLIT_URL=http://127.0.0.1:8501/
# Optional: comma-separated list of hosts allowed for OAuth redirect safety checks
ALLOWED_REDIRECT_HOSTS=localhost,127.0.0.1
```

Notes
- `APP_DB_URL` must point to the DB you’ll use at runtime. The URL format is `postgresql+psycopg2://user:pass@host:port/dbname`.
- `POSTGRES_SUPER_URL` should connect to the default maintenance DB (often `postgres`) with a role that can create roles/databases.
- The OAuth client must be of type “Web application”. Add an authorized redirect URI that matches the API URL (default `http://localhost:8000/auth/callback`).
- If Streamlit is running on a non-default host/port, set `STREAMLIT_URL` so the OAuth callback returns you to the correct page after signing in.
- Use `ALLOWED_REDIRECT_HOSTS` if you need to permit additional domains for the post-login redirect safety check.

2) Install dependencies
```
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

3) Prepare PostgreSQL
- Make sure Postgres is running and the credentials in `.env` are correct.
- Initialize database and tables:
```
python create_db.py
```
This creates the role/database if missing and creates all SQLAlchemy tables.

4) Run the Streamlit app (sign‑in + sync + explore)
The Streamlit sidebar now includes everything you need: start the OAuth helper, launch Google sign-in, trigger sync, and clear the database.

```
streamlit run streamlit_app.py
```

Then open the URL Streamlit prints (typically `http://localhost:8501`).

Sidebar workflow:
1. Click **Start FastAPI server** (spawns the OAuth helper on `http://127.0.0.1:8000`).
2. Click **Sign in with Google** to finish the familiar `/login → /auth/callback` web flow. After login you are sent straight back to Streamlit, and tokens are stored in Postgres for reuse.
3. Once signed in, use **Sync All Mail** to ingest Gmail metadata and attachments without leaving Streamlit.
4. Use **Clear database** to drop and recreate all tables (including saved tokens) when you need a clean slate.

Common Operations
- Re-run sync after more emails arrive: Click **Sync All Mail** in the Streamlit sidebar; existing messages are skipped.
- Narrow sync during development: raise/lower `PAGE_LIMIT` in `.env`.

Data Model (high level)
- `messages`: one row per Gmail message, including Gmail IDs, timestamps, snippet, raw RFC 5322, and basic top-level metadata (subject, from, date).
- `labels`, `message_labels`: Gmail label catalog and message-label many-to-many links.
- `headers`: all message headers captured from the “full” payload.
- `addresses`, `message_addresses`: normalized addresses for from/to/cc/bcc/reply-to.
- `parts`, `part_headers`: flattened MIME parts with optional inline bytes and per-part headers.
- `attachments`: attachment metadata and stored bytes (when available) with SHA-256.

Security and Scope
- The app requests `https://www.googleapis.com/auth/gmail.readonly` to read messages and attachments.
- Session data stores the OAuth token in a server-side cookie-backed session. Set a strong session secret by using a strong `GOOGLE_CLIENT_SECRET` or add a separate `SESSION_SECRET` if you extend the code.

Useful Commands
- Initialize DB: `python create_db.py`
- Streamlit UI (starts everything): `streamlit run streamlit_app.py`
- Run just the API (optional): `uvicorn app:app --reload --port 8000`

AI (RAG with Ollama)
- Models (local via Ollama):
  - Embeddings: `mxbai-embed-large:latest` (dimension 1024)
  - Chat LLM: `llama3.2:latest`
- Env vars (optional overrides):
  - `OLLAMA_HOST=http://localhost:11434`
  - `EMBED_MODEL=mxbai-embed-large:latest`
  - `CHAT_MODEL=llama3.2:latest`
- Database extensions and tables:
  - `CREATE EXTENSION IF NOT EXISTS vector;` (run by `create_db.py`)
  - New tables: `message_index`, `message_nlp`, `sender_profiles`, `audit_logs`
- In the Streamlit UI, open the new AI tab:
  - **AI Chatbot** tab: build/refresh the index (only missing messages), reindex ALL messages if models or metadata change, and chat with the assistant (responses include gmail_id citations) with optional filters per query
  - **Sender Summary** tab: view/refine sender profiles (tone/relationship/threat summary generated via local LLM) and inspect the stored JSON profile for each sender

FAQ
- Q: Can I use a different database? A: Code is wired for Postgres. You could point `APP_DB_URL` to another SQLAlchemy-supported DB, but `create_db.py` assumes Postgres for role/database creation.
- Q: Where are attachments stored? A: In the `attachments` table (column `data`) with optional SHA-256 in `sha256`.
- Q: How do I reset data? A: Drop and recreate the database from Postgres, or write a small script to `Base.metadata.drop_all()` then `create_all()`.
- Q: I already created a Web OAuth client. Can I reuse it? A: Yes — the workflow now relies on the Web client (`/auth/callback` redirect). Ensure the redirect URI matches the API host/port (defaults to `http://localhost:8000/auth/callback`).
