import os
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from dotenv import load_dotenv

# Load env first so imports that read env work correctly
load_dotenv()

from sqlalchemy import text
from db import engine
from models import Base

SUPER_URL = os.getenv("POSTGRES_SUPER_URL")
APP_DB_NAME = os.getenv("APP_DB_NAME", "gmail_forensics")
APP_DB_USER = os.getenv("APP_DB_USER", "gmail_app")
APP_DB_PASS = os.getenv("APP_DB_PASS", "gmail_app")

def ensure_db_and_user():
    # Connect to the 'postgres' maintenance DB
    conn = psycopg2.connect(SUPER_URL)
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()

    # Create role if not exists
    cur.execute(f"SELECT 1 FROM pg_roles WHERE rolname = %s;", (APP_DB_USER,))
    if not cur.fetchone():
        cur.execute(f"CREATE ROLE {APP_DB_USER} LOGIN PASSWORD %s;", (APP_DB_PASS,))

    # Create database if not exists
    cur.execute("SELECT 1 FROM pg_database WHERE datname = %s;", (APP_DB_NAME,))
    if not cur.fetchone():
        cur.execute(f'CREATE DATABASE "{APP_DB_NAME}" OWNER {APP_DB_USER};')

    # Grant privileges just in case
    cur.execute(f'GRANT ALL PRIVILEGES ON DATABASE "{APP_DB_NAME}" TO {APP_DB_USER};')

    cur.close()
    conn.close()

def enable_pgvector_extension():
    if not SUPER_URL:
        raise RuntimeError("POSTGRES_SUPER_URL not set; cannot enable pgvector without superuser connection.")
    # Connect to the target DB with super privileges and enable the extension
    conn = psycopg2.connect(SUPER_URL, dbname=APP_DB_NAME)
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()
    cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
    cur.close()
    conn.close()

def create_tables():
    # Use SQLAlchemy engine bound to APP_DB_URL to create tables
    Base.metadata.create_all(bind=engine)

if __name__ == "__main__":
    ensure_db_and_user()
    # Enable pgvector on the target DB using super privileges
    try:
        enable_pgvector_extension()
        print("pgvector extension enabled (or already present).")
    except Exception as e:
        print(f"Warning: could not enable pgvector automatically: {e}")
    create_tables()
    print(f"Database '{APP_DB_NAME}' and tables are ready.")
