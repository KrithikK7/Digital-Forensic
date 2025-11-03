import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from dotenv import load_dotenv

# Ensure .env is loaded before reading env vars
load_dotenv()

APP_DB_URL = os.getenv("APP_DB_URL")

class Base(DeclarativeBase):
    pass

if not APP_DB_URL:
    raise ValueError(
        "APP_DB_URL is not set. Define it in your environment or .env file."
    )

engine = create_engine(APP_DB_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
