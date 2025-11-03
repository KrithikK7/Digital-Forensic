import os
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
from dotenv import load_dotenv

# Ensure env is loaded when this module is imported directly
load_dotenv()

config = Config(environ=os.environ)
oauth = OAuth(config)

oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    access_token_url="https://oauth2.googleapis.com/token",
    authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile https://www.googleapis.com/auth/gmail.readonly",
        "prompt": "consent",
        "access_type": "offline",
        "include_granted_scopes": "true",
    },
)

