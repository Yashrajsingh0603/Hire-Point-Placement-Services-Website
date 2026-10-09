
import os
from urllib.parse import urlparse, unquote

# Render PostgreSQL connection
DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL:
    parsed = urlparse(DATABASE_URL)

    DB_HOST = parsed.hostname
    DB_PORT = parsed.port or 5432
    DB_NAME = unquote(parsed.path.lstrip("/"))
    DB_USER = unquote(parsed.username or "")
    DB_PASSWORD = unquote(parsed.password or "")
else:
    # Local development database
    DB_HOST = "localhost"
    DB_PORT = 5432
    DB_NAME = "job_portal_company"
    DB_USER = "postgres"
    DB_PASSWORD = "root"