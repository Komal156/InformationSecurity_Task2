"""
Shared DB connection settings for the SAFE app.
Override any of these with environment variables if your setup differs
from setup/mysql_setup.sql.
"""
import os

DB_HOST = os.environ.get("BOOKNEST_DB_HOST", "localhost")
DB_USER = os.environ.get("BOOKNEST_DB_USER", "booknest_user")
DB_PASSWORD = os.environ.get("BOOKNEST_DB_PASSWORD", "B00kNest#Secure2026")
DB_NAME = os.environ.get("BOOKNEST_DB_NAME", "booknest_safe")
