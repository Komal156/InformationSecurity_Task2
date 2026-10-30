-- One-time MySQL setup for the BookNest (Python/Flask + MySQL) project.
--
-- Creates a dedicated, low-privilege MySQL user for the app (never use
-- the MySQL root account from application code) and two empty databases,
-- one per version, so the vulnerable and safe apps never share data.
--
-- Run ONCE, as a MySQL admin:
--   sudo mysql < setup/mysql_setup.sql
--
-- On a fresh machine/examiner's machine this is the only step that needs
-- elevated privileges. Everything after this (creating tables, seeding
-- data, running the apps) uses the app-level user created here and needs
-- no sudo/root at all.

CREATE DATABASE IF NOT EXISTS booknest_vulnerable
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE DATABASE IF NOT EXISTS booknest_safe
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- A stronger password is used here because MySQL's validate_password
-- policy (enabled by default on this install) rejects simple ones.
CREATE USER IF NOT EXISTS 'booknest_user'@'localhost' IDENTIFIED BY 'B00kNest#Secure2026';

GRANT ALL PRIVILEGES ON booknest_vulnerable.* TO 'booknest_user'@'localhost';
GRANT ALL PRIVILEGES ON booknest_safe.* TO 'booknest_user'@'localhost';

FLUSH PRIVILEGES;

SELECT 'BookNest MySQL setup complete.' AS status;
