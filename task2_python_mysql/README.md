# BookNest — Web Security Project (Part 2, Python/Flask + MySQL)

An online bookstore built twice: once **deliberately vulnerable**, once
**hardened**, so that every required web vulnerability and its fix can be
demonstrated side by side on the same real feature set.

## Use case

BookNest is a small online bookstore: browse books, search the catalog,
register/log in, leave reviews on a book, and manage your profile (change
your email). Both versions share the exact same pages, routes, and seed
data — only the security posture differs.

## Tech stack

- **Backend:** Python 3 + Flask
- **Database:** MySQL (via `PyMySQL`) — one database per version, same
  MySQL server
- **Templates:** Jinja2 (Flask's built-in templating, server-rendered HTML)
- **Frontend:** plain HTML/CSS/JS (no framework), to keep the client-side
  DOM XSS example easy to follow
- **Auth:** Flask's built-in signed-cookie sessions; the Safe version
  additionally hashes passwords with Werkzeug's `generate_password_hash`
  (scrypt)

## Project structure

```
task2_python_mysql/
├── setup/
│   └── mysql_setup.sql   # one-time, run with sudo — see below
├── vulnerable/            # insecure version — every attack below works
│   ├── app.py
│   ├── config.py
│   ├── db_init.py         # seeds booknest_vulnerable (plaintext passwords — see note below)
│   ├── requirements.txt
│   ├── templates/          (Jinja2 templates)
│   └── static/              (CSS, client-side JS incl. the DOM-XSS sink)
├── safe/                  # hardened version — same features, attacks fail
│   ├── app.py
│   ├── config.py
│   ├── db_init.py         # seeds booknest_safe (hashed passwords)
│   ├── requirements.txt
│   ├── templates/
│   └── static/              (incl. the DOM-XSS fix)
├── csrf_attack/
│   └── evil.html           # the CSRF proof-of-concept page
└── docs/
    └── payloads.md          # every payload used + what it proves, for the report
```

## How to run

### 1. One-time MySQL setup (needs `sudo`, run once)

```bash
sudo mysql < setup/mysql_setup.sql
```

This creates a dedicated, low-privilege MySQL user (`booknest_user`) and
two empty databases (`booknest_vulnerable`, `booknest_safe`). The app
code never uses the MySQL root account. Nothing after this step needs
`sudo` — this also means the same script is all a fresh machine (or your
examiner's machine) needs before cloning and running the apps.

> Using different MySQL credentials? Override them with environment
> variables instead of editing `config.py`: `BOOKNEST_DB_HOST`,
> `BOOKNEST_DB_USER`, `BOOKNEST_DB_PASSWORD`, `BOOKNEST_DB_NAME`.

### 2. Vulnerable app — http://localhost:5000

```bash
cd vulnerable
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
./venv/bin/python db_init.py      # creates tables + seed data
./venv/bin/python app.py
```

### 3. Safe app — http://localhost:5001 (in a second terminal)

```bash
cd safe
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
./venv/bin/python db_init.py
./venv/bin/python app.py
```

Run both at once to compare them directly — same bookstore, same seed
data, different security posture (red banner vs green banner at the top
of every page confirms which one you're on).

### Test accounts (identical in both versions)

| Username | Password | Role |
|---|---|---|
| alice | alice123 | regular user |
| bob | bob123 | regular user |
| admin | SuperSecretAdmin!2026 | admin |

## Vulnerable vs Safe — what's different

| # | Vulnerability | Where (both versions) | Vulnerable version | Safe version |
|---|---|---|---|---|
| 1 | Reflected XSS | `GET /search?q=` | `q` rendered with Jinja's `\|safe` filter (disables auto-escaping) | rendered with no filter — Jinja2's default auto-escaping applies |
| 2 | Stored XSS | book reviews, `POST /book/<id>/review` | review `comment` rendered with `\|safe` | rendered with no filter |
| 3 | DOM-based XSS | `static/js/quicknote.js`, reads `location.hash` | writes the value with `.innerHTML` | writes the value with `.textContent` |
| 4 | CSRF | `/profile/update-email` | `GET`, no token check | `POST`-only, requires a per-session CSRF token (`_csrf`) |
| 5 | SQL Injection — easy | `POST /login` | raw f-string query, plaintext password compared in SQL | parameterized lookup by username, password checked with `check_password_hash()` in Python |
| 6 | SQL Injection — intermediate | `GET /api/check-email` | f-string query; boolean result *and* raw DB error are both leaked | parameterized query (`%s` placeholder); generic error, no detail leaked |
| 7 | SQL Injection — advanced | `GET /search?q=` | f-string `LIKE` query, lets a full UNION-based chain run via `information_schema` | parameterized `LIKE %s` query, user input can never change the SQL structure |

**Why Flask/Jinja2 needed an explicit mistake to become vulnerable:**
Jinja2 auto-escapes all template output by default — this is Flask's
"secure by default" behaviour. To make the vulnerable version genuinely
exploitable, the specific unsafe render points use Jinja's `|safe` filter
to deliberately opt out of that protection. This mirrors a real mistake:
a developer adds `|safe` so *some* trusted HTML renders correctly (e.g. a
formatted description) and doesn't realise it also disables escaping for
attacker-controlled input flowing through the same template variable.

**Note on plaintext passwords in the vulnerable version:** the vulnerable
login route builds `WHERE username='x' AND password='y'` directly as SQL
text, which only makes sense if the password column can be compared as
plain text in SQL. This is intentional and documented in
`vulnerable/db_init.py` — it's the same reason real legacy apps with this
exact SQLi bug also tend to store plaintext passwords. The Safe version
fixes both problems together: passwords are hashed, and the password is
*never* part of a SQL string at all.

**On `information_schema`:** this stack uses real MySQL, so the advanced
SQL injection chain uses MySQL's actual `information_schema.tables` and
`information_schema.columns` — exactly as described in the assignment
brief, no adaptation needed (unlike a SQLite-based version, which would
need `sqlite_master`/`pragma_table_info` as stand-ins).

## Demonstrating CSRF

`csrf_attack/evil.html` is a standalone page simulating a malicious
external site. Open it in a browser while logged into BookNest to see it
silently change the logged-in user's email.

1. Start the **vulnerable** app, log in as `alice` at `http://localhost:5000/login`.
2. Without logging out, open `csrf_attack/evil.html` directly in the same
   browser (e.g. double-click the file).
3. Go back to `http://localhost:5000/profile` — alice's email is now
   `attacker-controlled@evil.com`, even though she never touched that form.
4. Repeat against the **safe** app (edit the form's `action` in
   `evil.html` to point at `localhost:5001`) — the request is rejected
   with `405 Method Not Allowed` (the route no longer accepts `GET` at
   all). If an attacker's page instead forged a `POST`, it would get
   `403 Forbidden` for missing/invalid CSRF token — either way, the
   email is never changed.

## Full payload list

See [`docs/payloads.md`](docs/payloads.md) for every payload used for
each vulnerability (both the exploit and the corresponding safe-version
test showing it now fails), ready to copy into the assignment's report
alongside your screenshots.

## Disclaimer

This project is for authorized educational use only (a university
Information Security coursework assignment). Do not deploy the
vulnerable version on a public or shared network.
