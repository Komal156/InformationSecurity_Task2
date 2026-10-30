"""
BookNest — SAFE VERSION (Python / Flask / MySQL)

Same functionality as the vulnerable version, hardened:
  - Reflected XSS   -> FIXED: templates no longer use |safe on q; Jinja2's
                       default auto-escaping handles it.
  - Stored XSS      -> FIXED: review comments rendered without |safe.
  - DOM-based XSS   -> FIXED: quicknote.js uses textContent, not innerHTML.
  - CSRF            -> FIXED: update-email is POST-only and requires a
                       per-session CSRF token the attacker cannot know.
  - SQL Injection (easy/intermediate/advanced) -> FIXED: every query uses
    parameterized placeholders (%s), user input is never concatenated
    into SQL text. Passwords are hashed (Werkzeug scrypt) and verified in
    Python, never inside a SQL string.
"""
import secrets
from functools import wraps

import pymysql
from flask import Flask, g, request, session, redirect, url_for, render_template, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash

import config

app = Flask(__name__)
app.secret_key = "booknest-dev-secret-safe"
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")


def get_db():
    if "db" not in g:
        g.db = pymysql.connect(
            host=config.DB_HOST,
            user=config.DB_USER,
            password=config.DB_PASSWORD,
            database=config.DB_NAME,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True,
        )
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.before_request
def load_user_context():
    g.logged_in = "user_id" in session
    g.username = session.get("username")
    # Issue a per-session CSRF token once, reuse it for every form.
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(24)
    g.csrf_token = session["csrf_token"]


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": g.csrf_token}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def csrf_required(view):
    """Generic CSRF guard for any POST that changes state."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        token = request.form.get("_csrf")
        if not token or token != session.get("csrf_token"):
            abort(403, description="Invalid or missing CSRF token.")
        return view(*args, **kwargs)

    return wrapped


# ---------- Home / catalog ----------
@app.route("/")
def home():
    db = get_db()
    with db.cursor() as cur:
        cur.execute("SELECT * FROM books ORDER BY id")
        books = cur.fetchall()
    return render_template("index.html", title="BookNest (Safe)", books=books)


# ---------- SQL injection FIX (parameterized) + reflected XSS FIX (auto-escaped) ----------
@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    # FIXED: parameterized query — user input can never change the SQL
    # structure, no matter what characters it contains.
    with db.cursor() as cur:
        cur.execute(
            "SELECT id, title, author, price FROM books WHERE title LIKE %s",
            (f"%{q}%",),
        )
        results = cur.fetchall()
    # FIXED: q is rendered WITHOUT |safe in search.html -> Jinja2 escapes it.
    return render_template(
        "search.html", title="Search — BookNest (Safe)", q=q, results=results, error=None
    )


# ---------- Book detail + stored XSS FIX ----------
@app.route("/book/<int:book_id>")
def book_detail(book_id):
    db = get_db()
    with db.cursor() as cur:
        cur.execute("SELECT * FROM books WHERE id = %s", (book_id,))
        book = cur.fetchone()
        if not book:
            return "Book not found", 404
        cur.execute(
            "SELECT * FROM reviews WHERE book_id = %s ORDER BY id DESC", (book_id,)
        )
        reviews = cur.fetchall()
    return render_template(
        "book.html", title=book["title"] + " — BookNest (Safe)", book=book, reviews=reviews
    )


@app.route("/book/<int:book_id>/review", methods=["POST"])
@login_required
@csrf_required
def submit_review(book_id):
    comment = request.form.get("comment", "")
    db = get_db()
    # FIXED: comment is still stored as-is (that's normal), but book.html
    # now renders it WITHOUT |safe, so any HTML/JS is escaped before it
    # reaches the browser -> a stored <script> payload shows up as inert text.
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO reviews (book_id, username, comment) VALUES (%s, %s, %s)",
            (book_id, session["username"], comment),
        )
    return redirect(url_for("book_detail", book_id=book_id))


# ---------- Auth ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html", title="Register — BookNest (Safe)", error=None)
    username = request.form.get("username", "")
    email = request.form.get("email", "")
    password = request.form.get("password", "")
    db = get_db()
    try:
        hashed = generate_password_hash(password)
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, email, password, is_admin) VALUES (%s, %s, %s, 0)",
                (username, email, hashed),
            )
        return redirect(url_for("login"))
    except pymysql.Error:
        return render_template(
            "register.html",
            title="Register — BookNest (Safe)",
            error="Could not register (username or email may already be taken).",
        )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", title="Login — BookNest (Safe)", error=None)

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    db = get_db()
    # FIXED: look the user up by username ONLY, with a parameterized
    # query. The password is never part of the SQL at all — it is
    # compared separately in Python with check_password_hash() against
    # the stored hash.
    with db.cursor() as cur:
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()

    ok = user and check_password_hash(user["password"], password)
    if ok:
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return redirect(url_for("profile"))
    return render_template(
        "login.html", title="Login — BookNest (Safe)", error="Invalid username or password."
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ---------- Profile + CSRF FIX ----------
@app.route("/profile")
@login_required
def profile():
    db = get_db()
    with db.cursor() as cur:
        cur.execute("SELECT * FROM users WHERE id = %s", (session["user_id"],))
        user = cur.fetchone()
    return render_template("profile.html", title="My Profile — BookNest (Safe)", user=user)


# FIXED: state-changing action now requires POST AND a valid CSRF token
# tied to the user's own session. An attacker's page has no way to read
# or guess this token (it's never exposed cross-origin), so a forged
# request from another site is rejected with 403.
@app.route("/profile/update-email", methods=["POST"])
@login_required
@csrf_required
def update_email():
    new_email = request.form.get("email")
    if new_email:
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                "UPDATE users SET email = %s WHERE id = %s",
                (new_email, session["user_id"]),
            )
    return redirect(url_for("profile"))


# ---------- SQL injection FIX for the email-availability check ----------
@app.route("/api/check-email")
def check_email():
    email = request.args.get("email", "")
    db = get_db()
    try:
        # FIXED: parameterized query, nothing to inject.
        with db.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            row = cur.fetchone()
        return jsonify({"status": "taken" if row else "available"})
    except pymysql.Error:
        # FIXED: never leak raw DB error details to the client.
        return jsonify({"status": "error"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
