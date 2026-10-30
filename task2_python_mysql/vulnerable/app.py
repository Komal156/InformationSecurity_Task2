"""
BookNest — VULNERABLE VERSION (Python / Flask / MySQL)

This server deliberately contains:
  - Reflected XSS   (GET /search          -> ?q= reflected unescaped, via |safe)
  - Stored XSS      (POST /book/<id>/review -> comment stored & rendered unescaped)
  - DOM-based XSS   (static/js/quicknote.js -> reads location.hash into innerHTML)
  - CSRF            (GET /profile/update-email -> no token, state change via GET)
  - SQL Injection (easy)         -> POST /login (string-concatenated query)
  - SQL Injection (intermediate) -> GET /api/check-email (blind boolean/error-based)
  - SQL Injection (advanced)     -> GET /search (UNION-based extraction via information_schema)

Flask/Jinja2 auto-escape HTML by default, which is the modern-framework
"secure by default" behaviour. To make this version genuinely vulnerable,
the specific unsafe render points below explicitly opt OUT of that
protection with Jinja's `| safe` filter (or `Markup`) — the same mistake
real developers make when they want "a bit of raw HTML" to render
somewhere and don't realise it also disables escaping for attacker input.

FOR AUTHORIZED COURSEWORK / LOCAL TESTING ONLY. Do not deploy publicly.
"""
import pymysql
from flask import Flask, g, request, session, redirect, url_for, render_template, jsonify

import config

app = Flask(__name__)
app.secret_key = "booknest-dev-secret-vulnerable"


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


def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


# ---------- Home / catalog ----------
@app.route("/")
def home():
    db = get_db()
    with db.cursor() as cur:
        cur.execute("SELECT * FROM books ORDER BY id")
        books = cur.fetchall()
    return render_template("index.html", title="BookNest", books=books)


# ---------- SQL INJECTION (ADVANCED, UNION-based) + REFLECTED XSS ----------
@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    # VULNERABLE: raw string concatenation straight into the query.
    query = f"SELECT id, title, author, price FROM books WHERE title LIKE '%{q}%'"
    print("[VULNERABLE SQL]", query)
    results = []
    error = None
    try:
        with db.cursor() as cur:
            cur.execute(query)
            results = cur.fetchall()
    except pymysql.Error as e:
        error = str(e)
    # VULNERABLE: q is echoed back into the page with |safe -> reflected XSS.
    return render_template(
        "search.html", title="Search — BookNest", q=q, results=results, error=error
    )


# ---------- Book detail + STORED XSS ----------
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
        "book.html", title=book["title"] + " — BookNest", book=book, reviews=reviews
    )


@app.route("/book/<int:book_id>/review", methods=["POST"])
@login_required
def submit_review(book_id):
    comment = request.form.get("comment", "")
    db = get_db()
    # VULNERABLE: comment is stored as-is and later rendered with |safe
    # on every visitor's page -> stored XSS.
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
        return render_template("register.html", title="Register — BookNest", error=None)
    username = request.form.get("username", "")
    email = request.form.get("email", "")
    password = request.form.get("password", "")
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, email, password, is_admin) VALUES (%s, %s, %s, 0)",
                (username, email, password),
            )
        return redirect(url_for("login"))
    except pymysql.Error as e:
        return render_template(
            "register.html", title="Register — BookNest", error=f"Could not register: {e}"
        )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", title="Login — BookNest", error=None)

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    db = get_db()
    # VULNERABLE: user input concatenated directly into the SQL string.
    query = (
        f"SELECT * FROM users WHERE username = '{username}' "
        f"AND password = '{password}'"
    )
    print("[VULNERABLE SQL]", query)
    try:
        with db.cursor() as cur:
            cur.execute(query)
            user = cur.fetchone()
    except pymysql.Error as e:
        return render_template(
            "login.html", title="Login — BookNest", error=f"Database error: {e}"
        )

    if user:
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return redirect(url_for("profile"))
    return render_template(
        "login.html", title="Login — BookNest", error="Invalid username or password."
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ---------- Profile + CSRF target ----------
@app.route("/profile")
@login_required
def profile():
    db = get_db()
    with db.cursor() as cur:
        cur.execute("SELECT * FROM users WHERE id = %s", (session["user_id"],))
        user = cur.fetchone()
    return render_template("profile.html", title="My Profile — BookNest", user=user)


# VULNERABLE: state-changing action reachable via GET, with no CSRF token
# check at all. Any page the victim's browser visits while logged in can
# trigger this (e.g. an auto-submitting form on an attacker's site).
@app.route("/profile/update-email")
@login_required
def update_email():
    new_email = request.args.get("email")
    if new_email:
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                "UPDATE users SET email = %s WHERE id = %s",
                (new_email, session["user_id"]),
            )
    return redirect(url_for("profile"))


# ---------- SQL INJECTION (INTERMEDIATE, blind boolean/error-based) ----------
# Used by the registration page to live-check "is this email taken?".
@app.route("/api/check-email")
def check_email():
    email = request.args.get("email", "")
    db = get_db()
    query = f"SELECT id FROM users WHERE email = '{email}'"
    print("[VULNERABLE SQL]", query)
    try:
        with db.cursor() as cur:
            cur.execute(query)
            row = cur.fetchone()
        return jsonify({"status": "taken" if row else "available"})
    except pymysql.Error as e:
        # VULNERABLE: leaking the raw DB error back to the client makes
        # error-based injection possible too, in addition to boolean-blind.
        return jsonify({"status": "error", "detail": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
