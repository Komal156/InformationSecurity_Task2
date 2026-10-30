"""
db_init.py — creates and seeds the booknest_safe MySQL database.

FIX vs vulnerable version: passwords are hashed with Werkzeug's
generate_password_hash() (scrypt-based) before being stored, and app.py
never builds SQL by concatenating the password (or anything else) into a
query string — it always uses parameterized queries and verifies the
password with check_password_hash() in Python.

Run with: python3 db_init.py
(requires setup/mysql_setup.sql to have been run once already)
"""
import pymysql
from werkzeug.security import generate_password_hash
import config

conn = pymysql.connect(
    host=config.DB_HOST,
    user=config.DB_USER,
    password=config.DB_PASSWORD,
    database=config.DB_NAME,
    charset="utf8mb4",
)

with conn.cursor() as cur:
    cur.execute("DROP TABLE IF EXISTS reviews")
    cur.execute("DROP TABLE IF EXISTS books")
    cur.execute("DROP TABLE IF EXISTS users")

    cur.execute(
        """
        CREATE TABLE users (
          id INT AUTO_INCREMENT PRIMARY KEY,
          username VARCHAR(50) UNIQUE NOT NULL,
          email VARCHAR(100) UNIQUE NOT NULL,
          password VARCHAR(255) NOT NULL,
          is_admin TINYINT NOT NULL DEFAULT 0
        ) ENGINE=InnoDB
        """
    )

    cur.execute(
        """
        CREATE TABLE books (
          id INT AUTO_INCREMENT PRIMARY KEY,
          title VARCHAR(200) NOT NULL,
          author VARCHAR(100) NOT NULL,
          price DECIMAL(6,2) NOT NULL,
          description TEXT NOT NULL
        ) ENGINE=InnoDB
        """
    )

    cur.execute(
        """
        CREATE TABLE reviews (
          id INT AUTO_INCREMENT PRIMARY KEY,
          book_id INT NOT NULL,
          username VARCHAR(50) NOT NULL,
          comment TEXT NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (book_id) REFERENCES books(id)
        ) ENGINE=InnoDB
        """
    )

    cur.executemany(
        "INSERT INTO users (username, email, password, is_admin) VALUES (%s, %s, %s, %s)",
        [
            ("alice", "alice@example.com", generate_password_hash("alice123"), 0),
            ("bob", "bob@example.com", generate_password_hash("bob123"), 0),
            ("admin", "admin@booknest.com", generate_password_hash("SuperSecretAdmin!2026"), 1),
        ],
    )

    cur.executemany(
        "INSERT INTO books (title, author, price, description) VALUES (%s, %s, %s, %s)",
        [
            ("The Silent Algorithm", "N. Marsh", 14.99, "A thriller set inside a rogue AI lab."),
            ("Gardens of Rust", "P. Okafor", 9.50, "A quiet novel about a blacksmith's last winter."),
            ("Beneath Two Moons", "R. Castellan", 12.00, "Fantasy epic, first in the Lumen Cycle."),
            ("The Debugger's Diary", "S. Iqbal", 11.25, "A memoir from twenty years of chasing bugs."),
            ("Paper Boats", "L. Chen", 8.75, "Short stories about childhood and rivers."),
            ("Fault Lines", "M. Torres", 15.50, "Investigative nonfiction on the 2041 grid collapse."),
        ],
    )

    cur.executemany(
        "INSERT INTO reviews (book_id, username, comment) VALUES (%s, %s, %s)",
        [
            (1, "bob", "Could not put this down, finished it in two nights."),
            (3, "alice", "Beautifully written, the world-building is incredible."),
        ],
    )

conn.commit()
conn.close()

print(f"{config.DB_NAME} created and seeded.")
print("Seed users (same logins as the vulnerable version): alice/alice123, bob/bob123, admin/SuperSecretAdmin!2026")
print("Passwords are stored hashed this time (Werkzeug scrypt).")
