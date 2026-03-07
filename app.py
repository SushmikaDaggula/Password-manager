import os
import re
import secrets
import string
import sqlite3
from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

# ── Encryption ────────────────────────────────────────────────────────────────
def get_fernet():
    key = os.getenv("FERNET_KEY")
    if not key:
        raise RuntimeError("FERNET_KEY not set in .env")
    return Fernet(key.encode())

def encrypt(text: str) -> str:
    return get_fernet().encrypt(text.encode()).decode()

def decrypt(token: str) -> str:
    return get_fernet().decrypt(token.encode()).decode()

# ── Database ──────────────────────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(__file__), "vault.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                website   TEXT    NOT NULL,
                username  TEXT    NOT NULL,
                password  TEXT    NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

init_db()

# ── Password Utilities ────────────────────────────────────────────────────────
def check_strength(password: str) -> str:
    """Returns Weak / Medium / Strong based on regex rules."""
    if len(password) < 6:
        return "Weak"
    has_upper   = bool(re.search(r"[A-Z]", password))
    has_lower   = bool(re.search(r"[a-z]", password))
    has_digit   = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]", password))
    score = sum([has_upper, has_lower, has_digit, has_special])
    if len(password) >= 12 and score == 4:
        return "Strong"
    if len(password) >= 8 and score >= 3:
        return "Medium"
    return "Weak"

def generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{};"
    # Guarantee at least one of each category
    pwd = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*()_+-=[];"),
    ]
    pwd += [secrets.choice(alphabet) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)

# ── API Routes ────────────────────────────────────────────────────────────────
@app.route("/api/credentials", methods=["GET"])
def list_credentials():
    q = request.args.get("q", "").lower()
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, website, username, password, created_at FROM credentials ORDER BY created_at DESC"
        ).fetchall()
    result = []
    for row in rows:
        website = row["website"]
        if q and q not in website.lower():
            continue
        result.append({
            "id": row["id"],
            "website": website,
            "username": row["username"],
            "password": decrypt(row["password"]),
            "created_at": row["created_at"],
        })
    return jsonify(result)

@app.route("/api/credentials", methods=["POST"])
def add_credential():
    data = request.get_json()
    website  = (data.get("website") or "").strip()
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    if not website or not username or not password:
        return jsonify({"error": "website, username, and password are required"}), 400
    encrypted = encrypt(password)
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO credentials (website, username, password) VALUES (?, ?, ?)",
            (website, username, encrypted),
        )
        conn.commit()
        new_id = cur.lastrowid
    return jsonify({
        "id": new_id,
        "website": website,
        "username": username,
        "strength": check_strength(password),
    }), 201

@app.route("/api/credentials/<int:cred_id>", methods=["DELETE"])
def delete_credential(cred_id):
    with get_db() as conn:
        deleted = conn.execute(
            "DELETE FROM credentials WHERE id = ?", (cred_id,)
        ).rowcount
        conn.commit()
    if not deleted:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"deleted": cred_id})

@app.route("/api/strength", methods=["POST"])
def strength():
    data = request.get_json()
    pwd = data.get("password", "")
    return jsonify({"strength": check_strength(pwd)})

@app.route("/api/generate", methods=["GET"])
def generate():
    length = min(max(int(request.args.get("length", 16)), 8), 64)
    pwd = generate_password(length)
    return jsonify({"password": pwd, "strength": check_strength(pwd)})

if __name__ == "__main__":
    app.run(debug=True, port=5000)
