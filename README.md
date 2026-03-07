# 🔐 Vault — Local Password Manager

A secure, locally-run credential manager built with **Python/Flask** (backend) and vanilla **HTML/CSS/JS** (frontend).

---

## Features

| Feature | Details |
|---|---|
| Fernet encryption | All passwords AES-128-CBC encrypted before being saved to SQLite |
| Password strength | Regex-based Weak / Medium / Strong checker, shown in real time |
| Password generator | `secrets` module + guaranteed character class mix |
| REST API | `GET /credentials`, `POST /credentials`, `DELETE /credentials/:id`, `POST /strength`, `GET /generate` |
| Frontend | Add form, show/hide toggle, clipboard copy, real-time search, strength bar |

---

## Setup

### 1. Clone & install backend dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Generate your encryption key (run once)

```bash
python generate_key.py
```

This writes a `.env` file containing `FERNET_KEY=<your-key>`.  
**Never commit `.env` to version control.**  Add it to `.gitignore`:

```
.env
vault.db
```

### 3. Start the backend

```bash
python app.py
# Flask runs on http://localhost:5000
```

### 4. Open the frontend

Open `frontend/index.html` in your browser directly, or serve it:

```bash
cd frontend
python -m http.server 8080
# Visit http://localhost:8080
```

---

## Encryption Key Management

| Decision | Rationale |
|---|---|
| **Fernet (AES-128-CBC + HMAC-SHA256)** | Standard symmetric authenticated encryption from the `cryptography` library — resistant to tampering and replay attacks |
| **Key stored in `.env`** | Keeps the key out of source code and out of the database; loaded at runtime via `python-dotenv` |
| **One key per installation** | Each local install generates its own key via `generate_key.py` using `Fernet.generate_key()` (OS CSPRNG) |
| **Never hardcoded** | `get_fernet()` raises `RuntimeError` if `FERNET_KEY` is missing — fails fast rather than silently insecure |
| **Key rotation** | To rotate: decrypt all rows with the old key, generate a new key, re-encrypt, replace `.env` |

---

## Project Structure

```
password-manager/
├── backend/
│   ├── app.py            # Flask API
│   ├── generate_key.py   # One-time key generator
│   ├── requirements.txt
│   ├── .env              # FERNET_KEY (gitignored)
│   └── vault.db          # SQLite database (gitignored)
└── frontend/
    └── index.html        # Single-file UI
```

---

## API Reference

```
GET    /api/credentials?q=<search>   # List / search credentials
POST   /api/credentials              # Add { website, username, password }
DELETE /api/credentials/:id          # Remove by ID
POST   /api/strength                 # Check { password } → { strength }
GET    /api/generate?length=16       # Generate password
```

---

## Security Notes

- **All encryption/decryption happens on the server** — the raw password is never stored.
- The app is designed for **local use only**; expose it to a network only behind authentication.
- `vault.db` contains ciphertext only; without the `.env` key it cannot be decrypted.
