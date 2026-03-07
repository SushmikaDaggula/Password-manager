"""Run once to generate your FERNET_KEY and write it to .env"""
from cryptography.fernet import Fernet

key = Fernet.generate_key().decode()
with open(".env", "w") as f:
    f.write(f"FERNET_KEY={key}\n")
print(f"✅  Key written to .env:\n    FERNET_KEY={key}")
