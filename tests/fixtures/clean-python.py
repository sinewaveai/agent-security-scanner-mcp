import os
import hashlib
import json
import sqlite3

# Safe: Parameterized query
def get_user(user_id):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()

# Safe: SHA-256 hashing
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Safe: Environment variable for secrets
key = os.environ.get("API_KEY")

# Safe: json.loads instead of pickle
def load_data(data):
    return json.loads(data)

# Safe: No eval
def calculate(a, b):
    return a + b

# Safe: No hardcoded secrets
def get_db_password():
    return os.environ.get("DATABASE_PASSWORD")
