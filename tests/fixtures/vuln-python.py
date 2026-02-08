import os
import hashlib
import pickle
import subprocess
import sqlite3
import requests
import yaml

# 1. SQL Injection
def get_user(user_id):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()

# 2. Command Injection
def run_command(user_input):
    cmd = "ls " + user_input
    result = subprocess.call(cmd, shell=True)
    return result

# 3. Hardcoded secret
API_KEY = "sk_live_abc123def456ghi789"

# 4. Weak crypto (MD5)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# 5. Insecure deserialization
def load_data(data):
    return pickle.loads(data)

# 6. YAML unsafe load
def parse_config(config_str):
    return yaml.load(config_str)

# 7. SSL verification disabled
def fetch_data(url):
    return requests.get(url, verify=False)

# 8. Hardcoded password
DATABASE_PASSWORD = "super_secret_password_123"

# 9. eval() usage
def calculate(expression):
    return eval(expression)

# 10. Weak crypto (SHA1)
def hash_token(token):
    return hashlib.sha1(token.encode()).hexdigest()
