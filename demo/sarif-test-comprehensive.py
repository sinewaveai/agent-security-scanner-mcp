# Comprehensive test file for SARIF output validation
# Contains multiple vulnerability types

import os
import pickle
import subprocess

# 1. SQL Injection - f-string
def get_user(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()

# 2. SQL Injection - concatenation
def delete_user(user_id):
    cursor.execute("DELETE FROM users WHERE id = " + user_id)

# 3. Hardcoded secrets
API_KEY = "sk-proj-abc123xyz789secretkey"
AWS_ACCESS_KEY = "AKIAFAKEACCESSKEYID00"
DATABASE_PASSWORD = "super_secret_password_123"

# 4. Command injection
def run_command(user_input):
    os.system("ls " + user_input)

# 5. Dangerous subprocess
def execute(cmd):
    subprocess.call(cmd, shell=True)

# 6. Insecure deserialization
def load_data(data):
    return pickle.loads(data)

# 7. Weak crypto (if detected)
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
