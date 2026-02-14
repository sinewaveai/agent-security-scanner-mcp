# Clean code with no vulnerabilities
import os
import json

def get_user(user_id):
    """Get user with parameterized query"""
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()

def load_config():
    """Safe config loading"""
    with open("config.json") as f:
        return json.load(f)

def get_api_key():
    """Safe secret retrieval"""
    return os.environ.get("API_KEY")
