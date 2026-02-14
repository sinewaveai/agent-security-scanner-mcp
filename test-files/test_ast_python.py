# AST Analysis Test File - Python
# Tests structural pattern matching with metavariables

import os
import subprocess
import pickle
import yaml
import hashlib
import sqlite3
from flask import Flask, request

app = Flask(__name__)

# Test 1: Hardcoded credentials (AST should detect variable assignment patterns)
API_KEY = "sk-proj-abc123xyz789"
DATABASE_PASSWORD = "super_secret_password"
AWS_ACCESS_KEY = "AKIAFAKEACCESSKEYID00"

# Test 2: SQL Injection (AST should detect string concatenation in execute)
@app.route('/user/<user_id>')
def get_user(user_id):
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    # Direct concatenation - should be caught
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()

# Test 3: Command Injection (AST should detect os.system with variable)
def run_command(cmd):
    os.system(cmd)  # Dangerous - variable in system call
    subprocess.call(cmd, shell=True)  # Dangerous - shell=True
    subprocess.Popen(cmd, shell=True)  # Dangerous

# Test 4: Insecure Deserialization (AST pattern matching)
def load_user_data(data):
    return pickle.loads(data)  # pickle.loads with any argument

def load_config(config_str):
    return yaml.load(config_str)  # yaml.load without safe_load

# Test 5: Weak Cryptography (AST should match hashlib.md5/sha1 calls)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # MD5 is weak

def hash_token(token):
    return hashlib.sha1(token.encode()).hexdigest()  # SHA1 is weak

# Test 6: Flask debug mode (AST pattern for app.run with debug=True)
if __name__ == '__main__':
    app.run(debug=True)  # Debug mode in production
