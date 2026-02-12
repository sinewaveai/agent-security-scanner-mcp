# Test file for vulnerability detection evaluation
import os
import subprocess
import sqlite3
import pickle
import yaml

# Hardcoded secrets
API_KEY = "sk-live-abc123xyz789"
password = "super_secret_password_123"
aws_key = "AKIAFAKEACCESSKEYID00"

# SQL Injection
def get_user(user_id):
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()

# Command Injection
def run_command(cmd):
    os.system(cmd)
    subprocess.call(cmd, shell=True)

# Path Traversal
def read_file(filename):
    with open("/var/data/" + filename) as f:
        return f.read()

# Insecure Deserialization
def load_data(data):
    return pickle.loads(data)

def load_yaml(data):
    return yaml.load(data)

# Weak Crypto
import hashlib
def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()
