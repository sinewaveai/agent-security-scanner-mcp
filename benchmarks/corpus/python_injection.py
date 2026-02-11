"""Benchmark corpus: Python injection vulnerabilities (SQLi, command injection, code injection)."""
import os
import subprocess

# --- SQL Injection ---

user_id = "1; DROP TABLE users"

# VULN: sql-injection-db-cursor
cursor.execute("SELECT * FROM users WHERE id = " + user_id)

# VULN: sql-injection-db-cursor
# VULN: sql-injection-using-sqlalchemy
cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")

# SAFE: sql-injection-db-cursor
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# SAFE: sql-injection-db-cursor
cursor.execute("SELECT * FROM users WHERE name = ?", [username])

# --- Command Injection ---

user_input = "file.txt; rm -rf /"

# VULN: dangerous-subprocess-use
subprocess.call(user_input, shell=True)

# VULN: dangerous-subprocess-use
subprocess.Popen(user_input, shell=True)

# VULN: dangerous-system-call
os.system("cat " + user_input)

# SAFE: dangerous-subprocess-use
subprocess.call(["cat", user_input], shell=False)

# SAFE: dangerous-system-call
subprocess.run(["ls", "-la", user_input])

# --- Code Injection ---

user_code = "print('hello')"

# VULN: eval-detected
result = eval(user_code)

# VULN: exec-detected
exec(user_code)

# VULN: compile-detected
code = compile(user_code, "<string>", "exec")

# SAFE: eval-detected
result = int(user_code) if user_code.isdigit() else 0

# --- Deserialization ---

import pickle
import yaml

# VULN: pickle-load
data = pickle.loads(untrusted_data)

# VULN: yaml-load
config = yaml.load(untrusted_yaml)

# SAFE: yaml-load
config = yaml.safe_load(trusted_yaml)
