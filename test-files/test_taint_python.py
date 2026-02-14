# Taint Analysis Test File - Python
# Tests data flow tracking from sources (user input) to sinks (dangerous functions)

import os
import subprocess
import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)

# ============================================
# TAINT TEST 1: SQL Injection via request.args
# Source: request.args.get() -> Sink: cursor.execute()
# ============================================
@app.route('/search')
def search_users():
    username = request.args.get('username')  # SOURCE: user input
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Taint flows: request.args -> username -> query -> execute
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)  # SINK: SQL execution with tainted data
    return str(cursor.fetchall())

# ============================================
# TAINT TEST 2: Command Injection via request.form
# Source: request.form -> Sink: os.system()
# ============================================
@app.route('/ping', methods=['POST'])
def ping_host():
    host = request.form['host']  # SOURCE: user input from form
    # Taint flows: request.form -> host -> command -> os.system
    command = "ping -c 1 " + host
    os.system(command)  # SINK: OS command with tainted data
    return "Pinged"

# ============================================
# TAINT TEST 3: Command Injection via subprocess
# Source: request.json -> Sink: subprocess.call()
# ============================================
@app.route('/run', methods=['POST'])
def run_script():
    data = request.json  # SOURCE: JSON body
    script_name = data['script']
    # Taint flows: request.json -> data -> script_name -> subprocess
    subprocess.call(script_name, shell=True)  # SINK: subprocess with tainted data
    return "Executed"

# ============================================
# TAINT TEST 4: Path Traversal
# Source: request.args -> Sink: open()
# ============================================
@app.route('/file')
def read_file():
    filename = request.args.get('name')  # SOURCE: user input
    # Taint flows: request.args -> filename -> open
    with open('/var/data/' + filename, 'r') as f:  # SINK: file open with tainted path
        return f.read()

# ============================================
# TAINT TEST 5: XSS via Template Injection
# Source: request.args -> Sink: render_template_string()
# ============================================
@app.route('/greet')
def greet():
    name = request.args.get('name')  # SOURCE: user input
    # Taint flows: request.args -> name -> template -> render
    template = "<h1>Hello, " + name + "!</h1>"
    return render_template_string(template)  # SINK: template rendering with tainted data

# ============================================
# TAINT TEST 6: Multi-hop taint propagation
# Source: request.args -> intermediate variables -> Sink
# ============================================
@app.route('/complex')
def complex_flow():
    user_input = request.args.get('input')  # SOURCE
    step1 = user_input.strip()  # Taint propagates through string methods
    step2 = step1.lower()
    step3 = "prefix_" + step2
    final = step3 + "_suffix"
    os.system(final)  # SINK: should still detect taint through multiple hops
    return "Done"

# ============================================
# TAINT TEST 7: Taint through function calls
# Source in one function, sink in another
# ============================================
def process_input(data):
    return "cmd: " + data

@app.route('/indirect')
def indirect_injection():
    cmd = request.args.get('cmd')  # SOURCE
    processed = process_input(cmd)  # Taint flows through function
    os.system(processed)  # SINK
    return "OK"

# ============================================
# TAINT TEST 8: Safe pattern (should NOT flag)
# Sanitized/validated input
# ============================================
@app.route('/safe')
def safe_query():
    user_id = request.args.get('id')
    # Using parameterized query - should be safe
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))  # SAFE
    return str(cursor.fetchall())
