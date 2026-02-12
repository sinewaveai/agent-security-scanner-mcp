"""
Comprehensive test file for Semgrep-aligned security rules.
Contains true positives for each rule category.

Run with: python test_semgrep_rules.py
Or:       python -m pytest test_semgrep_rules.py -v
"""

import unittest
import tempfile
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analyzer import analyze_file
from rules import get_rules, get_rule_stats, get_rules_for_language


# ============================================================================
# TEST UTILITIES
# ============================================================================

def analyze_code(code, extension='.py'):
    """Analyze code string using a temp file"""
    fd, filepath = tempfile.mkstemp(suffix=extension, text=True)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(code)
        return analyze_file(filepath)
    finally:
        try:
            os.unlink(filepath)
        except:
            pass


def has_rule(issues, rule_pattern):
    """Check if any issue matches rule pattern"""
    return any(rule_pattern in i['ruleId'] for i in issues)


# ============================================================================
# UNIT TESTS
# ============================================================================

class TestRulesLoading(unittest.TestCase):
    """Test that rules load correctly"""
    
    def test_rules_loaded(self):
        rules = get_rules()
        self.assertGreater(len(rules), 100)
    
    def test_python_rules_exist(self):
        rules = get_rules_for_language('python')
        self.assertGreater(len(rules), 20)
    
    def test_javascript_rules_exist(self):
        rules = get_rules_for_language('javascript')
        self.assertGreater(len(rules), 20)
    
    def test_generic_rules_apply_to_all(self):
        py_rules = get_rules_for_language('python')
        js_rules = get_rules_for_language('javascript')
        # Generic secrets rules should be in both
        self.assertTrue(any('generic' in r for r in py_rules))
        self.assertTrue(any('generic' in r for r in js_rules))


class TestSQLInjection(unittest.TestCase):
    """SQL Injection detection tests"""
    
    def test_cursor_execute_concat(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
        issues = analyze_code(code)
        self.assertTrue(has_rule(issues, 'sqli'))
    
    def test_cursor_execute_fstring(self):
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")'
        issues = analyze_code(code)
        self.assertTrue(has_rule(issues, 'sqli'))
    
    def test_cursor_execute_percent(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = %s" % uid)'
        issues = analyze_code(code)
        self.assertTrue(has_rule(issues, 'sqli'))
    
    def test_safe_parameterized_query(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))'
        issues = analyze_code(code)
        self.assertFalse(has_rule(issues, 'sqli'))


class TestCommandInjection(unittest.TestCase):
    """Command Injection detection tests"""
    
    def test_subprocess_shell_true(self):
        code = 'subprocess.call(cmd, shell=True)'
        issues = analyze_code(code)
        self.assertTrue(has_rule(issues, 'subprocess'))
    
    def test_os_system(self):
        code = 'os.system("ls " + path)'
        issues = analyze_code(code)
        self.assertTrue(has_rule(issues, 'system'))
    
    def test_safe_subprocess(self):
        code = 'subprocess.run(["ls", "-la"], shell=False)'
        issues = analyze_code(code)
        self.assertFalse(has_rule(issues, 'dangerous-subprocess'))


class TestDeserialization(unittest.TestCase):
    """Deserialization detection tests"""
    
    def test_pickle_loads(self):
        code = 'data = pickle.loads(user_data)'
        issues = analyze_code(code)
        self.assertTrue(has_rule(issues, 'pickle'))
    
    def test_yaml_load_unsafe(self):
        code = 'yaml.load(data, Loader=yaml.Loader)'
        issues = analyze_code(code)
        self.assertTrue(has_rule(issues, 'yaml'))
    
    def test_yaml_safe_load(self):
        code = 'yaml.safe_load(data)'
        issues = analyze_code(code)
        self.assertFalse(has_rule(issues, 'yaml'))


class TestCryptography(unittest.TestCase):
    """Cryptography weakness detection tests"""
    
    def test_md5_hash(self):
        code = 'hashlib.md5(data)'
        issues = analyze_code(code)
        self.assertTrue(has_rule(issues, 'md5'))
    
    def test_sha1_hash(self):
        code = 'hashlib.sha1(data)'
        issues = analyze_code(code)
        self.assertTrue(has_rule(issues, 'sha1'))
    
    def test_insecure_random(self):
        code = 'token = random.randint(0, 1000000)'
        issues = analyze_code(code)
        self.assertTrue(has_rule(issues, 'random'))


class TestSecrets(unittest.TestCase):
    """Hardcoded secrets detection tests"""
    
    def test_aws_access_key(self):
        code = 'aws_key = "AKIAFAKEACCESSKEYID00"'
        issues = analyze_code(code)
        self.assertTrue(has_rule(issues, 'aws'))
    
    def test_github_token(self):
        code = 'token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"'
        issues = analyze_code(code)
        self.assertTrue(has_rule(issues, 'github'))
    
    def test_stripe_key(self):
        code = 'key = "stripe_test_FAKEFAKEFAKEFAKEFAKE1234"'
        issues = analyze_code(code)
        self.assertTrue(has_rule(issues, 'stripe'))
    
    def test_private_key(self):
        code = 'key = "-----BEGIN RSA PRIVATE KEY-----"'
        issues = analyze_code(code)
        self.assertTrue(has_rule(issues, 'private-key'))


class TestXSS(unittest.TestCase):
    """XSS detection tests (JavaScript)"""
    
    def test_innerhtml(self):
        code = 'element.innerHTML = userInput;'
        issues = analyze_code(code, '.js')
        self.assertTrue(has_rule(issues, 'innerHTML'))
    
    def test_document_write(self):
        code = 'document.write(data);'
        issues = analyze_code(code, '.js')
        self.assertTrue(has_rule(issues, 'document-write'))
    
    def test_eval(self):
        code = 'eval(userCode);'
        issues = analyze_code(code, '.js')
        self.assertTrue(has_rule(issues, 'eval'))


class TestSSL(unittest.TestCase):
    """SSL/TLS security tests"""
    
    def test_verify_false(self):
        code = 'requests.get(url, verify=False)'
        issues = analyze_code(code)
        self.assertTrue(has_rule(issues, 'ssl') or has_rule(issues, 'verify'))


class TestEdgeCases(unittest.TestCase):
    """Edge cases and error handling"""
    
    def test_empty_file(self):
        issues = analyze_code('')
        self.assertEqual(issues, [])
    
    def test_nonexistent_file(self):
        result = analyze_file('/nonexistent/path.py')
        self.assertIn('error', result)
    
    def test_issue_structure(self):
        code = 'eval(user_input)'
        issues = analyze_code(code)
        self.assertTrue(len(issues) > 0)
        issue = issues[0]
        self.assertIn('ruleId', issue)
        self.assertIn('message', issue)
        self.assertIn('line', issue)
        self.assertIn('severity', issue)
        self.assertIn('metadata', issue)


# ============================================================================
# VULNERABLE CODE SAMPLES (for manual testing / demo)
# ============================================================================

PYTHON_SAMPLES = '''
# SQL Injection
user_id = "123"
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
db.execute(f"SELECT * FROM users WHERE id = {user_id}")
User.objects.raw(f"SELECT * FROM users WHERE id = {user_id}")

# Command Injection
subprocess.call(user_input, shell=True)
subprocess.run(f"ls {directory}", shell=True)
os.system("rm -rf " + user_path)

# Code Injection
eval(user_input)
exec(user_code)

# Deserialization
pickle.loads(untrusted_data)
yaml.load(user_data)
yaml.load(data, Loader=yaml.UnsafeLoader)
marshal.loads(data)

# Weak Cryptography
hashlib.md5(data)
hashlib.sha1(data)
DES.new(key)
random.randint(0, 100)
RSA.generate(1024)

# Path Traversal
open("/var/data/" + user_filename, "r")
Path("/data/" + user_input)

# SSRF
requests.get("http://api.example.com/" + endpoint)
requests.post(f"http://internal/{user_url}")
urllib.request.urlopen("http://internal/" + path)

# XXE
ET.parse(user_file)
ET.fromstring(user_xml)

# JWT Issues
jwt.decode(token, verify=False)
jwt.encode(payload, "hardcoded_secret_key", algorithm="HS256")

# SSL Issues
requests.get(url, verify=False)
ssl._create_unverified_context()

# Template Injection
Environment(autoescape=False)

# Django Issues
DEBUG = True
SECRET_KEY = "django-insecure-12345678901234567890"

# Flask Issues
app.run(debug=True)
app.secret_key = "my_secret_key_12345"

# Hardcoded Credentials
password = "mysecretpassword123"
api_key = "stripe_test_FAKEFAKEFAKEFAKE1234"

# Logging Sensitive Data
logging.info(f"User password: {password}")
'''

JAVASCRIPT_SAMPLES = '''
// XSS
element.innerHTML = userInput;
document.write(data);
element.insertAdjacentHTML('beforeend', userHtml);

// Code Injection
eval(userCode);
new Function(userCode);
setTimeout("alert(" + msg + ")", 100);

// Command Injection
exec(cmd + userInput);
spawn("cmd", {shell: true});

// SQL Injection
db.query("SELECT * FROM users WHERE id = " + id);
sequelize.query(`SELECT * FROM users WHERE name = '${name}'`);

// NoSQL Injection
collection.find({$where: userFunc});

// Path Traversal
fs.readFile("./uploads/" + filename);
path.join(baseDir, req.params.file);

// SSRF
fetch(userUrl);
axios.get(`http://internal/${endpoint}`);

// Prototype Pollution
obj[key] = value;
Object.assign({}, req.body);

// Hardcoded Secrets
const apiKey = "stripe_test_FAKEFAKEFAKEFAKE1234";
const password = "admin123456";

// JWT Issues
jwt.sign(payload, "hardcoded_secret");

// SSL Issues
rejectUnauthorized: false

// Weak Crypto
crypto.createHash('md5');
Math.random();
'''

SECRET_SAMPLES = '''
# AWS
AKIAFAKEACCESSKEYID00
aws_secret_access_key = "fakesecretkeyFAKE00000000000000000000"

# GitHub
ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
github_pat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Stripe
stripe_test_FAKEFAKEFAKEFAKEFAKEFAKE00

# OpenAI
sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Slack
xoxb-FAKE-FAKE-FAKE-FAKEFAKEFAKEFAKE
https://hooks.slack.example.com/services/TFAKE0000/BFAKE0000/FAKEFAKEFAKE

# Private Keys
-----BEGIN RSA PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----

# Database URLs
postgres://user:password123@localhost:5432/mydb
mongodb://admin:secretpass@mongodb.example.com:27017/db
'''


if __name__ == '__main__':
    # Run unit tests
    unittest.main(verbosity=2)


# True positive: Django raw query
User.objects.raw(f"SELECT * FROM users WHERE id = {user_id}")

# ============================================================================
# 2. COMMAND INJECTION (python.lang.security.audit.dangerous-subprocess-use)
# ============================================================================

# True positive: subprocess with shell=True
subprocess.call(user_input, shell=True)
subprocess.run(f"ls {directory}", shell=True)
subprocess.Popen(command, shell=True)
subprocess.check_output(cmd, shell=True)

# True positive: os.system
os.system("rm -rf " + user_path)
os.popen(user_command)

# ============================================================================
# 3. CODE INJECTION (python.lang.security.audit.eval-detected)
# ============================================================================

# True positive: eval
eval(user_input)
result = eval("print('hello')")

# True positive: exec
exec(user_code)
exec("import os; os.system('ls')")

# ============================================================================
# 4. DESERIALIZATION (python.lang.security.deserialization.*)
# ============================================================================

# True positive: pickle
import pickle
data = pickle.loads(untrusted_data)
pickle.load(open("data.pkl", "rb"))

# True positive: yaml.load without safe loader
import yaml
yaml.load(user_data)
yaml.load(data, Loader=yaml.Loader)
yaml.load(data, Loader=yaml.UnsafeLoader)
yaml.unsafe_load(data)

# True positive: marshal
import marshal
marshal.loads(data)

# True positive: shelve
import shelve
db = shelve.open("data.db")

# ============================================================================
# 5. CRYPTOGRAPHY (python.lang.security.crypto.*)
# ============================================================================

# True positive: MD5
import hashlib
hashlib.md5(data)
MD5.new(data)

# True positive: SHA1
hashlib.sha1(data)
SHA1.new(data)

# True positive: DES
from Crypto.Cipher import DES
DES.new(key)
DES3.new(key)

# True positive: Insecure random
import random
random.random()
random.randint(0, 100)
token = random.choice(chars)

# True positive: Weak RSA key
from Crypto.PublicKey import RSA
RSA.generate(1024)

# ============================================================================
# 6. PATH TRAVERSAL (python.lang.security.audit.path-traversal-open)
# ============================================================================

# True positive: open with concatenation
file = open("/var/data/" + user_filename, "r")
file = open(f"/uploads/{filename}", "rb")

# True positive: pathlib
from pathlib import Path
path = Path("/data/" + user_input)

# ============================================================================
# 7. SSRF (python.lang.security.audit.ssrf-requests)
# ============================================================================

# True positive: requests with user input
import requests
requests.get("http://api.example.com/" + endpoint)
requests.post(f"http://internal/{user_url}")
requests.get(user_provided_url)

# True positive: urllib
import urllib.request
urllib.request.urlopen("http://internal/" + path)

# ============================================================================
# 8. XXE (python.lang.security.xxe.*)
# ============================================================================

# True positive: xml.etree
import xml.etree.ElementTree as ET
ET.parse(user_file)
ET.fromstring(user_xml)

# True positive: lxml
from lxml import etree
etree.parse(user_file, parser=XMLParser(resolve_entities=True))

# ============================================================================
# 9. JWT SECURITY (python.lang.security.jwt.*)
# ============================================================================

# True positive: JWT decode without verification
import jwt
jwt.decode(token, verify=False)
jwt.decode(token, options={'verify_signature': False})

# True positive: Hardcoded JWT secret
jwt.encode(payload, "super_secret_key_12345", algorithm="HS256")
jwt.decode(token, "my_hardcoded_secret", algorithms=["HS256"])

# ============================================================================
# 10. SSL/TLS (python.lang.security.ssl.*)
# ============================================================================

# True positive: SSL verification disabled
requests.get(url, verify=False)
ssl._create_unverified_context()
context.check_hostname = False

# ============================================================================
# 11. TEMPLATE INJECTION (python.lang.security.audit.jinja2-autoescape-disabled)
# ============================================================================

# True positive: Jinja2 autoescape disabled
from jinja2 import Environment
env = Environment(autoescape=False)
Template(template_string, autoescape=False)

# ============================================================================
# 12. DJANGO SPECIFIC (python.django.security.*)
# ============================================================================

# True positive: CSRF exempt
from django.views.decorators.csrf import csrf_exempt
@csrf_exempt
def my_view(request):
    pass

# True positive: DEBUG enabled
DEBUG = True

# True positive: Hardcoded SECRET_KEY
SECRET_KEY = "django-insecure-12345678901234567890"

# ============================================================================
# 13. FLASK SPECIFIC (python.flask.security.*)
# ============================================================================

# True positive: Flask debug mode
app.run(debug=True)

# True positive: Flask secret key
app.secret_key = "my_secret_key_12345"

# ============================================================================
# 14. HARDCODED CREDENTIALS (python.lang.security.audit.hardcoded-*)
# ============================================================================

# True positive: Hardcoded passwords
password = "mysecretpassword123"
db_password = "admin1234"
api_key = "stripe_test_FAKEFAKEFAKEFAKE1234"
secret_key = "ghp_1234567890abcdefghijklmnopqrstuvwx"

# ============================================================================
# 15. LOGGING SENSITIVE DATA (python.lang.security.audit.logging-sensitive-data)
# ============================================================================

# True positive: Logging passwords
import logging
logging.info(f"User password: {password}")
logger.debug(f"Secret key: {secret}")
print(f"Token: {token}")

# ============================================================================
# 16. REGEX DOS (python.lang.security.audit.regex-dos)
# ============================================================================

# True positive: Potentially vulnerable regex
import re
re.compile(r"(a+)+b")
re.match(r"(x*)*y", user_input)

# ============================================================================
# JAVASCRIPT EXAMPLES (for reference)
# ============================================================================

# The following would be in .js files:
# innerHTML = userInput
# document.write(data)
# eval(userCode)
# exec(cmd + userInput)
# new Function(userCode)

# ============================================================================
# GENERIC SECRET PATTERNS
# ============================================================================

# AWS
aws_key = "AKIAFAKEACCESSKEYID00"
aws_secret = "fakesecretkeyFAKE00000000000000000000"

# GitHub
github_token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
github_pat = "github_pat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Stripe
stripe_key = "stripe_test_FAKEFAKEFAKEFAKEFAKEFAKE00"

# OpenAI
openai_key = "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Slack
slack_token = "xoxb-FAKE-FAKE-FAKE-FAKEFAKEFAKEFAKE"
slack_webhook = "https://hooks.slack.example.com/services/TFAKE0000/BFAKE0000/FAKEFAKEFAKE"

# Private keys
private_key = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----
"""

# Database URLs
db_url = "postgres://user:password123@localhost:5432/mydb"
mongo_url = "mongodb://admin:secretpass@mongodb.example.com:27017/db"

# ============================================================================
# MAIN TEST RUNNER
# ============================================================================

if __name__ == "__main__":
    print("This file contains security anti-patterns for testing purposes.")
    print("Do NOT use these patterns in production code!")
    print()
    print("Run the analyzer against this file to verify rule detection:")
    print("  python analyzer.py test_semgrep_rules.py")
