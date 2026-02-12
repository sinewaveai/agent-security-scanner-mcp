"""Benchmark corpus: Python cryptographic vulnerabilities."""
import hashlib
import random
import os

# --- Weak Hashing ---

# VULN: insecure-hash-md5
digest = hashlib.md5(data).hexdigest()

# VULN: insecure-hash-sha1
digest = hashlib.sha1(data).hexdigest()

# SAFE: insecure-hash-md5
digest = hashlib.sha256(data).hexdigest()

# SAFE: insecure-hash-sha1
digest = hashlib.sha512(data).hexdigest()

# FP-PRONE: insecure-hash-md5 (checksum, not security)
checksum = hashlib.md5(file_bytes).hexdigest()

# --- Insecure Randomness ---

# VULN: insecure-random
token = random.randint(100000, 999999)

# VULN: insecure-random
session_id = random.random()

# SAFE: insecure-random
token = os.urandom(32).hex()

# --- SSL Verification ---

import requests

# VULN: ssl-verify-disabled
response = requests.get(url, verify=False)

# SAFE: ssl-verify-disabled
response = requests.get(url, verify=True)

# --- Hardcoded Secrets ---

# VULN: python.lang.security.audit.hardcoded-password
# VULN: generic.secrets.security.hardcoded-password
db_password = "super_secret_password_123"

# SAFE: hardcoded-password
db_password = os.environ.get("DB_PASSWORD")

# VULN: python.lang.security.audit.hardcoded-api-key
# VULN: generic.secrets.security.hardcoded-api-key
api_key = "stripe_test_FAKEFAKEFAKEFAKE1234"

# SAFE: hardcoded-api-key
api_key = os.environ.get("API_KEY")
