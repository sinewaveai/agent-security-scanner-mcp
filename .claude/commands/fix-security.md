# Fix Security Issues

Analyze the current file for security vulnerabilities detected by the Agent Security extension and automatically apply fixes.

## Instructions

1. First, get all diagnostics for the current file using the IDE diagnostics tool
2. Filter for diagnostics where `source` is "Agent Security"
3. For each security issue found, analyze the code and apply the appropriate fix based on the rule ID

## Fix Strategies by Rule Type

### SQL Injection (sql-injection, sqli)
- Convert string concatenation to parameterized queries
- Replace f-strings/template literals with placeholders
- Use prepared statements

### XSS (innerHTML, outerHTML, dangerouslySetInnerHTML)
- Replace `.innerHTML` with `.textContent` for plain text
- Add DOMPurify.sanitize() wrapper for HTML content
- Use safe DOM methods like createElement/appendChild

### Command Injection (exec, subprocess, shell=True)
- Replace `exec()` with `execFile()` or `spawn()`
- Change `shell=True` to `shell=False`
- Split command strings into argument arrays

### Hardcoded Secrets (password, api_key, secret)
- Replace hardcoded values with environment variables
- Use `process.env.VAR_NAME` (JS) or `os.environ.get('VAR_NAME')` (Python)

### Weak Cryptography (md5, sha1)
- Replace MD5/SHA1 with SHA-256 or stronger
- Use `hashlib.sha256()` (Python) or `crypto.createHash('sha256')` (JS)

### Insecure Deserialization (pickle, yaml.load)
- Replace `pickle.load` with `json.load`
- Replace `yaml.load()` with `yaml.safe_load()`

### SSL/TLS Issues (verify=False, rejectUnauthorized)
- Set `verify=True` or remove the insecure option
- Enable certificate verification

## Task

Read the current file, identify all security issues from the Agent Security extension diagnostics, and apply fixes directly to the code. After fixing, briefly explain what was changed.

$ARGUMENTS
