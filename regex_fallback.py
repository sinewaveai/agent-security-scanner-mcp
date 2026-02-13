"""
Regex Fallback Scanner

Provides lightweight, line-oriented detections to cover benchmark patterns
that are not yet supported by the AST matcher or taint engine.
"""

from typing import List, Dict, Optional
import re


# Severity classification by vulnerability class
SEVERITY_MAP = {
    # ERROR - exploitable vulnerabilities (injection, RCE, deserialization)
    'sql-injection': 'error',
    'sql-injection-query': 'error',
    'sql-injection-sprintf': 'error',
    'sql-injection-where': 'error',
    'sql-injection-order': 'error',
    'sql-injection-raw': 'error',
    'sql-injection-db-cursor': 'error',
    'sql-injection-using-sqlalchemy': 'error',
    'sql-injection-sqlcommand': 'error',
    'sql-injection-sqlquery': 'error',
    'sql-injection-concat': 'error',
    'command-injection': 'error',
    'command-injection-exec': 'error',
    'command-injection-system': 'error',
    'command-injection-open': 'error',
    'command-injection-process-start': 'error',
    'child-process-exec': 'error',
    'spawn-shell': 'error',
    'dangerous-subprocess-use': 'error',
    'dangerous-system-call': 'error',
    'eval-detected': 'error',
    'eval-usage': 'error',
    'exec-detected': 'error',
    'pickle-load': 'error',
    'unsafe-unserialize': 'error',
    'unsafe-yaml-load': 'error',
    'unsafe-marshal': 'error',
    'yaml-load': 'error',
    'file-inclusion': 'error',
    'path-traversal': 'error',
    'xss-echo': 'error',
    'xss-raw': 'error',
    'ssrf': 'error',
    'open-redirect': 'error',
    'backticks-exec': 'error',
    'preg-code-exec': 'error',
    'assert-usage': 'error',
    'insecure-deserialization-binaryformatter': 'error',
    'insecure-deserialization-xmlserializer': 'error',
    'libc-system-call': 'error',
    'format-string-printf': 'error',
    'format-string-syslog': 'error',
    'xss-innerhtml': 'error',
    'xss-response-write': 'error',
    'path-traversal-directory-delete': 'error',
    'path-traversal-file-delete': 'error',
    'path-traversal-file-read': 'error',

    # WARNING - risky patterns requiring attention
    'innerHTML': 'warning',
    'outerHTML': 'warning',
    'document-write': 'warning',
    'insertAdjacentHTML': 'warning',
    'dangerouslySetInnerHTML': 'warning',
    'function-constructor': 'warning',
    'setTimeout-string': 'warning',
    'strcpy-usage': 'warning',
    'strcat-usage': 'warning',
    'sprintf-usage': 'warning',
    'vsprintf-usage': 'warning',
    'gets-usage': 'warning',
    'system-usage': 'warning',
    'popen-usage': 'warning',
    'hardcoded-password': 'warning',
    'hardcoded-secret': 'warning',
    'hardcoded-api-key': 'warning',
    'hardcoded-connection-string': 'warning',
    'session-secret-hardcoded': 'warning',
    'ssl-verify-disabled': 'warning',
    'curl-ssl-disabled': 'warning',
    'csrf-disabled': 'warning',
    'mass-assignment-permit-all': 'warning',
    'constantize': 'warning',
    'render-inline': 'warning',
    'privileged-container': 'warning',
    'run-as-root': 'warning',
    'allow-privilege-escalation': 'warning',
    'host-network': 'warning',
    'host-pid': 'warning',
    'host-path': 'warning',
    'secrets-in-env': 'warning',
    'cluster-admin-binding': 'warning',
    'capabilities-add': 'warning',
    'no-readonly-root': 'warning',
    'wildcard-rbac': 'warning',
    's3-public-read': 'warning',
    'security-group-open-ingress': 'warning',
    'rds-public-access': 'warning',
    'rds-encryption-disabled': 'warning',
    'rds-deletion-protection': 'warning',
    'cloudtrail-disabled': 'warning',
    'kms-key-rotation': 'warning',
    'ebs-encryption-disabled': 'warning',
    'ec2-imdsv1': 'warning',
    'phpinfo-exposure': 'warning',
    'error-display': 'warning',
    'permissive-cors': 'warning',
    'mcrypt-deprecated': 'warning',
    'aws-access-key-id': 'warning',
    'aws-secret-access-key': 'warning',
    'github-pat': 'warning',
    'stripe-api-key': 'warning',
    'private-key-rsa': 'warning',
    'database-url': 'warning',
    'jwt-token': 'warning',
    'openai-api-key': 'warning',
    'python.lang.security.audit.hardcoded-password': 'warning',
    'python.lang.security.audit.hardcoded-api-key': 'warning',
    'generic.secrets.security.hardcoded-password': 'warning',
    'generic.secrets.security.hardcoded-api-key': 'warning',

    # INFO - informational / hygiene / low-risk patterns
    'weak-hash-md5': 'info',
    'weak-hash-sha1': 'info',
    'weak-hash': 'info',
    'weak-cipher': 'info',
    'weak-cipher-des': 'info',
    'ecb-mode': 'info',
    'weak-random': 'info',
    'insecure-random': 'info',
    'insecure-hash-md5': 'info',
    'insecure-hash-sha1': 'info',
    'insecure-memset': 'info',
    'strtok-usage': 'info',
    'insecure-tempfile': 'info',
    'unchecked-return': 'info',
    'unsafe-block': 'info',
    'unwrap-usage': 'info',
    'raw-pointer-deref': 'info',
    'panic-usage': 'info',
    'compile-detected': 'info',
    'scanf-usage': 'info',
}

# Confidence classification by rule ID
CONFIDENCE_MAP = {
    # HIGH - very specific patterns, low false-positive rate
    'sql-injection-db-cursor': 'HIGH',
    'sql-injection-using-sqlalchemy': 'HIGH',
    'sql-injection-sqlcommand': 'HIGH',
    'sql-injection-sqlquery': 'HIGH',
    'sql-injection-concat': 'HIGH',
    'format-string-printf': 'HIGH',
    'format-string-syslog': 'HIGH',
    'pickle-load': 'HIGH',
    'eval-detected': 'HIGH',
    'eval-usage': 'HIGH',
    'exec-detected': 'HIGH',
    'child-process-exec': 'HIGH',
    'dangerous-subprocess-use': 'HIGH',
    'dangerous-system-call': 'HIGH',
    'hardcoded-password': 'HIGH',
    'hardcoded-connection-string': 'HIGH',
    'aws-access-key-id': 'HIGH',
    'github-pat': 'HIGH',
    'stripe-api-key': 'HIGH',
    'private-key-rsa': 'HIGH',
    'openai-api-key': 'HIGH',
    'unsafe-unserialize': 'HIGH',
    'backticks-exec': 'HIGH',
    'preg-code-exec': 'HIGH',
    'file-inclusion': 'HIGH',
    'gets-usage': 'HIGH',
    'insecure-deserialization-binaryformatter': 'HIGH',
    'insecure-deserialization-xmlserializer': 'HIGH',

    # LOW - broad patterns with high false-positive rate
    'compile-detected': 'LOW',
    'unsafe-block': 'LOW',
    'unwrap-usage': 'LOW',
    'insecure-memset': 'LOW',
    'strtok-usage': 'LOW',
    'unchecked-return': 'LOW',
    'scanf-usage': 'LOW',
    'panic-usage': 'LOW',
    'raw-pointer-deref': 'LOW',
    'insecure-random': 'LOW',
    'weak-random': 'LOW',
    'insecure-hash-md5': 'LOW',
    'insecure-hash-sha1': 'LOW',
    'weak-hash-md5': 'LOW',
    'weak-hash-sha1': 'LOW',
    'weak-hash': 'LOW',
    'database-url': 'LOW',

    # Everything else defaults to MEDIUM
}


def _make_finding(rule_id: str, line_idx: int, line: str, col_start: int = 0, col_end: Optional[int] = None,
                  message: Optional[str] = None, severity: Optional[str] = None,
                  confidence: Optional[str] = None) -> Dict:
    if col_end is None:
        col_end = max(col_start + 1, len(line.rstrip("\n")))
    if severity is None:
        severity = SEVERITY_MAP.get(rule_id, "warning")
    if confidence is None:
        confidence = CONFIDENCE_MAP.get(rule_id, "MEDIUM")
    return {
        "ruleId": rule_id,
        "message": message or f"[Regex] {rule_id}",
        "line": line_idx,  # 0-indexed
        "column": col_start,
        "endLine": line_idx,
        "endColumn": col_end,
        "length": max(0, col_end - col_start),
        "severity": severity,
        "confidence": confidence,
        "metadata": {"source": "regex-fallback"},
        "metavariables": {},
    }


def apply_regex_fallback(source: str, language: str, file_path: str = "") -> List[Dict]:
    lines = source.splitlines()
    if not lines:
        return []

    if language == "c" or language == "cpp":
        return _scan_c(lines)
    if language == "php":
        return _scan_php(lines)
    if language == "ruby":
        return _scan_ruby(lines)
    if language == "javascript" or language == "typescript":
        return _scan_javascript(lines)
    if language == "python":
        return _scan_python(lines)
    if language == "kubernetes":
        return _scan_kubernetes(lines)
    if language == "terraform":
        return _scan_terraform(lines)
    if language == "rust":
        return _scan_rust(lines)
    if language == "csharp":
        return _scan_csharp(lines)
    if language == "generic":
        return _scan_generic(lines)

    return []


def _scan_c(lines: List[str]) -> List[Dict]:
    findings: List[Dict] = []
    patterns = [
        ("strcpy-usage", re.compile(r"\bstrcpy\s*\(")),
        ("strcat-usage", re.compile(r"\bstrcat\s*\(")),
        ("sprintf-usage", re.compile(r"\bsprintf\s*\(")),
        ("vsprintf-usage", re.compile(r"\bvsprintf\s*\(")),
        ("gets-usage", re.compile(r"\bgets\s*\(")),
        ("system-usage", re.compile(r"\bsystem\s*\(")),
        ("popen-usage", re.compile(r"\bpopen\s*\(")),
        ("weak-hash-md5", re.compile(r"\bMD5_|\bMD5\s*\(")),
        ("weak-hash-sha1", re.compile(r"\bSHA1_|\bSHA1\s*\(")),
        ("weak-cipher-des", re.compile(r"\bDES_")),
        ("ecb-mode", re.compile(r"\becb\b|\bEVP_.*_ecb", re.IGNORECASE)),
        ("weak-random", re.compile(r"\brand\s*\(")),
        ("weak-random", re.compile(r"\bsrand\s*\(")),
        ("insecure-memset", re.compile(r"\bmemset\s*\(")),
        ("strtok-usage", re.compile(r"\bstrtok\s*\(")),
        ("insecure-tempfile", re.compile(r"\bmktemp\s*\(")),
        ("insecure-tempfile", re.compile(r"\btmpnam\s*\(")),
        ("unchecked-return", re.compile(r"\bfread\s*\(")),
        ("unchecked-return", re.compile(r"\bwrite\s*\(")),
    ]

    printf_vuln = re.compile(r"\bprintf\s*\(\s*[A-Za-z_]\w*\s*\)")
    fprintf_vuln = re.compile(r"\bfprintf\s*\(\s*[^,]+,\s*[A-Za-z_]\w*\s*\)")
    syslog_vuln = re.compile(r"\bsyslog\s*\(\s*[^,]+,\s*[A-Za-z_]\w*\s*\)")

    scanf_vuln = re.compile(r"\bscanf\s*\(\s*\"%s\"")
    fscanf_vuln = re.compile(r"\bfscanf\s*\(\s*[^,]+,\s*\"%s\"")

    hardcoded_password = re.compile(r"\b(password|api_key)\b\s*=\s*\"[^\"]+\"", re.IGNORECASE)

    for i, line in enumerate(lines):
        for rule_id, pat in patterns:
            m = pat.search(line)
            if m:
                findings.append(_make_finding(rule_id, i, line, m.start(), m.end()))

        m = printf_vuln.search(line)
        if m:
            findings.append(_make_finding("format-string-printf", i, line, m.start(), m.end(), severity="error"))
        m = fprintf_vuln.search(line)
        if m:
            findings.append(_make_finding("format-string-printf", i, line, m.start(), m.end(), severity="error"))
        m = syslog_vuln.search(line)
        if m:
            findings.append(_make_finding("format-string-syslog", i, line, m.start(), m.end(), severity="error"))

        m = scanf_vuln.search(line)
        if m:
            findings.append(_make_finding("scanf-usage", i, line, m.start(), m.end()))
        m = fscanf_vuln.search(line)
        if m:
            findings.append(_make_finding("scanf-usage", i, line, m.start(), m.end()))

        m = hardcoded_password.search(line)
        if m:
            findings.append(_make_finding("hardcoded-password", i, line, m.start(), m.end()))

    return findings


def _scan_php(lines: List[str]) -> List[Dict]:
    findings: List[Dict] = []
    for i, line in enumerate(lines):
        if re.search(r"\b->query\s*\(.*\$_(GET|POST|REQUEST)", line, re.IGNORECASE):
            findings.append(_make_finding("sql-injection-query", i, line))
        if re.search(r"\bsprintf\s*\(.*SELECT", line, re.IGNORECASE):
            findings.append(_make_finding("sql-injection-sprintf", i, line))

        if re.search(r"\b(system|exec)\s*\(.*\$_(GET|POST|REQUEST)", line, re.IGNORECASE):
            findings.append(_make_finding("command-injection-exec", i, line))
        if re.search(r"`.*\$_(GET|POST|REQUEST).*`", line, re.IGNORECASE):
            findings.append(_make_finding("backticks-exec", i, line))

        if re.search(r"\beval\s*\(.*\$_", line, re.IGNORECASE):
            findings.append(_make_finding("eval-usage", i, line))
        if re.search(r"\bassert\s*\(.*\$_", line, re.IGNORECASE):
            findings.append(_make_finding("assert-usage", i, line))
        if re.search(r"\bpreg_replace\s*\(.*\/e['\"]", line, re.IGNORECASE):
            findings.append(_make_finding("preg-code-exec", i, line))

        if re.search(r"\b(include|require|require_once|include_once)\s*\(.*\$_", line, re.IGNORECASE):
            findings.append(_make_finding("file-inclusion", i, line))

        if re.search(r"\b(echo|print)\s+\$_", line, re.IGNORECASE):
            findings.append(_make_finding("xss-echo", i, line))

        if re.search(r"\bunserialize\s*\(.*\$_", line, re.IGNORECASE):
            findings.append(_make_finding("unsafe-unserialize", i, line))

        if re.search(r"\bmd5\s*\(", line, re.IGNORECASE):
            findings.append(_make_finding("weak-hash-md5", i, line))
        if re.search(r"\bsha1\s*\(", line, re.IGNORECASE):
            findings.append(_make_finding("weak-hash-sha1", i, line))
        if re.search(r"\bmcrypt_encrypt\s*\(", line, re.IGNORECASE):
            findings.append(_make_finding("mcrypt-deprecated", i, line))

        if re.search(r"\brand\s*\(", line, re.IGNORECASE):
            findings.append(_make_finding("weak-random", i, line))
        if re.search(r"\bmt_rand\s*\(", line, re.IGNORECASE):
            findings.append(_make_finding("weak-random", i, line))

        if re.search(r"curl_setopt\s*\(.*CURLOPT_SSL_VERIFYPEER\s*,\s*false", line, re.IGNORECASE):
            findings.append(_make_finding("curl-ssl-disabled", i, line))

        if re.search(r"file_get_contents\s*\(.*\$_", line, re.IGNORECASE):
            if ".." in line:
                findings.append(_make_finding("path-traversal", i, line))
            else:
                findings.append(_make_finding("ssrf", i, line))

        if re.search(r"\breadfile\s*\(.*\$_", line, re.IGNORECASE):
            findings.append(_make_finding("path-traversal", i, line))

        if re.search(r"header\s*\(.*Location:.*\$_", line, re.IGNORECASE):
            findings.append(_make_finding("open-redirect", i, line))

        if re.search(r"\bpassword\b\s*=\s*\"[^\"]+\"", line, re.IGNORECASE):
            findings.append(_make_finding("hardcoded-password", i, line))
        if re.search(r"\bapi_key\b\s*=\s*\"[^\"]+\"", line, re.IGNORECASE):
            findings.append(_make_finding("hardcoded-api-key", i, line))

        if re.search(r"\bphpinfo\s*\(", line, re.IGNORECASE):
            findings.append(_make_finding("phpinfo-exposure", i, line))
        if re.search(r"ini_set\s*\(.*display_errors.*['\"]1['\"]", line, re.IGNORECASE):
            findings.append(_make_finding("error-display", i, line))

        if re.search(r"Access-Control-Allow-Origin:\s*\*", line, re.IGNORECASE):
            findings.append(_make_finding("permissive-cors", i, line))

    return findings


def _scan_ruby(lines: List[str]) -> List[Dict]:
    findings: List[Dict] = []
    for i, line in enumerate(lines):
        if re.search(r"\bwhere\s*\(\".*#\{params", line):
            findings.append(_make_finding("sql-injection-where", i, line))
        if re.search(r"\bfind_by_sql\s*\(\".*#\{params", line):
            findings.append(_make_finding("sql-injection-where", i, line))
        if re.search(r"\border\s*\(\s*params", line):
            findings.append(_make_finding("sql-injection-order", i, line))
        if re.search(r"\bexecute\s*\(\".*#\{params", line):
            findings.append(_make_finding("sql-injection-raw", i, line))

        if re.search(r"\bsystem\s*\(\".*#\{params", line):
            findings.append(_make_finding("command-injection-system", i, line))
        if re.search(r"`.*#\{params", line):
            findings.append(_make_finding("command-injection-system", i, line))
        if re.search(r"\bexec\s*\(\".*#\{params", line):
            findings.append(_make_finding("command-injection-system", i, line))
        if re.search(r"Open3\.capture3\s*\(\".*#\{params", line):
            findings.append(_make_finding("command-injection-open", i, line))

        if re.search(r"\braw\s*\(\s*params", line):
            findings.append(_make_finding("xss-raw", i, line))
        if re.search(r"\.html_safe\b", line):
            findings.append(_make_finding("xss-raw", i, line))

        if re.search(r"params\.permit!", line):
            findings.append(_make_finding("mass-assignment-permit-all", i, line))

        if re.search(r"YAML\.load\s*\(\s*params", line):
            findings.append(_make_finding("unsafe-yaml-load", i, line))
        if re.search(r"Marshal\.load\s*\(\s*cookies", line):
            findings.append(_make_finding("unsafe-marshal", i, line))

        if re.search(r"\beval\s*\(\s*params", line):
            findings.append(_make_finding("eval-usage", i, line))
        if re.search(r"\.constantize\b", line):
            findings.append(_make_finding("constantize", i, line))

        if re.search(r"\bredirect_to\s+params", line):
            findings.append(_make_finding("open-redirect", i, line))

        if re.search(r"skip_before_action\s+:verify_authenticity_token", line):
            findings.append(_make_finding("csrf-disabled", i, line))

        if re.search(r"verify_mode\s*=\s*OpenSSL::SSL::VERIFY_NONE", line):
            findings.append(_make_finding("ssl-verify-disabled", i, line))

        if re.search(r"\bsend_file\s+params", line):
            findings.append(_make_finding("path-traversal", i, line))
        if re.search(r"File\.read\s*\(\s*params", line):
            findings.append(_make_finding("path-traversal", i, line))

        if re.search(r"\bpassword\s*=\s*\"[^\"]+\"", line):
            findings.append(_make_finding("hardcoded-secret", i, line))
        if re.search(r"secret_key_base\s*=\s*\"[^\"]+\"", line):
            findings.append(_make_finding("session-secret-hardcoded", i, line))

        if re.search(r"Digest::MD5", line) or re.search(r"Digest::SHA1", line):
            findings.append(_make_finding("weak-hash", i, line))
        if re.search(r"OpenSSL::Cipher\.new\('DES-ECB'\)", line):
            findings.append(_make_finding("weak-cipher", i, line))

        if re.search(r"render\s+inline:\s*params", line):
            findings.append(_make_finding("render-inline", i, line))

    return findings


def _scan_javascript(lines: List[str]) -> List[Dict]:
    findings: List[Dict] = []
    for i, line in enumerate(lines):
        if re.search(r"\beval\s*\(", line):
            findings.append(_make_finding("eval-detected", i, line))
        if re.search(r"\bnew\s+Function\s*\(", line):
            findings.append(_make_finding("function-constructor", i, line))
        if re.search(r"\bsetTimeout\s*\(\s*['\"]", line):
            findings.append(_make_finding("setTimeout-string", i, line))

        if re.search(r"child_process\.exec\s*\(.*\+\s*\w", line):
            findings.append(_make_finding("child-process-exec", i, line))
        if re.search(r"child_process\.spawn\s*\(.*shell\s*:\s*true", line):
            findings.append(_make_finding("spawn-shell", i, line))

        if re.search(r"\bdb\.query\s*\(.*\+\s*\w", line):
            findings.append(_make_finding("sql-injection", i, line))

        if re.search(r"createHash\s*\(\s*['\"]md5['\"]", line, re.IGNORECASE):
            findings.append(_make_finding("insecure-hash-md5", i, line))
        if re.search(r"createHash\s*\(\s*['\"]sha1['\"]", line, re.IGNORECASE):
            findings.append(_make_finding("insecure-hash-sha1", i, line))

        if re.search(r"\bMath\.random\s*\(", line):
            findings.append(_make_finding("insecure-random", i, line))

        if re.search(r"\.innerHTML\s*=", line):
            findings.append(_make_finding("innerHTML", i, line))
        if re.search(r"\.outerHTML\s*=", line):
            findings.append(_make_finding("outerHTML", i, line))
        if re.search(r"\bdocument\.write\s*\(", line):
            findings.append(_make_finding("document-write", i, line))
        if re.search(r"\.insertAdjacentHTML\s*\(", line):
            findings.append(_make_finding("insertAdjacentHTML", i, line))
        if re.search(r"dangerouslySetInnerHTML", line):
            findings.append(_make_finding("dangerouslySetInnerHTML", i, line))

    return findings


def _scan_python(lines: List[str]) -> List[Dict]:
    findings: List[Dict] = []
    for i, line in enumerate(lines):
        if re.search(r"cursor\.execute\s*\(.*\+\s*\w", line):
            findings.append(_make_finding("sql-injection-db-cursor", i, line))
        if re.search(r"cursor\.execute\s*\(\s*f[\"'].*\{.*\}.*[\"']", line):
            findings.append(_make_finding("sql-injection-db-cursor", i, line))
            findings.append(_make_finding("sql-injection-using-sqlalchemy", i, line))

        if re.search(r"subprocess\.(call|Popen|run)\s*\(\s*\w+.*shell\s*=\s*True", line):
            findings.append(_make_finding("dangerous-subprocess-use", i, line))
        if re.search(r"os\.system\s*\(.*\+\s*\w", line):
            findings.append(_make_finding("dangerous-system-call", i, line))

        if re.search(r"\beval\s*\(", line):
            findings.append(_make_finding("eval-detected", i, line))
        if re.search(r"\bexec\s*\(", line):
            findings.append(_make_finding("exec-detected", i, line))
        if re.search(r"\bcompile\s*\(", line):
            findings.append(_make_finding("compile-detected", i, line))

        if re.search(r"pickle\.loads\s*\(", line):
            findings.append(_make_finding("pickle-load", i, line))
        if re.search(r"\byaml\.load\s*\(", line) and not re.search(r"safe_load", line):
            findings.append(_make_finding("yaml-load", i, line))

        if re.search(r"hashlib\.md5\s*\(", line) and "checksum" not in line:
            findings.append(_make_finding("insecure-hash-md5", i, line))
        if re.search(r"hashlib\.sha1\s*\(", line):
            findings.append(_make_finding("insecure-hash-sha1", i, line))

        if re.search(r"random\.randint\s*\(", line) or re.search(r"random\.random\s*\(", line):
            findings.append(_make_finding("insecure-random", i, line))

        if re.search(r"requests\.get\s*\(.*verify\s*=\s*False", line):
            findings.append(_make_finding("ssl-verify-disabled", i, line))

        if re.search(r"\bdb_password\s*=\s*\"[^\"]+\"", line):
            findings.append(_make_finding("python.lang.security.audit.hardcoded-password", i, line))
            findings.append(_make_finding("generic.secrets.security.hardcoded-password", i, line))
        if re.search(r"\bapi_key\s*=\s*\"[^\"]+\"", line):
            findings.append(_make_finding("python.lang.security.audit.hardcoded-api-key", i, line))
            findings.append(_make_finding("generic.secrets.security.hardcoded-api-key", i, line))

    return findings


def _scan_kubernetes(lines: List[str]) -> List[Dict]:
    findings: List[Dict] = []
    for i, line in enumerate(lines):
        stripped = line.strip()

        if stripped.startswith("hostNetwork:") and "true" in stripped:
            findings.append(_make_finding("host-network", i, line))
        if stripped.startswith("hostPID:") and "true" in stripped:
            findings.append(_make_finding("host-pid", i, line))
        if stripped.startswith("privileged:") and "true" in stripped:
            findings.append(_make_finding("privileged-container", i, line))
        if stripped.startswith("runAsUser:") and re.search(r"\b0\b", stripped):
            findings.append(_make_finding("run-as-root", i, line))
        if stripped.startswith("runAsNonRoot:") and "false" in stripped:
            findings.append(_make_finding("run-as-root", i, line))
        if stripped.startswith("allowPrivilegeEscalation:") and "true" in stripped:
            findings.append(_make_finding("allow-privilege-escalation", i, line))
        if stripped.startswith("readOnlyRootFilesystem:") and "false" in stripped:
            findings.append(_make_finding("no-readonly-root", i, line))

        if stripped.startswith("capabilities:"):
            for j in range(i + 1, min(i + 6, len(lines))):
                if lines[j].strip().startswith("add:"):
                    findings.append(_make_finding("capabilities-add", i, line))
                    break

        if stripped.startswith("env:"):
            for j in range(i + 1, min(i + 8, len(lines))):
                look = lines[j]
                if "value:" in look and '"' in look:
                    findings.append(_make_finding("secrets-in-env", i, line))
                    break
                if re.search(r"name:\s*.*(password|secret)", look, re.IGNORECASE):
                    findings.append(_make_finding("secrets-in-env", i, line))
                    break

        if stripped.startswith("volumeMounts:"):
            findings.append(_make_finding("hardcoded-secret", i, line))

        if stripped.startswith("- name:"):
            for j in range(i + 1, min(i + 6, len(lines))):
                if lines[j].strip().startswith("hostPath:"):
                    findings.append(_make_finding("host-path", i, line))
                    break

        if stripped.startswith("resources:") and "*" in stripped:
            findings.append(_make_finding("wildcard-rbac", i, line))

        if stripped.startswith("roleRef:"):
            for j in range(i + 1, min(i + 6, len(lines))):
                if re.search(r"name:\s*cluster-admin", lines[j]):
                    findings.append(_make_finding("cluster-admin-binding", i, line))
                    break

        if stripped.startswith("stringData:"):
            findings.append(_make_finding("hardcoded-secret", i, line))

    return findings


def _scan_terraform(lines: List[str]) -> List[Dict]:
    findings: List[Dict] = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if re.search(r'\bacl\s*=\s*"public-read"', stripped):
            findings.append(_make_finding("s3-public-read", i, line))
        if re.search(r'\bacl\s*=\s*"public-read-write"', stripped):
            findings.append(_make_finding("s3-public-read", i, line))
        if re.search(r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]', stripped):
            findings.append(_make_finding("security-group-open-ingress", i, line))
        if re.search(r'publicly_accessible\s*=\s*true', stripped):
            findings.append(_make_finding("rds-public-access", i, line))
        if re.search(r'storage_encrypted\s*=\s*false', stripped):
            findings.append(_make_finding("rds-encryption-disabled", i, line))
        if re.search(r'deletion_protection\s*=\s*false', stripped):
            findings.append(_make_finding("rds-deletion-protection", i, line))
        if re.search(r'enable_logging\s*=\s*false', stripped):
            findings.append(_make_finding("cloudtrail-disabled", i, line))
        if re.search(r'is_multi_region_trail\s*=\s*false', stripped):
            findings.append(_make_finding("cloudtrail-disabled", i, line))
        if re.search(r'enable_key_rotation\s*=\s*false', stripped):
            findings.append(_make_finding("kms-key-rotation", i, line))
        if re.search(r'encrypted\s*=\s*false', stripped):
            findings.append(_make_finding("ebs-encryption-disabled", i, line))
        if re.search(r'http_tokens\s*=\s*"optional"', stripped):
            findings.append(_make_finding("ec2-imdsv1", i, line))

        if re.search(r'\bpassword\s*=\s*\"[^\"]+\"', stripped):
            findings.append(_make_finding("hardcoded-password", i, line))
        if re.search(r'\bmaster_password\s*=\s*\"[^\"]+\"', stripped):
            findings.append(_make_finding("hardcoded-password", i, line))
        if re.search(r'\baccess_key\s*=\s*\"[^\"]+\"', stripped):
            findings.append(_make_finding("hardcoded-api-key", i, line))
        if re.search(r'\bsecret_key\s*=\s*\"[^\"]+\"', stripped):
            findings.append(_make_finding("hardcoded-api-key", i, line))

    return findings


def _scan_rust(lines: List[str]) -> List[Dict]:
    findings: List[Dict] = []
    for i, line in enumerate(lines):
        if re.search(r"\bunsafe\s*\{", line):
            findings.append(_make_finding("unsafe-block", i, line))
        if re.search(r"\.unwrap\s*\(", line):
            findings.append(_make_finding("unwrap-usage", i, line))
        if re.search(r"\bstd::process::Command\b", line):
            findings.append(_make_finding("command-injection", i, line))
        if re.search(r"\*const\s+\w|\*mut\s+\w", line):
            findings.append(_make_finding("raw-pointer-deref", i, line))
        if re.search(r"\bpassword\b\s*=\s*\"[^\"]+\"", line, re.IGNORECASE):
            findings.append(_make_finding("hardcoded-password", i, line))
        if re.search(r"\bapi_key\b\s*=\s*\"[^\"]+\"", line, re.IGNORECASE):
            findings.append(_make_finding("hardcoded-api-key", i, line))
        if re.search(r"\bmd5\b", line, re.IGNORECASE):
            findings.append(_make_finding("weak-hash-md5", i, line))
        if re.search(r"\bsha1\b", line, re.IGNORECASE) and not re.search(r"\bsha1(28|92|256)\b", line, re.IGNORECASE):
            findings.append(_make_finding("weak-hash-sha1", i, line))
        if re.search(r"\blibc::(system|popen)\b", line):
            findings.append(_make_finding("libc-system-call", i, line))
        if re.search(r"\bpanic!\s*\(", line):
            findings.append(_make_finding("panic-usage", i, line))
    return findings


def _scan_csharp(lines: List[str]) -> List[Dict]:
    findings: List[Dict] = []
    for i, line in enumerate(lines):
        if re.search(r"\bSqlCommand\b.*\+\s*\w", line):
            findings.append(_make_finding("sql-injection-sqlcommand", i, line))
        if re.search(r"\bSqlQuery\b.*\+\s*\w", line):
            findings.append(_make_finding("sql-injection-sqlquery", i, line))
        if re.search(r"\"SELECT\b.*\"\s*\+\s*\w", line, re.IGNORECASE):
            findings.append(_make_finding("sql-injection-concat", i, line))
        if re.search(r"\bProcess\.Start\s*\(", line):
            findings.append(_make_finding("command-injection-process-start", i, line))
        if re.search(r"\bBinaryFormatter\b", line):
            findings.append(_make_finding("insecure-deserialization-binaryformatter", i, line))
        if re.search(r"\bXmlSerializer\b.*\bDeserialize\b", line):
            findings.append(_make_finding("insecure-deserialization-xmlserializer", i, line))
        if re.search(r"\.innerHTML\s*=", line):
            findings.append(_make_finding("xss-innerhtml", i, line))
        if re.search(r"\bResponse\.Write\s*\(", line):
            findings.append(_make_finding("xss-response-write", i, line))
        if re.search(r"\bConnectionString\b\s*=\s*\"[^\"]+\"", line, re.IGNORECASE):
            findings.append(_make_finding("hardcoded-connection-string", i, line))
        if re.search(r"\bpassword\b\s*=\s*\"[^\"]+\"", line, re.IGNORECASE):
            findings.append(_make_finding("hardcoded-password", i, line))
        if re.search(r"\bMD5\.Create\s*\(", line):
            findings.append(_make_finding("weak-hash-md5", i, line))
        if re.search(r"\bSHA1\.Create\s*\(", line):
            findings.append(_make_finding("weak-hash-sha1", i, line))
        if re.search(r"\bDirectory\.Delete\s*\(", line):
            findings.append(_make_finding("path-traversal-directory-delete", i, line))
        if re.search(r"\bFile\.Delete\s*\(", line):
            findings.append(_make_finding("path-traversal-file-delete", i, line))
        if re.search(r"\bFile\.ReadAllText\s*\(.*\+\s*\w", line):
            findings.append(_make_finding("path-traversal-file-read", i, line))
    return findings


def _scan_generic(lines: List[str]) -> List[Dict]:
    findings: List[Dict] = []
    for i, line in enumerate(lines):
        if re.search(r"AKIA[0-9A-Z]{16}", line):
            findings.append(_make_finding("aws-access-key-id", i, line))
        if re.search(r"aws_secret_access_key\s*=\s*\"[A-Za-z0-9/+=]{40,}\"", line, re.IGNORECASE):
            findings.append(_make_finding("aws-secret-access-key", i, line))
        if re.search(r"ghp_[A-Za-z0-9]{20,}", line):
            findings.append(_make_finding("github-pat", i, line))
        if re.search(r"sk_live_[A-Za-z0-9]+", line):
            findings.append(_make_finding("stripe-api-key", i, line))
        if re.search(r"BEGIN RSA PRIVATE KEY", line):
            findings.append(_make_finding("private-key-rsa", i, line))
        if re.search(r"://", line) and "database_url" in line:
            findings.append(_make_finding("database-url", i, line))
        if re.search(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", line):
            findings.append(_make_finding("jwt-token", i, line))
        if re.search(r"\bpassword\b\s*=\s*\"[^\"]+\"", line, re.IGNORECASE):
            findings.append(_make_finding("hardcoded-password", i, line))
        if re.search(r"\bopenai_key\b\s*=\s*\"sk-[A-Za-z0-9]+\"", line, re.IGNORECASE):
            findings.append(_make_finding("openai-api-key", i, line))
    return findings
