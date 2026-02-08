# Security Policy

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in agent-security-scanner-mcp, please report it responsibly.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please email us at: **security@sinewave.ai**

Include the following information:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Depends on severity, typically 30-90 days

### Severity Levels

| Severity | Description | Target Resolution |
|----------|-------------|-------------------|
| Critical | RCE, data exfiltration | 7 days |
| High | Privilege escalation, auth bypass | 14 days |
| Medium | Information disclosure | 30 days |
| Low | Minor issues | 90 days |

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x.x   | ✅ Yes |
| 1.x.x   | ❌ No (upgrade recommended) |

## Security Best Practices

When using this tool:

1. **Keep Updated**: Always use the latest version
2. **Review Prompts**: The prompt scanner helps, but review AI instructions manually for sensitive operations
3. **Verify Packages**: Use hallucination detection before installing AI-suggested packages
4. **Scan Before Commit**: Run security scans before committing code

## Past Security Issues

| Version | Issue | Fixed In |
|---------|-------|----------|
| < 2.0.0 | Command injection in file path handling | 2.0.0 |

## Acknowledgments

We thank the security researchers who help keep this project secure. Contributors will be acknowledged here (with permission).
