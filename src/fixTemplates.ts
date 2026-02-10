import * as vscode from 'vscode';

/**
 * Security Fix Templates - Agentic fix suggestions for security vulnerabilities
 *
 * This module provides intelligent, context-aware fix suggestions for each
 * security rule. The "agentic" approach means:
 * 1. Analyzing the matched code context
 * 2. Generating appropriate fix suggestions
 * 3. Offering multiple fix options when applicable
 */

export interface FixSuggestion {
    title: string;
    replacement: string;
    isPreferred?: boolean;
    description?: string;
}

export interface FixContext {
    document: vscode.TextDocument;
    range: vscode.Range;
    matchedText: string;
    fullLine: string;
    ruleId: string;
}

type FixGenerator = (context: FixContext) => FixSuggestion[];

/**
 * Registry of fix generators for each rule ID pattern
 */
const fixGenerators: Map<string, FixGenerator> = new Map();

// ============================================================================
// PYTHON FIXES
// ============================================================================

// SQL Injection fixes
fixGenerators.set('python.lang.security.audit.sqli', (ctx) => {
    const fixes: FixSuggestion[] = [];
    const line = ctx.fullLine;

    // Detect f-string SQL
    if (line.includes('f"') || line.includes("f'")) {
        const paramMatch = line.match(/cursor\.execute\s*\(\s*f["']([^"']+)["']/);
        if (paramMatch) {
            fixes.push({
                title: 'Convert to parameterized query',
                replacement: line.replace(
                    /cursor\.execute\s*\(\s*f["']([^"']+)["']\s*\)/,
                    'cursor.execute("$1", (params,))  # TODO: Replace {vars} with ? placeholders'
                ),
                isPreferred: true,
                description: 'Use parameterized queries to prevent SQL injection'
            });
        }
    }

    // Detect string concatenation
    if (line.includes('+')) {
        fixes.push({
            title: 'Use parameterized query with placeholders',
            replacement: '# TODO: Refactor to use parameterized query:\n# cursor.execute("SELECT * FROM table WHERE column = ?", (user_input,))',
            description: 'Parameterized queries prevent SQL injection attacks'
        });
    }

    // Detect .format()
    if (line.includes('.format(')) {
        fixes.push({
            title: 'Replace .format() with parameterized query',
            replacement: line.replace(/\.format\s*\([^)]*\)/, ', (params,)  # TODO: Use ? placeholders'),
            description: 'Never use string formatting for SQL queries'
        });
    }

    if (fixes.length === 0) {
        fixes.push({
            title: 'Convert to parameterized query',
            replacement: '# Use: cursor.execute("query with ? placeholders", (param1, param2))',
            description: 'Parameterized queries prevent SQL injection'
        });
    }

    return fixes;
});

// Command Injection - subprocess fixes
fixGenerators.set('python.lang.security.audit.dangerous-subprocess', (ctx) => {
    const line = ctx.fullLine;
    const fixes: FixSuggestion[] = [];

    // Replace shell=True with shell=False and list arguments
    const shellTrueMatch = line.match(/(subprocess\.\w+)\s*\(\s*([^,]+),?\s*shell\s*=\s*True/);
    if (shellTrueMatch) {
        const func = shellTrueMatch[1];
        const cmd = shellTrueMatch[2].trim();

        fixes.push({
            title: 'Use shell=False with argument list',
            replacement: line.replace(
                /shell\s*=\s*True/,
                'shell=False  # Pass command as list: ["cmd", "arg1", "arg2"]'
            ),
            isPreferred: true,
            description: 'shell=False prevents command injection attacks'
        });

        fixes.push({
            title: 'Use shlex.split() for safe argument parsing',
            replacement: `import shlex\n${func}(shlex.split(${cmd}), shell=False)`,
            description: 'shlex.split() safely tokenizes command strings'
        });
    }

    return fixes;
});

// os.system fixes
fixGenerators.set('python.lang.security.audit.dangerous-system-call', (ctx) => {
    const line = ctx.fullLine;
    const fixes: FixSuggestion[] = [];

    const osSystemMatch = line.match(/os\.system\s*\(\s*(.+)\s*\)/);
    if (osSystemMatch) {
        const cmd = osSystemMatch[1];
        fixes.push({
            title: 'Replace with subprocess.run()',
            replacement: line.replace(
                /os\.system\s*\(\s*.+\s*\)/,
                `subprocess.run([${cmd}], shell=False, check=True)  # Split command into list`
            ),
            isPreferred: true,
            description: 'subprocess.run with shell=False is safer'
        });
    }

    const osPopenMatch = line.match(/os\.popen\s*\(\s*(.+)\s*\)/);
    if (osPopenMatch) {
        fixes.push({
            title: 'Replace with subprocess.Popen()',
            replacement: line.replace(
                /os\.popen\s*\(.+\)/,
                'subprocess.Popen(cmd_list, shell=False, stdout=subprocess.PIPE)'
            ),
            isPreferred: true
        });
    }

    return fixes;
});

// eval() fixes
fixGenerators.set('python.lang.security.audit.eval-detected', (ctx) => {
    return [
        {
            title: 'Replace eval() with ast.literal_eval() for literals',
            replacement: ctx.fullLine.replace(/\beval\s*\(/, 'ast.literal_eval('),
            isPreferred: true,
            description: 'ast.literal_eval() safely evaluates literal expressions only'
        },
        {
            title: 'Use JSON parsing instead',
            replacement: ctx.fullLine.replace(/\beval\s*\(([^)]+)\)/, 'json.loads($1)'),
            description: 'For JSON data, use json.loads() instead of eval()'
        }
    ];
});

// exec() fixes
fixGenerators.set('python.lang.security.audit.exec-detected', (_ctx) => {
    return [
        {
            title: 'Remove exec() - refactor to use safe alternatives',
            replacement: '# WARNING: exec() removed - refactor this code to avoid dynamic code execution',
            isPreferred: true,
            description: 'exec() should be avoided; use explicit function calls instead'
        }
    ];
});

// Pickle fixes
fixGenerators.set('python.lang.security.deserialization.pickle', (ctx) => {
    const line = ctx.fullLine;
    return [
        {
            title: 'Replace pickle with JSON',
            replacement: line.replace(/pickle\.loads?\s*\(/, 'json.load(').replace(/pickle/, 'json'),
            isPreferred: true,
            description: 'JSON is safe for untrusted data'
        },
        {
            title: 'Add HMAC verification before unpickling',
            replacement: `# Verify HMAC signature before unpickling untrusted data\n# if hmac.compare_digest(signature, expected): ...\n${line}`,
            description: 'Verify data integrity before deserializing'
        }
    ];
});

// YAML unsafe load fixes
fixGenerators.set('python.lang.security.deserialization.yaml', (ctx) => {
    return [
        {
            title: 'Use yaml.safe_load() instead',
            replacement: ctx.fullLine.replace(/yaml\.load\s*\([^)]*\)/, 'yaml.safe_load(data)'),
            isPreferred: true,
            description: 'safe_load() prevents arbitrary code execution'
        },
        {
            title: 'Use yaml.load() with SafeLoader',
            replacement: ctx.fullLine.replace(
                /yaml\.load\s*\(\s*([^,)]+)\s*\)/,
                'yaml.load($1, Loader=yaml.SafeLoader)'
            ),
            description: 'Explicitly specify SafeLoader for security'
        }
    ];
});

// MD5/SHA1 weak hash fixes
fixGenerators.set('python.lang.security.crypto.insecure-hash-md5', (ctx) => {
    return [
        {
            title: 'Replace MD5 with SHA-256',
            replacement: ctx.fullLine.replace(/hashlib\.md5\s*\(/, 'hashlib.sha256('),
            isPreferred: true,
            description: 'SHA-256 is cryptographically secure'
        },
        {
            title: 'Replace with SHA-3',
            replacement: ctx.fullLine.replace(/hashlib\.md5\s*\(/, 'hashlib.sha3_256('),
            description: 'SHA-3 provides additional security margin'
        }
    ];
});

fixGenerators.set('python.lang.security.crypto.insecure-hash-sha1', (ctx) => {
    return [
        {
            title: 'Replace SHA1 with SHA-256',
            replacement: ctx.fullLine.replace(/hashlib\.sha1\s*\(/, 'hashlib.sha256('),
            isPreferred: true,
            description: 'SHA-256 is cryptographically secure'
        }
    ];
});

// Insecure random fixes
fixGenerators.set('python.lang.security.crypto.insecure-random', (ctx) => {
    const line = ctx.fullLine;
    const fixes: FixSuggestion[] = [];

    if (line.includes('random.random')) {
        fixes.push({
            title: 'Use secrets.SystemRandom() for security',
            replacement: line.replace('random.random()', 'secrets.SystemRandom().random()'),
            isPreferred: true
        });
    }
    if (line.includes('random.randint')) {
        fixes.push({
            title: 'Use secrets.randbelow() for security',
            replacement: line.replace(/random\.randint\s*\(\s*\d+\s*,\s*(\d+)\s*\)/, 'secrets.randbelow($1 + 1)'),
            isPreferred: true
        });
    }
    if (line.includes('random.choice')) {
        fixes.push({
            title: 'Use secrets.choice() for security',
            replacement: line.replace('random.choice', 'secrets.choice'),
            isPreferred: true
        });
    }

    if (fixes.length === 0) {
        fixes.push({
            title: 'Use secrets module for cryptographic randomness',
            replacement: '# import secrets; use secrets.token_bytes(), secrets.token_hex(), etc.',
            description: 'The secrets module provides cryptographically secure randomness'
        });
    }

    return fixes;
});

// SSL verification disabled fixes
fixGenerators.set('python.lang.security.ssl.ssl-verify-disabled', (ctx) => {
    return [
        {
            title: 'Enable SSL verification',
            replacement: ctx.fullLine.replace(/verify\s*=\s*False/, 'verify=True'),
            isPreferred: true,
            description: 'SSL verification prevents man-in-the-middle attacks'
        }
    ];
});

// Flask/Django debug mode fixes
fixGenerators.set('python.flask.security.debug-enabled', (ctx) => {
    return [
        {
            title: 'Disable debug mode for production',
            replacement: ctx.fullLine.replace(/debug\s*=\s*True/, 'debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true"'),
            isPreferred: true,
            description: 'Use environment variable to control debug mode'
        },
        {
            title: 'Set debug=False',
            replacement: ctx.fullLine.replace(/debug\s*=\s*True/, 'debug=False'),
            description: 'Disable debug mode entirely'
        }
    ];
});

fixGenerators.set('python.django.security.debug-enabled', (ctx) => {
    return [
        {
            title: 'Use environment variable for DEBUG',
            replacement: ctx.fullLine.replace(/DEBUG\s*=\s*True/, 'DEBUG = os.environ.get("DJANGO_DEBUG", "False") == "True"'),
            isPreferred: true,
            description: 'Control debug mode via environment'
        }
    ];
});

// Hardcoded secrets fixes
fixGenerators.set('python.lang.security.audit.hardcoded-password', (ctx) => {
    return [
        {
            title: 'Use environment variable',
            replacement: ctx.fullLine.replace(
                /(password|passwd|pwd)\s*=\s*["'][^"']+["']/i,
                '$1 = os.environ.get("$1".upper())'
            ),
            isPreferred: true,
            description: 'Store secrets in environment variables'
        },
        {
            title: 'Use secrets manager',
            replacement: '# Use a secrets manager: AWS Secrets Manager, HashiCorp Vault, etc.',
            description: 'Secrets managers provide secure credential storage'
        }
    ];
});

fixGenerators.set('python.lang.security.audit.hardcoded-api-key', (ctx) => {
    return [
        {
            title: 'Load API key from environment',
            replacement: ctx.fullLine.replace(
                /(api[_-]?key|apikey)\s*=\s*["'][^"']+["']/i,
                '$1 = os.environ.get("API_KEY")'
            ),
            isPreferred: true,
            description: 'Never hardcode API keys in source code'
        }
    ];
});

// ============================================================================
// JAVASCRIPT/TYPESCRIPT FIXES
// ============================================================================

// XSS - innerHTML fixes
fixGenerators.set('javascript.browser.security.dom-based-xss.innerHTML', (ctx) => {
    return [
        {
            title: 'Use textContent instead of innerHTML',
            replacement: ctx.fullLine.replace(/\.innerHTML\s*=/, '.textContent ='),
            isPreferred: true,
            description: 'textContent safely escapes HTML entities'
        },
        {
            title: 'Sanitize with DOMPurify before setting innerHTML',
            replacement: ctx.fullLine.replace(
                /\.innerHTML\s*=\s*(.+)/,
                '.innerHTML = DOMPurify.sanitize($1)'
            ),
            description: 'DOMPurify removes dangerous HTML'
        }
    ];
});

// React dangerouslySetInnerHTML fixes
fixGenerators.set('javascript.react.security.dangerouslySetInnerHTML', (ctx) => {
    return [
        {
            title: 'Sanitize content with DOMPurify',
            replacement: ctx.fullLine.replace(
                /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([^}]+)\}\s*\}/,
                'dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize($1) }}'
            ),
            isPreferred: true,
            description: 'Always sanitize HTML content with DOMPurify'
        },
        {
            title: 'Use a safe markdown renderer instead',
            replacement: '// Consider using react-markdown or similar safe alternatives',
            description: 'Safe markdown renderers prevent XSS'
        }
    ];
});

// eval() fixes for JavaScript
fixGenerators.set('javascript.lang.security.audit.eval-detected', (ctx) => {
    return [
        {
            title: 'Use JSON.parse() for JSON data',
            replacement: ctx.fullLine.replace(/\beval\s*\(([^)]+)\)/, 'JSON.parse($1)'),
            isPreferred: true,
            description: 'JSON.parse() safely parses JSON without code execution'
        },
        {
            title: 'Use Function constructor with validation',
            replacement: '// If dynamic code is needed, validate input strictly before execution',
            description: 'Avoid eval() entirely when possible'
        }
    ];
});

// SQL injection fixes for JavaScript
fixGenerators.set('javascript.lang.security.audit.sql-injection', (ctx) => {
    return [
        {
            title: 'Use parameterized query',
            replacement: ctx.fullLine.replace(
                /query\s*\(\s*`[^`]*\$\{([^}]+)\}[^`]*`/,
                'query("SELECT * FROM table WHERE column = ?", [$1]'
            ),
            isPreferred: true,
            description: 'Parameterized queries prevent SQL injection'
        },
        {
            title: 'Use prepared statements',
            replacement: '// Use: db.query("SELECT * FROM users WHERE id = ?", [userId])',
            description: 'Prepared statements are the safest approach'
        }
    ];
});

// Command injection fixes
fixGenerators.set('javascript.lang.security.audit.child-process-exec', (ctx) => {
    return [
        {
            title: 'Use execFile() instead of exec()',
            replacement: ctx.fullLine.replace(/\bexec\s*\(/, 'execFile('),
            isPreferred: true,
            description: 'execFile() does not spawn a shell, preventing injection'
        },
        {
            title: 'Use spawn() with shell: false',
            replacement: ctx.fullLine.replace(
                /exec\s*\([^)]+\)/,
                'spawn(cmd, args, { shell: false })'
            ),
            description: 'spawn() with shell: false is safe'
        }
    ];
});

// Hardcoded secrets fixes for JavaScript
fixGenerators.set('javascript.lang.security.audit.hardcoded-secret', (ctx) => {
    return [
        {
            title: 'Use environment variable',
            replacement: ctx.fullLine.replace(
                /(api[_-]?key|password|secret[_-]?key|token)\s*[:=]\s*["'][^"']+["']/i,
                '$1: process.env.$1.toUpperCase()'
            ),
            isPreferred: true,
            description: 'Load secrets from environment variables'
        },
        {
            title: 'Use dotenv for local development',
            replacement: '// require("dotenv").config(); then use process.env.SECRET_NAME',
            description: 'dotenv loads .env file in development'
        }
    ];
});

// SSL/TLS verification disabled
fixGenerators.set('javascript.lang.security.ssl.reject-unauthorized-false', (ctx) => {
    return [
        {
            title: 'Enable certificate verification',
            replacement: ctx.fullLine.replace(/rejectUnauthorized\s*:\s*false/, 'rejectUnauthorized: true'),
            isPreferred: true,
            description: 'Certificate verification prevents MITM attacks'
        },
        {
            title: 'Remove the insecure option',
            replacement: ctx.fullLine.replace(/,?\s*rejectUnauthorized\s*:\s*false\s*,?/, ''),
            description: 'Default behavior is to verify certificates'
        }
    ];
});

// Weak crypto fixes
fixGenerators.set('javascript.lang.security.crypto.insecure-hash-md5', (ctx) => {
    return [
        {
            title: 'Use SHA-256 instead of MD5',
            replacement: ctx.fullLine.replace(/["']md5["']/, '"sha256"'),
            isPreferred: true,
            description: 'SHA-256 is cryptographically secure'
        }
    ];
});

fixGenerators.set('javascript.lang.security.crypto.insecure-random', (ctx) => {
    return [
        {
            title: 'Use crypto.randomBytes() for security',
            replacement: ctx.fullLine.replace(
                /Math\.random\s*\(\s*\)/,
                'crypto.randomBytes(16).toString("hex")'
            ),
            isPreferred: true,
            description: 'crypto.randomBytes() provides cryptographic randomness'
        },
        {
            title: 'Use crypto.getRandomValues() in browser',
            replacement: '// const array = new Uint32Array(1); crypto.getRandomValues(array);',
            description: 'Web Crypto API for browser environments'
        }
    ];
});

// Prototype pollution fixes
fixGenerators.set('javascript.lang.security.audit.prototype-pollution', (_ctx) => {
    return [
        {
            title: 'Validate object keys before assignment',
            replacement: '// Validate key: if (["__proto__", "constructor", "prototype"].includes(key)) throw new Error("Invalid key");',
            isPreferred: true,
            description: 'Block dangerous property names'
        },
        {
            title: 'Use Object.create(null) for lookup objects',
            replacement: '// Use: const obj = Object.create(null); // No prototype chain',
            description: 'Objects without prototype cannot be polluted'
        }
    ];
});

// ============================================================================
// GENERIC FIXES
// ============================================================================

// Hardcoded credentials (generic)
fixGenerators.set('generic.secrets', (_ctx) => {
    return [
        {
            title: 'Remove hardcoded secret',
            replacement: '# REMOVED: Hardcoded secret - use environment variables or secrets manager',
            isPreferred: true,
            description: 'Never commit secrets to source control'
        }
    ];
});

/**
 * Get fix suggestions for a given rule and context
 */
export function getFixSuggestions(context: FixContext): FixSuggestion[] {
    // Try exact match first
    let generator = fixGenerators.get(context.ruleId);

    // If no exact match, try prefix matching for rule categories
    if (!generator) {
        for (const [pattern, gen] of fixGenerators.entries()) {
            if (context.ruleId.startsWith(pattern) || context.ruleId.includes(pattern)) {
                generator = gen;
                break;
            }
        }
    }

    if (generator) {
        try {
            return generator(context);
        } catch (e) {
            console.error(`Error generating fix for ${context.ruleId}:`, e);
        }
    }

    // Return a generic suggestion if no specific fix is available
    return [{
        title: 'See documentation for remediation',
        replacement: '',
        description: 'Review the security rule documentation for fix guidance'
    }];
}

/**
 * Check if a rule has available fixes
 */
export function hasFixAvailable(ruleId: string): boolean {
    if (fixGenerators.has(ruleId)) {
        return true;
    }

    for (const pattern of fixGenerators.keys()) {
        if (ruleId.startsWith(pattern) || ruleId.includes(pattern)) {
            return true;
        }
    }

    return false;
}
