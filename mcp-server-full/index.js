#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { execSync } from "child_process";
import { readFileSync, existsSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import bloomFilters from "bloom-filters";
const { BloomFilter } = bloomFilters;

const __dirname = dirname(fileURLToPath(import.meta.url));

// Security fix templates - comprehensive coverage for 165+ rules
const FIX_TEMPLATES = {
  // ===========================================
  // SQL INJECTION
  // ===========================================
  "sql-injection": {
    description: "Use parameterized queries instead of string concatenation",
    fix: (line) => line.replace(/["']([^"']*)\s*["']\s*\+\s*(\w+)/, '"$1?", [$2]')
  },
  "nosql-injection": {
    description: "Sanitize MongoDB query inputs",
    fix: (line) => line.replace(/\{\s*(\w+)\s*:\s*(\w+)\s*\}/, '{ $1: sanitize($2) }')
  },
  "raw-query": {
    description: "Use parameterized queries instead of raw SQL",
    fix: (line) => line.replace(/\.query\s*\(\s*["'`]/, '.query("SELECT * FROM table WHERE id = ?", [')
  },

  // ===========================================
  // XSS (Cross-Site Scripting)
  // ===========================================
  "innerhtml": {
    description: "Use textContent or DOMPurify.sanitize()",
    fix: (line) => line.replace(/\.innerHTML\s*=/, '.textContent =')
  },
  "outerhtml": {
    description: "Use textContent or DOMPurify.sanitize()",
    fix: (line) => line.replace(/\.outerHTML\s*=/, '.textContent =')
  },
  "document-write": {
    description: "Use DOM methods instead of document.write()",
    fix: (line) => line.replace(/document\.write(ln)?\s*\(/, 'document.body.appendChild(document.createTextNode(')
  },
  "insertadjacenthtml": {
    description: "Use insertAdjacentText or sanitize input",
    fix: (line) => line.replace(/\.insertAdjacentHTML\s*\(/, '.insertAdjacentText(')
  },
  "dangerouslysetinnerhtml": {
    description: "Sanitize content with DOMPurify before using dangerouslySetInnerHTML",
    fix: (line) => line.replace(/dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(\w+)/, 'dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize($1)')
  },
  "xss-response-writer": {
    description: "Escape HTML output before writing to response",
    fix: (line) => line.replace(/\.Write\s*\(\s*(\w+)/, '.Write(html.EscapeString($1)')
  },

  // ===========================================
  // COMMAND INJECTION
  // ===========================================
  "child-process-exec": {
    description: "Use execFile() or spawn() with shell: false",
    fix: (line) => line.replace(/\bexec\s*\(/, 'execFile(')
  },
  "spawn-shell": {
    description: "Use spawn with shell: false",
    fix: (line) => line.replace(/shell\s*:\s*true/i, 'shell: false')
  },
  "dangerous-subprocess": {
    description: "Use subprocess.run with list arguments",
    fix: (line) => line.replace(/subprocess\.(call|run|Popen)\s*\(\s*["'](.+?)["']\s*,\s*shell\s*=\s*True/, 'subprocess.$1(["$2".split()], shell=False')
  },
  "dangerous-system-call": {
    description: "Use subprocess.run instead of os.system",
    fix: (line) => line.replace(/os\.system\s*\(/, 'subprocess.run([')
  },
  "command-injection-exec": {
    description: "Use exec.Command with separate arguments",
    fix: (line) => line.replace(/exec\.Command\s*\(\s*["'](\w+)\s+/, 'exec.Command("$1", ')
  },
  "runtime-exec": {
    description: "Use ProcessBuilder with separate arguments",
    fix: (line) => line.replace(/Runtime\.getRuntime\(\)\.exec\s*\(/, 'new ProcessBuilder(')
  },
  "process-builder": {
    description: "Validate and sanitize command arguments",
    fix: (line) => line.replace(/new ProcessBuilder\s*\(\s*(.+?)\s*\)/, 'new ProcessBuilder(validateArgs($1))')
  },

  // ===========================================
  // HARDCODED SECRETS & CREDENTIALS
  // ===========================================
  "hardcoded": {
    description: "Use environment variables",
    fix: (line, lang) => {
      if (lang === 'python') {
        return line.replace(/=\s*["'][^"']+["']/, '= os.environ.get("SECRET")');
      }
      return line.replace(/=\s*["'][^"']+["']/, '= process.env.SECRET');
    }
  },
  "api-key": {
    description: "Use environment variables for API keys",
    fix: (line, lang) => {
      if (lang === 'python') return line.replace(/=\s*["'][^"']+["']/, '= os.environ.get("API_KEY")');
      if (lang === 'go') return line.replace(/=\s*["'][^"']+["']/, '= os.Getenv("API_KEY")');
      return line.replace(/=\s*["'][^"']+["']/, '= process.env.API_KEY');
    }
  },
  "password": {
    description: "Use environment variables for passwords",
    fix: (line, lang) => {
      if (lang === 'python') return line.replace(/=\s*["'][^"']+["']/, '= os.environ.get("PASSWORD")');
      if (lang === 'go') return line.replace(/=\s*["'][^"']+["']/, '= os.Getenv("PASSWORD")');
      return line.replace(/=\s*["'][^"']+["']/, '= process.env.PASSWORD');
    }
  },
  "secret-key": {
    description: "Use environment variables for secret keys",
    fix: (line, lang) => {
      if (lang === 'python') return line.replace(/=\s*["'][^"']+["']/, '= os.environ.get("SECRET_KEY")');
      return line.replace(/=\s*["'][^"']+["']/, '= process.env.SECRET_KEY');
    }
  },
  "aws-access": {
    description: "Use AWS credentials from environment or IAM roles",
    fix: (line) => line.replace(/=\s*["']AKIA[^"']+["']/, '= os.environ.get("AWS_ACCESS_KEY_ID")')
  },
  "aws-secret": {
    description: "Use AWS credentials from environment or IAM roles",
    fix: (line) => line.replace(/=\s*["'][^"']{40}["']/, '= os.environ.get("AWS_SECRET_ACCESS_KEY")')
  },
  "stripe": {
    description: "Use environment variables for Stripe keys",
    fix: (line, lang) => {
      if (lang === 'python') return line.replace(/=\s*["']sk_(live|test)_[^"']+["']/, '= os.environ.get("STRIPE_SECRET_KEY")');
      return line.replace(/=\s*["']sk_(live|test)_[^"']+["']/, '= process.env.STRIPE_SECRET_KEY');
    }
  },
  "github": {
    description: "Use environment variables for GitHub tokens",
    fix: (line, lang) => {
      if (lang === 'python') return line.replace(/=\s*["'](ghp_|github_pat_)[^"']+["']/, '= os.environ.get("GITHUB_TOKEN")');
      return line.replace(/=\s*["'](ghp_|github_pat_)[^"']+["']/, '= process.env.GITHUB_TOKEN');
    }
  },
  "openai": {
    description: "Use environment variables for OpenAI keys",
    fix: (line, lang) => {
      if (lang === 'python') return line.replace(/=\s*["']sk-[^"']+["']/, '= os.environ.get("OPENAI_API_KEY")');
      return line.replace(/=\s*["']sk-[^"']+["']/, '= process.env.OPENAI_API_KEY');
    }
  },
  "slack": {
    description: "Use environment variables for Slack tokens",
    fix: (line, lang) => {
      if (lang === 'python') return line.replace(/=\s*["']xox[baprs]-[^"']+["']/, '= os.environ.get("SLACK_TOKEN")');
      return line.replace(/=\s*["']xox[baprs]-[^"']+["']/, '= process.env.SLACK_TOKEN');
    }
  },
  "jwt-token": {
    description: "Use environment variables for JWT secrets",
    fix: (line, lang) => {
      if (lang === 'python') return line.replace(/=\s*["'][^"']+["']/, '= os.environ.get("JWT_SECRET")');
      return line.replace(/=\s*["'][^"']+["']/, '= process.env.JWT_SECRET');
    }
  },
  "private-key": {
    description: "Load private keys from secure file or vault",
    fix: (line, lang) => {
      if (lang === 'python') return line.replace(/=\s*["']-----BEGIN[^"']+["']/, '= load_key_from_file(os.environ.get("PRIVATE_KEY_PATH"))');
      return line.replace(/=\s*["']-----BEGIN[^"']+["']/, '= fs.readFileSync(process.env.PRIVATE_KEY_PATH)');
    }
  },
  "database-url": {
    description: "Use environment variables for database URLs",
    fix: (line, lang) => {
      if (lang === 'python') return line.replace(/=\s*["'][^"']+["']/, '= os.environ.get("DATABASE_URL")');
      return line.replace(/=\s*["'][^"']+["']/, '= process.env.DATABASE_URL');
    }
  },

  // ===========================================
  // WEAK CRYPTOGRAPHY
  // ===========================================
  "md5": {
    description: "Use SHA-256 or stronger",
    fix: (line) => line.replace(/md5/gi, 'sha256')
  },
  "sha1": {
    description: "Use SHA-256 or stronger",
    fix: (line) => line.replace(/sha1/gi, 'sha256')
  },
  "des": {
    description: "Use AES instead of DES",
    fix: (line) => line.replace(/DES/g, 'AES').replace(/des/g, 'aes')
  },
  "ecb-mode": {
    description: "Use CBC or GCM mode instead of ECB",
    fix: (line) => line.replace(/ECB/g, 'GCM').replace(/ecb/g, 'gcm')
  },
  "weak-cipher": {
    description: "Use AES-256-GCM or ChaCha20-Poly1305",
    fix: (line) => line.replace(/(DES|RC4|Blowfish)/gi, 'AES')
  },
  "insecure-random": {
    description: "Use cryptographically secure random",
    fix: (line, lang) => {
      if (lang === 'python') return line.replace(/random\.(random|randint|choice|randrange)\s*\(/, 'secrets.token_hex(');
      if (lang === 'go') return line.replace(/math\/rand/, 'crypto/rand');
      if (lang === 'java') return line.replace(/new Random\(\)/, 'SecureRandom.getInstanceStrong()');
      return line.replace(/Math\.random\s*\(\)/, 'crypto.randomUUID()');
    }
  },
  "weak-rsa": {
    description: "Use RSA key size of 2048 bits or more",
    fix: (line) => line.replace(/\b(512|1024)\b/, '2048')
  },
  "weak-tls": {
    description: "Use TLS 1.2 or higher",
    fix: (line) => line.replace(/TLS1[01]|SSLv[23]/gi, 'TLS12')
  },

  // ===========================================
  // INSECURE DESERIALIZATION
  // ===========================================
  "pickle": {
    description: "Use JSON instead of pickle",
    fix: (line) => line.replace(/pickle\.(load|loads)\s*\(/, 'json.$1(')
  },
  "yaml-load": {
    description: "Use yaml.safe_load()",
    fix: (line) => line.replace(/yaml\.load\s*\(/, 'yaml.safe_load(')
  },
  "marshal": {
    description: "Use JSON instead of marshal",
    fix: (line) => line.replace(/marshal\.(load|loads)\s*\(/, 'json.$1(')
  },
  "shelve": {
    description: "Use JSON or SQLite instead of shelve",
    fix: (line) => line.replace(/shelve\.open\s*\(/, 'json.load(open(')
  },
  "node-serialize": {
    description: "Use JSON.parse instead of node-serialize",
    fix: (line) => line.replace(/serialize\.unserialize\s*\(/, 'JSON.parse(')
  },
  "object-inputstream": {
    description: "Use JSON or validated deserialization",
    fix: (line) => line.replace(/new ObjectInputStream\s*\(/, 'new JsonReader(')
  },
  "xstream": {
    description: "Configure XStream security or use JSON",
    fix: (line) => line.replace(/xstream\.fromXML\s*\(/, 'new ObjectMapper().readValue(')
  },
  "gob-decode": {
    description: "Use JSON instead of gob for untrusted data",
    fix: (line) => line.replace(/gob\.NewDecoder/, 'json.NewDecoder')
  },

  // ===========================================
  // SSL/TLS ISSUES
  // ===========================================
  "verify": {
    description: "Enable SSL verification",
    fix: (line) => line.replace(/verify\s*=\s*False/i, 'verify=True')
  },
  "insecure-skip-verify": {
    description: "Enable certificate verification",
    fix: (line) => line.replace(/InsecureSkipVerify\s*:\s*true/, 'InsecureSkipVerify: false')
  },
  "reject-unauthorized": {
    description: "Enable certificate verification",
    fix: (line) => line.replace(/rejectUnauthorized\s*:\s*false/, 'rejectUnauthorized: true')
  },
  "trust-all": {
    description: "Remove trust-all certificate configuration",
    fix: (line) => '// TODO: Remove trust-all certificates - ' + line
  },
  "ssl-verify-disabled": {
    description: "Enable SSL verification",
    fix: (line) => line.replace(/verify\s*=\s*False/, 'verify=True')
  },

  // ===========================================
  // PATH TRAVERSAL
  // ===========================================
  "path-traversal": {
    description: "Sanitize file paths and use basename",
    fix: (line, lang) => {
      if (lang === 'python') return line.replace(/open\s*\(\s*(\w+)/, 'open(os.path.basename($1)');
      if (lang === 'go') return line.replace(/os\.Open\s*\(\s*(\w+)/, 'os.Open(filepath.Base($1)');
      if (lang === 'java') return line.replace(/new File\s*\(\s*(\w+)/, 'new File(new File($1).getName()');
      return line.replace(/readFileSync\s*\(\s*(\w+)/, 'readFileSync(path.basename($1)');
    }
  },

  // ===========================================
  // SSRF (Server-Side Request Forgery)
  // ===========================================
  "ssrf": {
    description: "Validate and whitelist URLs before making requests",
    fix: (line) => line.replace(/(axios|fetch|requests|http)\.(get|post|request)\s*\(\s*(\w+)/, '$1.$2(validateUrl($3)')
  },

  // ===========================================
  // EVAL AND CODE INJECTION
  // ===========================================
  "eval": {
    description: "Avoid eval() - use safer alternatives",
    fix: (line) => '// SECURITY: Remove eval() - ' + line
  },
  "exec-detected": {
    description: "Avoid exec() - use safer alternatives",
    fix: (line) => '# SECURITY: Remove exec() - ' + line
  },
  "compile-detected": {
    description: "Avoid compile() with untrusted input",
    fix: (line) => '# SECURITY: Review compile() usage - ' + line
  },
  "function-constructor": {
    description: "Avoid Function constructor - use safer alternatives",
    fix: (line) => '// SECURITY: Remove Function() constructor - ' + line
  },
  "settimeout-string": {
    description: "Use function reference instead of string",
    fix: (line) => line.replace(/setTimeout\s*\(\s*["'](.+?)["']/, 'setTimeout(() => { $1 }')
  },

  // ===========================================
  // OPEN REDIRECT
  // ===========================================
  "open-redirect": {
    description: "Validate redirect URLs against whitelist",
    fix: (line) => line.replace(/redirect\s*\(\s*(\w+)/, 'redirect(validateRedirectUrl($1)')
  },

  // ===========================================
  // CORS
  // ===========================================
  "cors-wildcard": {
    description: "Specify allowed origins instead of wildcard",
    fix: (line) => line.replace(/['"]\*['"]/, '"https://yourdomain.com"')
  },

  // ===========================================
  // CSRF
  // ===========================================
  "csrf": {
    description: "Enable CSRF protection",
    fix: (line) => line.replace(/csrf\s*:\s*false/i, 'csrf: true').replace(/@csrf_exempt/, '# @csrf_exempt  // TODO: Add CSRF protection')
  },

  // ===========================================
  // DEBUG MODE
  // ===========================================
  "debug": {
    description: "Disable debug mode in production",
    fix: (line) => line.replace(/debug\s*=\s*True/i, 'debug=os.environ.get("DEBUG", "False").lower() == "true"')
  },

  // ===========================================
  // JWT ISSUES
  // ===========================================
  "jwt-none": {
    description: "Specify a secure algorithm for JWT",
    fix: (line) => line.replace(/algorithm\s*[=:]\s*["']none["']/i, 'algorithm: "HS256"')
  },
  "jwt-decode-without-verify": {
    description: "Enable JWT signature verification",
    fix: (line) => line.replace(/verify\s*=\s*False/, 'verify=True')
  },

  // ===========================================
  // XXE (XML External Entities)
  // ===========================================
  "xxe": {
    description: "Disable external entities in XML parser",
    fix: (line, lang) => {
      if (lang === 'python') return line.replace(/etree\.parse\s*\(/, 'etree.parse(parser=etree.XMLParser(resolve_entities=False), ');
      if (lang === 'java') return '// TODO: Disable external entities - ' + line;
      return line;
    }
  },
  "lxml": {
    description: "Disable external entities in lxml",
    fix: (line) => line.replace(/etree\.(parse|fromstring)\s*\(/, 'etree.$1(parser=etree.XMLParser(resolve_entities=False, no_network=True), ')
  },

  // ===========================================
  // LDAP INJECTION
  // ===========================================
  "ldap-injection": {
    description: "Escape LDAP special characters in user input",
    fix: (line) => line.replace(/filter\s*=\s*["']([^"']*)\s*["']\s*\+\s*(\w+)/, 'filter = "$1" + escapeLdap($2)')
  },

  // ===========================================
  // XPATH INJECTION
  // ===========================================
  "xpath-injection": {
    description: "Use parameterized XPath queries",
    fix: (line) => line.replace(/xpath\s*\(\s*["']([^"']*)\s*["']\s*\+\s*(\w+)/, 'xpath("$1?", [$2]')
  },

  // ===========================================
  // TEMPLATE INJECTION
  // ===========================================
  "template-injection": {
    description: "Avoid user input in template strings",
    fix: (line) => '// TODO: Sanitize template input - ' + line
  },
  "jinja2-autoescape": {
    description: "Enable autoescape in Jinja2 templates",
    fix: (line) => line.replace(/autoescape\s*=\s*False/, 'autoescape=True')
  },

  // ===========================================
  // LOGGING SENSITIVE DATA
  // ===========================================
  "logging-sensitive": {
    description: "Remove sensitive data from logs",
    fix: (line) => line.replace(/(password|secret|token|key|credential)/gi, '[REDACTED]')
  },

  // ===========================================
  // REGEX DOS
  // ===========================================
  "regex-dos": {
    description: "Use regex with timeout or simplified pattern",
    fix: (line) => '// TODO: Review regex for ReDoS - ' + line
  },

  // ===========================================
  // PROTOTYPE POLLUTION
  // ===========================================
  "prototype-pollution": {
    description: "Validate object keys before assignment",
    fix: (line) => line.replace(/(\w+)\[(\w+)\]\s*=/, 'if (!["__proto__", "constructor", "prototype"].includes($2)) $1[$2] =')
  },

  // ===========================================
  // DOCKERFILE
  // ===========================================
  "latest-tag": {
    description: "Use specific version tags instead of latest",
    fix: (line) => line.replace(/:latest/, ':1.0.0  # TODO: specify exact version')
  },
  "run-as-root": {
    description: "Add USER directive to run as non-root",
    fix: (line) => line + '\nUSER nonroot'
  },
  "add-instead-of-copy": {
    description: "Use COPY instead of ADD for local files",
    fix: (line) => line.replace(/^ADD\s+/, 'COPY ')
  },
  "curl-pipe-bash": {
    description: "Download and verify scripts before execution",
    fix: (line) => '# TODO: Download, verify checksum, then execute - ' + line
  },
  "secret-in-env": {
    description: "Use Docker secrets or build args with --secret",
    fix: (line) => line.replace(/ENV\s+(\w*(?:PASSWORD|SECRET|KEY|TOKEN)\w*)\s*=\s*(\S+)/, '# Use --secret instead: ENV $1=$2')
  },
  "secret-in-arg": {
    description: "Use Docker secrets instead of ARG for secrets",
    fix: (line) => line.replace(/ARG\s+(\w*(?:PASSWORD|SECRET|KEY|TOKEN)\w*)/, '# Use --secret instead: ARG $1')
  },

  // ===========================================
  // HELMET / SECURITY HEADERS
  // ===========================================
  "helmet-missing": {
    description: "Add helmet middleware for security headers",
    fix: (line) => 'app.use(helmet()); // Add security headers\n' + line
  },

  // ===========================================
  // SPEL INJECTION
  // ===========================================
  "spel-injection": {
    description: "Avoid user input in SpEL expressions",
    fix: (line) => '// TODO: Sanitize SpEL input - ' + line
  },

  // ===========================================
  // ADDITIONAL DOCKERFILE FIXES
  // ===========================================
  "apt-get-no-version": {
    description: "Pin package versions in apt-get install",
    fix: (line) => line.replace(/apt-get install\s+(\w+)/, 'apt-get install $1=VERSION  # TODO: specify version')
  },
  "pip-no-version": {
    description: "Pin package versions in pip install",
    fix: (line) => line.replace(/pip install\s+(\w+)/, 'pip install $1==VERSION  # TODO: specify version')
  },
  "npm-install-unsafe": {
    description: "Use npm ci for reproducible builds",
    fix: (line) => line.replace(/npm install/, 'npm ci')
  },
  "missing-healthcheck": {
    description: "Add HEALTHCHECK instruction",
    fix: (line) => line + '\nHEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost/ || exit 1'
  },
  "expose-ssh": {
    description: "Avoid exposing SSH port in containers",
    fix: (line) => '# SECURITY: Avoid SSH in containers - ' + line
  },
  "chmod-dangerous": {
    description: "Use least privilege permissions",
    fix: (line) => line.replace(/chmod\s+(777|666|755)/, 'chmod 644  # TODO: use least privilege')
  },
  "apt-no-clean": {
    description: "Clean apt cache to reduce image size",
    fix: (line) => line.replace(/apt-get install/, 'apt-get install -y && apt-get clean && rm -rf /var/lib/apt/lists/*  #')
  },
  "curl-insecure": {
    description: "Remove insecure flag from curl",
    fix: (line) => line.replace(/curl\s+(-k|--insecure)/, 'curl')
  },
  "wget-no-check": {
    description: "Enable certificate checking in wget",
    fix: (line) => line.replace(/wget\s+--no-check-certificate/, 'wget')
  },
  "run-shell-form": {
    description: "Use exec form for RUN commands",
    fix: (line) => line.replace(/RUN\s+(.+)$/, 'RUN ["/bin/sh", "-c", "$1"]')
  },
  "sudo-in-dockerfile": {
    description: "Avoid sudo in Dockerfile - use USER directive",
    fix: (line) => line.replace(/sudo\s+/, '')
  },
  "workdir-absolute": {
    description: "Use absolute paths in WORKDIR",
    fix: (line) => line.replace(/WORKDIR\s+([^/])/, 'WORKDIR /$1')
  },

  // ===========================================
  // ADDITIONAL TOKEN/SECRET TYPES
  // ===========================================
  "gcp": {
    description: "Use environment variables for GCP credentials",
    fix: (line, lang) => {
      if (lang === 'python') return line.replace(/=\s*["'][^"']+["']/, '= os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")');
      return line.replace(/=\s*["'][^"']+["']/, '= process.env.GOOGLE_APPLICATION_CREDENTIALS');
    }
  },
  "azure": {
    description: "Use environment variables for Azure credentials",
    fix: (line, lang) => {
      if (lang === 'python') return line.replace(/=\s*["'][^"']+["']/, '= os.environ.get("AZURE_STORAGE_KEY")');
      return line.replace(/=\s*["'][^"']+["']/, '= process.env.AZURE_STORAGE_KEY');
    }
  },
  "npm-token": {
    description: "Use environment variables for npm tokens",
    fix: (line, lang) => {
      if (lang === 'python') return line.replace(/=\s*["'][^"']+["']/, '= os.environ.get("NPM_TOKEN")');
      return line.replace(/=\s*["'][^"']+["']/, '= process.env.NPM_TOKEN');
    }
  },
  "pypi": {
    description: "Use environment variables for PyPI tokens",
    fix: (line) => line.replace(/=\s*["'][^"']+["']/, '= os.environ.get("PYPI_TOKEN")')
  },
  "discord": {
    description: "Use environment variables for Discord tokens",
    fix: (line, lang) => {
      if (lang === 'python') return line.replace(/=\s*["'][^"']+["']/, '= os.environ.get("DISCORD_TOKEN")');
      return line.replace(/=\s*["'][^"']+["']/, '= process.env.DISCORD_TOKEN');
    }
  },
  "shopify": {
    description: "Use environment variables for Shopify tokens",
    fix: (line, lang) => {
      if (lang === 'python') return line.replace(/=\s*["'][^"']+["']/, '= os.environ.get("SHOPIFY_TOKEN")');
      return line.replace(/=\s*["'][^"']+["']/, '= process.env.SHOPIFY_TOKEN');
    }
  },
  "facebook": {
    description: "Use environment variables for Facebook tokens",
    fix: (line, lang) => {
      if (lang === 'python') return line.replace(/=\s*["'][^"']+["']/, '= os.environ.get("FACEBOOK_TOKEN")');
      return line.replace(/=\s*["'][^"']+["']/, '= process.env.FACEBOOK_TOKEN');
    }
  },
  "twitter": {
    description: "Use environment variables for Twitter tokens",
    fix: (line, lang) => {
      if (lang === 'python') return line.replace(/=\s*["'][^"']+["']/, '= os.environ.get("TWITTER_BEARER_TOKEN")');
      return line.replace(/=\s*["'][^"']+["']/, '= process.env.TWITTER_BEARER_TOKEN');
    }
  },
  "gitlab": {
    description: "Use environment variables for GitLab tokens",
    fix: (line, lang) => {
      if (lang === 'python') return line.replace(/=\s*["'][^"']+["']/, '= os.environ.get("GITLAB_TOKEN")');
      return line.replace(/=\s*["'][^"']+["']/, '= process.env.GITLAB_TOKEN');
    }
  },
  "bitbucket": {
    description: "Use environment variables for Bitbucket tokens",
    fix: (line, lang) => {
      if (lang === 'python') return line.replace(/=\s*["'][^"']+["']/, '= os.environ.get("BITBUCKET_TOKEN")');
      return line.replace(/=\s*["'][^"']+["']/, '= process.env.BITBUCKET_TOKEN');
    }
  },

  // ===========================================
  // PROMPT INJECTION - LLM SECURITY
  // ===========================================
  "prompt-injection": {
    description: "Sanitize user input before including in LLM prompts",
    fix: (line, lang) => {
      if (lang === 'python') {
        return line
          .replace(/f["']([^"']*)\{([^}]+)\}([^"']*)["']/, '"$1{sanitized}$3".format(sanitized=sanitize_prompt_input($2))')
          .replace(/\+\s*(\w+)/, '+ sanitize_prompt_input($1)');
      }
      return line
        .replace(/`([^`]*)\$\{([^}]+)\}([^`]*)`/, '`$1${sanitizePromptInput($2)}$3`')
        .replace(/\+\s*(\w+)/, '+ sanitizePromptInput($1)');
    }
  },
  "openai-unsafe-fstring": {
    description: "Sanitize user input before including in OpenAI prompts",
    fix: (line, lang) => {
      if (lang === 'python') {
        return line.replace(
          /content\s*:\s*f["']([^"']*)["']/,
          'content: sanitize_llm_input(f"$1")'
        );
      }
      return line.replace(/content\s*:\s*`([^`]*)`/, 'content: sanitizePromptInput(`$1`)');
    }
  },
  "anthropic-unsafe-fstring": {
    description: "Sanitize user input before including in Anthropic prompts",
    fix: (line, lang) => {
      if (lang === 'python') {
        return line.replace(
          /content\s*=\s*f["']([^"']*)["']/,
          'content=sanitize_llm_input(f"$1")'
        );
      }
      return line.replace(/content\s*:\s*`([^`]*)`/, 'content: sanitizePromptInput(`$1`)');
    }
  },
  "langchain-unsafe-template": {
    description: "Use input validation for LangChain template variables",
    fix: (line) => '# TODO: Sanitize template variables before use\n' + line
  },
  "langchain-chain-unsafe": {
    description: "Validate user input before LangChain chain execution",
    fix: (line, lang) => {
      if (lang === 'python') {
        return line.replace(/\.run\s*\(\s*(\w+)/, '.run(sanitize_chain_input($1)');
      }
      return line.replace(/\.invoke\s*\(\s*(\w+)/, '.invoke(sanitizeChainInput($1)');
    }
  },
  "langchain-agent-unsafe": {
    description: "Validate user input before LangChain agent execution",
    fix: (line) => '# SECURITY: Validate and sanitize user input before agent execution\n' + line
  },
  "eval-llm-response": {
    description: "CRITICAL: Never eval() LLM responses - use JSON parsing or ast.literal_eval for safe subset",
    fix: (line, lang) => {
      if (lang === 'python') {
        return line.replace(/eval\s*\(\s*(\w+)/, 'ast.literal_eval($1  # SECURITY: Use safe parsing only');
      }
      return line.replace(/eval\s*\(\s*(\w+)/, 'JSON.parse($1  /* SECURITY: Use safe JSON parsing */');
    }
  },
  "exec-llm-response": {
    description: "CRITICAL: Never exec() LLM responses - remove or use sandboxed execution",
    fix: (line) => '# SECURITY CRITICAL: Removed dangerous exec() of LLM response\n# ' + line
  },
  "function-constructor": {
    description: "CRITICAL: Never use new Function() with LLM responses",
    fix: (line) => '// SECURITY CRITICAL: Removed dangerous Function constructor with LLM response\n// ' + line
  },
  "pickle-llm-response": {
    description: "Use JSON instead of pickle for LLM response deserialization",
    fix: (line) => line.replace(/pickle\.(loads?)\s*\(/, 'json.$1(')
  },
  "ignore-previous-instructions": {
    description: "Detected prompt injection pattern - sanitize or reject this input",
    fix: (line) => '# SECURITY: Detected prompt injection attempt - INPUT SHOULD BE REJECTED\n# ' + line
  },
  "jailbreak-dan": {
    description: "Detected DAN jailbreak attempt - reject this input",
    fix: (line) => '# SECURITY: Detected jailbreak attempt - INPUT REJECTED\n# ' + line
  },
  "jailbreak-roleplay": {
    description: "Detected role-play jailbreak attempt - sanitize or reject",
    fix: (line) => '# SECURITY: Potential jailbreak via role-play - validate input\n# ' + line
  },
  "system-prompt-extraction": {
    description: "Detected system prompt extraction attempt - reject this input",
    fix: (line) => '# SECURITY: System prompt extraction attempt blocked\n# ' + line
  },
  "delimiter-injection": {
    description: "Detected delimiter injection - escape special characters or reject",
    fix: (line) => '# SECURITY: Delimiter injection blocked - escape special tokens\n# ' + line
  },
  "context-manipulation": {
    description: "Detected context manipulation attempt - validate input",
    fix: (line) => '# SECURITY: Context manipulation detected - validate user input\n# ' + line
  },

  // ===========================================
  // ADDITIONAL SECURITY FIXES
  // ===========================================
  "race-condition": {
    description: "Use mutex or sync primitives for shared state",
    fix: (line) => '// TODO: Add mutex protection - ' + line
  },
  "gin-bind": {
    description: "Use explicit binding in Gin handlers",
    fix: (line) => line.replace(/ShouldBind\s*\(/, 'ShouldBindJSON(')
  },
  "permit-all": {
    description: "Review permitAll() and restrict access",
    fix: (line) => '// SECURITY: Review permitAll() - ' + line
  }
};

// Detect language from file extension
function detectLanguage(filePath) {
  const ext = filePath.split('.').pop().toLowerCase();
  const langMap = {
    'py': 'python', 'js': 'javascript', 'ts': 'typescript',
    'tsx': 'typescript', 'jsx': 'javascript', 'java': 'java',
    'go': 'go', 'rb': 'ruby', 'php': 'php',
    // Prompt/text file extensions for prompt injection scanning
    'txt': 'generic', 'md': 'generic', 'prompt': 'generic',
    'jinja': 'generic', 'jinja2': 'generic', 'j2': 'generic'
  };
  return langMap[ext] || 'generic';
}

// Run the Python analyzer
function runAnalyzer(filePath) {
  try {
    const analyzerPath = join(__dirname, 'analyzer.py');
    const result = execSync(`python3 "${analyzerPath}" "${filePath}"`, {
      encoding: 'utf-8',
      timeout: 30000
    });
    return JSON.parse(result);
  } catch (error) {
    return { error: error.message };
  }
}

// Generate fix suggestion for an issue
function generateFix(issue, line, language) {
  const ruleId = issue.ruleId.toLowerCase();

  for (const [pattern, template] of Object.entries(FIX_TEMPLATES)) {
    if (ruleId.includes(pattern)) {
      return {
        description: template.description,
        original: line,
        fixed: template.fix(line, language)
      };
    }
  }

  return {
    description: "Review and fix manually based on the security rule",
    original: line,
    fixed: null
  };
}

// Create MCP Server
const server = new McpServer(
  {
    name: "security-scanner",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Register scan_security tool
server.tool(
  "scan_security",
  "Scan a file for security vulnerabilities and return issues with suggested fixes",
  {
    file_path: z.string().describe("Path to the file to scan")
  },
  async ({ file_path }) => {
    if (!existsSync(file_path)) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "File not found" }) }]
      };
    }

    const issues = runAnalyzer(file_path);

    if (issues.error) {
      return {
        content: [{ type: "text", text: JSON.stringify(issues) }]
      };
    }

    // Read file content for fix suggestions
    const content = readFileSync(file_path, 'utf-8');
    const lines = content.split('\n');
    const language = detectLanguage(file_path);

    // Enhance issues with fix suggestions
    const enhancedIssues = issues.map(issue => {
      const line = lines[issue.line] || '';
      const fix = generateFix(issue, line, language);
      return {
        ...issue,
        line_content: line.trim(),
        suggested_fix: fix
      };
    });

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          file: file_path,
          language: language,
          issues_count: enhancedIssues.length,
          issues: enhancedIssues
        }, null, 2)
      }]
    };
  }
);

// Register fix_security tool
server.tool(
  "fix_security",
  "Scan a file and return the fixed content with all security issues resolved",
  {
    file_path: z.string().describe("Path to the file to fix")
  },
  async ({ file_path }) => {
    if (!existsSync(file_path)) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "File not found" }) }]
      };
    }

    const issues = runAnalyzer(file_path);

    if (issues.error || !Array.isArray(issues) || issues.length === 0) {
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            message: issues.error ? "Error scanning file" : "No security issues found",
            details: issues
          })
        }]
      };
    }

    // Read and fix the file
    const content = readFileSync(file_path, 'utf-8');
    const lines = content.split('\n');
    const language = detectLanguage(file_path);
    const fixes = [];

    // Apply fixes (process in reverse order to preserve line numbers)
    const sortedIssues = [...issues].sort((a, b) => b.line - a.line);

    for (const issue of sortedIssues) {
      const lineIndex = issue.line;
      if (lineIndex >= 0 && lineIndex < lines.length) {
        const originalLine = lines[lineIndex];
        const fix = generateFix(issue, originalLine, language);

        if (fix.fixed && fix.fixed !== originalLine) {
          lines[lineIndex] = fix.fixed;
          fixes.push({
            line: lineIndex + 1,
            rule: issue.ruleId,
            original: originalLine.trim(),
            fixed: fix.fixed.trim(),
            description: fix.description
          });
        }
      }
    }

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          file: file_path,
          fixes_applied: fixes.length,
          fixes: fixes,
          fixed_content: lines.join('\n')
        }, null, 2)
      }]
    };
  }
);

// Register list_security_rules tool
server.tool(
  "list_security_rules",
  "List all available security fix templates and their descriptions",
  {},
  async () => {
    const rules = Object.entries(FIX_TEMPLATES).map(([id, template]) => ({
      pattern: id,
      description: template.description
    }));

    return {
      content: [{
        type: "text",
        text: JSON.stringify({ rules }, null, 2)
      }]
    };
  }
);

// ===========================================
// PACKAGE HALLUCINATION DETECTION
// ===========================================

// Load legitimate package lists into memory (hash sets for O(1) lookup)
const LEGITIMATE_PACKAGES = {
  dart: new Set(),
  perl: new Set(),
  raku: new Set(),
  npm: null,       // Uses Bloom Filter
  pypi: null,      // Uses Bloom Filter
  rubygems: null,  // Uses Bloom Filter
  crates: new Set()
};

// Bloom Filters for large ecosystems (npm, pypi, rubygems)
const BLOOM_FILTERS = {
  npm: null,
  pypi: null,
  rubygems: null
};

// Package counts for bloom filter ecosystems (filter doesn't store count)
const BLOOM_COUNTS = {
  npm: 3329177,
  pypi: 554762,
  rubygems: 180693
};

// Package import patterns by ecosystem
const IMPORT_PATTERNS = {
  dart: [
    /import\s+['"]package:([^\/'"]+)/g,
    /dependencies:\s*\n(?:\s+(\w+):\s*[\^~]?[\d.]+\n)+/g
  ],
  perl: [
    /use\s+([\w:]+)/g,
    /require\s+([\w:]+)/g
  ],
  raku: [
    /use\s+([\w:]+)/g,
    /need\s+([\w:]+)/g
  ],
  npm: [
    /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /from\s+['"]([^'"]+)['"]/g,
    /import\s+['"]([^'"]+)['"]/g
  ],
  pypi: [
    /^import\s+([\w]+)/gm,
    /^from\s+([\w]+)/gm
  ],
  rubygems: [
    /require\s+['"]([^'"]+)['"]/g,
    /gem\s+['"]([^'"]+)['"]/g,
    /require_relative\s+['"]([^'"]+)['"]/g
  ],
  crates: [
    /use\s+([\w_]+)/g,
    /extern\s+crate\s+([\w_]+)/g,
    /^\s*[\w_-]+\s*=/gm  // Cargo.toml dependencies
  ]
};

// Load package lists on startup
function loadPackageLists() {
  const packagesDir = join(__dirname, 'packages');

  // Load Bloom Filter ecosystems (npm, pypi, rubygems)
  for (const ecosystem of Object.keys(BLOOM_FILTERS)) {
    try {
      const bloomPath = join(packagesDir, `${ecosystem}-bloom.json`);
      if (existsSync(bloomPath)) {
        const bloomData = JSON.parse(readFileSync(bloomPath, 'utf-8'));
        BLOOM_FILTERS[ecosystem] = BloomFilter.fromJSON(bloomData);
        console.error(`Loaded ${ecosystem} Bloom Filter (${BLOOM_COUNTS[ecosystem].toLocaleString()} packages)`);
      }
    } catch (error) {
      console.error(`Warning: Could not load ${ecosystem} Bloom Filter: ${error.message}`);
    }
  }

  // Load other ecosystems using regular Set (smaller lists)
  for (const ecosystem of Object.keys(LEGITIMATE_PACKAGES)) {
    if (BLOOM_FILTERS.hasOwnProperty(ecosystem)) continue; // Uses Bloom Filter

    const filePath = join(packagesDir, `${ecosystem}.txt`);
    try {
      if (existsSync(filePath)) {
        const content = readFileSync(filePath, 'utf-8');
        const packages = content.split('\n').filter(p => p.trim());
        LEGITIMATE_PACKAGES[ecosystem] = new Set(packages);
        console.error(`Loaded ${packages.length} ${ecosystem} packages`);
      }
    } catch (error) {
      console.error(`Warning: Could not load ${ecosystem} packages: ${error.message}`);
    }
  }

  // Note about npm if not loaded
  if (!BLOOM_FILTERS.npm) {
    console.error(`npm: not included (use agent-security-scanner-mcp-full for npm support)`);
  }
}

// Extract package names from code
function extractPackages(code, ecosystem) {
  const packages = new Set();
  const patterns = IMPORT_PATTERNS[ecosystem] || [];

  for (const pattern of patterns) {
    const regex = new RegExp(pattern.source, pattern.flags);
    let match;
    while ((match = regex.exec(code)) !== null) {
      const pkg = match[1];
      if (pkg && !pkg.startsWith('.') && !pkg.startsWith('/')) {
        // Normalize package name (handle scoped packages, subpaths)
        const basePkg = pkg.split('/')[0].replace(/^@/, '');
        packages.add(basePkg);
      }
    }
  }

  return Array.from(packages);
}

// Check if a package exists in the package list
function packageExists(packageName, ecosystem) {
  // Bloom Filter ecosystems
  if (BLOOM_FILTERS.hasOwnProperty(ecosystem)) {
    return BLOOM_FILTERS[ecosystem] ? BLOOM_FILTERS[ecosystem].has(packageName) : false;
  }
  // Set-based ecosystems
  const legitPackages = LEGITIMATE_PACKAGES[ecosystem];
  return legitPackages ? legitPackages.has(packageName) : false;
}

// Get package count for an ecosystem
function getPackageCount(ecosystem) {
  // Bloom Filter ecosystems
  if (BLOOM_FILTERS.hasOwnProperty(ecosystem)) {
    return BLOOM_FILTERS[ecosystem] ? BLOOM_COUNTS[ecosystem] : 0;
  }
  // Set-based ecosystems
  const legitPackages = LEGITIMATE_PACKAGES[ecosystem];
  return legitPackages ? legitPackages.size : 0;
}

// Check if ecosystem is loaded
function isEcosystemLoaded(ecosystem) {
  // Bloom Filter ecosystems
  if (BLOOM_FILTERS.hasOwnProperty(ecosystem)) {
    return BLOOM_FILTERS[ecosystem] !== null;
  }
  // Set-based ecosystems
  const legitPackages = LEGITIMATE_PACKAGES[ecosystem];
  return legitPackages && legitPackages.size > 0;
}

// Check if a package is hallucinated
function isHallucinated(packageName, ecosystem) {
  if (!isEcosystemLoaded(ecosystem)) {
    return { unknown: true, reason: `No package list loaded for ${ecosystem}` };
  }
  return { hallucinated: !packageExists(packageName, ecosystem) };
}

// Register check_package tool
server.tool(
  "check_package",
  "Check if a package name is legitimate or potentially hallucinated (AI-invented)",
  {
    package_name: z.string().describe("The package name to verify"),
    ecosystem: z.enum(["dart", "perl", "raku", "npm", "pypi", "rubygems", "crates"]).describe("The package ecosystem (dart=pub.dev, perl=CPAN, raku=raku.land, npm=npmjs, pypi=PyPI, rubygems=RubyGems, crates=crates.io)")
  },
  async ({ package_name, ecosystem }) => {
    // Check if npm is requested but not available
    if (ecosystem === 'npm' && !BLOOM_FILTERS.npm) {
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            package: package_name,
            ecosystem,
            status: "unavailable",
            reason: "npm hallucination detection not included in default package (saves 7.6 MB)",
            suggestion: "Use 'agent-security-scanner-mcp-full' for npm support, or verify manually at npmjs.com"
          }, null, 2)
        }]
      };
    }

    const totalPackages = getPackageCount(ecosystem);

    if (!isEcosystemLoaded(ecosystem)) {
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            package: package_name,
            ecosystem,
            status: "unknown",
            reason: `No package list loaded for ${ecosystem}`,
            suggestion: "Verify manually at the package registry"
          }, null, 2)
        }]
      };
    }

    const exists = packageExists(package_name, ecosystem);

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          package: package_name,
          ecosystem,
          legitimate: exists,
          hallucinated: !exists,
          confidence: "high",
          total_known_packages: totalPackages,
          recommendation: exists
            ? "Package exists in registry - safe to use"
            : "⚠️ POTENTIAL HALLUCINATION - Package not found in registry. Verify before using!"
        }, null, 2)
      }]
    };
  }
);

// Register scan_packages tool
server.tool(
  "scan_packages",
  "Scan code for package imports and check for hallucinated (AI-invented) packages",
  {
    file_path: z.string().describe("Path to the file to scan"),
    ecosystem: z.enum(["dart", "perl", "raku", "npm", "pypi", "rubygems", "crates"]).describe("The package ecosystem (dart=pub.dev, perl=CPAN, raku=raku.land, npm=npmjs, pypi=PyPI, rubygems=RubyGems, crates=crates.io)")
  },
  async ({ file_path, ecosystem }) => {
    if (!existsSync(file_path)) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "File not found" }) }]
      };
    }

    // Check if npm is requested but not available
    if (ecosystem === 'npm' && !BLOOM_FILTERS.npm) {
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            file: file_path,
            ecosystem,
            status: "unavailable",
            reason: "npm hallucination detection not included in default package (saves 7.6 MB)",
            suggestion: "Use 'agent-security-scanner-mcp-full' for npm support, or verify manually at npmjs.com"
          }, null, 2)
        }]
      };
    }

    const code = readFileSync(file_path, 'utf-8');
    const packages = extractPackages(code, ecosystem);
    const totalKnown = getPackageCount(ecosystem);

    if (!isEcosystemLoaded(ecosystem)) {
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            file: file_path,
            ecosystem,
            packages_found: packages,
            status: "unknown",
            reason: `No package list loaded for ${ecosystem}`
          }, null, 2)
        }]
      };
    }

    const results = packages.map(pkg => ({
      package: pkg,
      legitimate: packageExists(pkg, ecosystem),
      hallucinated: !packageExists(pkg, ecosystem)
    }));

    const hallucinated = results.filter(r => r.hallucinated);
    const legitimate = results.filter(r => r.legitimate);

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          file: file_path,
          ecosystem,
          total_packages_found: packages.length,
          legitimate_count: legitimate.length,
          hallucinated_count: hallucinated.length,
          known_packages_in_registry: totalKnown,
          hallucinated_packages: hallucinated.map(r => r.package),
          legitimate_packages: legitimate.map(r => r.package),
          all_results: results,
          recommendation: hallucinated.length > 0
            ? `⚠️ Found ${hallucinated.length} potentially hallucinated package(s): ${hallucinated.map(r => r.package).join(', ')}`
            : "✅ All packages verified as legitimate"
        }, null, 2)
      }]
    };
  }
);

// Register list_package_stats tool
server.tool(
  "list_package_stats",
  "List statistics about loaded package lists for hallucination detection",
  {},
  async () => {
    const ecosystems = ['npm', 'pypi', 'rubygems', 'crates', 'dart', 'perl', 'raku'];
    const stats = ecosystems.map(ecosystem => {
      const loaded = isEcosystemLoaded(ecosystem);
      let status = loaded ? "ready" : "not loaded";
      let storage = BLOOM_FILTERS.hasOwnProperty(ecosystem) ? "bloom filter" : "hash set";

      // npm is not included in default package
      if (ecosystem === 'npm' && !loaded) {
        status = "not included (use -full package)";
      }

      return {
        ecosystem,
        packages_loaded: loaded ? getPackageCount(ecosystem) : 0,
        status,
        storage
      };
    });

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          package_lists: stats,
          total_packages: stats.reduce((sum, s) => sum + s.packages_loaded, 0),
          usage: "Use check_package or scan_packages to detect hallucinated packages"
        }, null, 2)
      }]
    };
  }
);

// ===========================================
// AGENT PROMPT SECURITY SCANNING
// ===========================================

// Risk thresholds for action determination
const RISK_THRESHOLDS = {
  CRITICAL: 85,
  HIGH: 70,
  MEDIUM: 50,
  LOW: 25
};

// Category weights for risk calculation
const CATEGORY_WEIGHTS = {
  "exfiltration": 1.0,
  "malicious-injection": 1.0,
  "system-manipulation": 1.0,
  "social-engineering": 0.8,
  "obfuscation": 0.7,
  "agent-manipulation": 0.9,
  "prompt-injection": 0.9,
  "prompt-injection-content": 0.9,
  "prompt-injection-jailbreak": 0.85,
  "prompt-injection-extraction": 0.9,
  "prompt-injection-delimiter": 0.8
};

// Confidence multipliers
const CONFIDENCE_MULTIPLIERS = {
  "HIGH": 1.0,
  "MEDIUM": 0.7,
  "LOW": 0.4
};

// Load agent attack rules from YAML
function loadAgentAttackRules() {
  try {
    const rulesPath = join(__dirname, 'rules', 'agent-attacks.security.yaml');
    if (!existsSync(rulesPath)) {
      console.error("Agent attack rules file not found");
      return [];
    }

    const yaml = readFileSync(rulesPath, 'utf-8');
    const rules = [];

    // Simple YAML parsing for rules
    const ruleBlocks = yaml.split(/^  - id:/m).slice(1);

    for (const block of ruleBlocks) {
      const lines = ('  - id:' + block).split('\n');
      const rule = {
        id: '',
        severity: 'WARNING',
        message: '',
        patterns: [],
        metadata: {}
      };

      let inPatterns = false;
      let inMetadata = false;

      for (const line of lines) {
        if (line.match(/^\s+- id:\s*/)) {
          rule.id = line.replace(/^\s+- id:\s*/, '').trim();
        } else if (line.match(/^\s+severity:\s*/)) {
          rule.severity = line.replace(/^\s+severity:\s*/, '').trim();
        } else if (line.match(/^\s+message:\s*/)) {
          rule.message = line.replace(/^\s+message:\s*["']?/, '').replace(/["']$/, '').trim();
        } else if (line.match(/^\s+patterns:\s*$/)) {
          inPatterns = true;
          inMetadata = false;
        } else if (line.match(/^\s+metadata:\s*$/)) {
          inPatterns = false;
          inMetadata = true;
        } else if (inPatterns && line.match(/^\s+- /)) {
          let pattern = line.replace(/^\s+- /, '').trim();
          pattern = pattern.replace(/^["']|["']$/g, '');
          // Strip Python-style inline flags - JS doesn't support them
          pattern = pattern.replace(/^\(\?i\)/, '');
          // Unescape double backslashes from YAML (\\s -> \s)
          pattern = pattern.replace(/\\\\/g, '\\');
          if (pattern) rule.patterns.push(pattern);
        } else if (inMetadata && line.match(/^\s+\w+:/)) {
          const match = line.match(/^\s+(\w+):\s*["']?([^"'\n]+)["']?/);
          if (match) {
            rule.metadata[match[1]] = match[2].trim();
          }
        } else if (line.match(/^\s+languages:/)) {
          inPatterns = false;
          inMetadata = false;
        }
      }

      if (rule.id && rule.patterns.length > 0) {
        rules.push(rule);
      }
    }

    return rules;
  } catch (error) {
    console.error("Error loading agent attack rules:", error.message);
    return [];
  }
}

// Also load prompt injection rules
function loadPromptInjectionRules() {
  try {
    const rulesPath = join(__dirname, 'rules', 'prompt-injection.security.yaml');
    if (!existsSync(rulesPath)) {
      return [];
    }

    const yaml = readFileSync(rulesPath, 'utf-8');
    const rules = [];

    const ruleBlocks = yaml.split(/^  - id:/m).slice(1);

    for (const block of ruleBlocks) {
      const lines = ('  - id:' + block).split('\n');
      const rule = {
        id: '',
        severity: 'WARNING',
        message: '',
        patterns: [],
        metadata: {}
      };

      let inPatterns = false;
      let inMetadata = false;

      for (const line of lines) {
        if (line.match(/^\s+- id:\s*/)) {
          rule.id = line.replace(/^\s+- id:\s*/, '').trim();
        } else if (line.match(/^\s+severity:\s*/)) {
          rule.severity = line.replace(/^\s+severity:\s*/, '').trim();
        } else if (line.match(/^\s+message:\s*/)) {
          rule.message = line.replace(/^\s+message:\s*["']?/, '').replace(/["']$/, '').trim();
        } else if (line.match(/^\s+patterns:\s*$/)) {
          inPatterns = true;
          inMetadata = false;
        } else if (line.match(/^\s+metadata:\s*$/)) {
          inPatterns = false;
          inMetadata = true;
        } else if (inPatterns && line.match(/^\s+- /)) {
          let pattern = line.replace(/^\s+- /, '').trim();
          pattern = pattern.replace(/^["']|["']$/g, '');
          // Strip Python-style inline flags - JS doesn't support them
          pattern = pattern.replace(/^\(\?i\)/, '');
          // Unescape double backslashes from YAML (\\s -> \s)
          pattern = pattern.replace(/\\\\/g, '\\');
          if (pattern) rule.patterns.push(pattern);
        } else if (inMetadata && line.match(/^\s+\w+:/)) {
          const match = line.match(/^\s+(\w+):\s*["']?([^"'\n]+)["']?/);
          if (match) {
            rule.metadata[match[1]] = match[2].trim();
          }
        }
      }

      // Only include generic rules (content patterns, not code patterns)
      if (rule.id && rule.patterns.length > 0 && rule.id.startsWith('generic.prompt')) {
        rules.push(rule);
      }
    }

    return rules;
  } catch (error) {
    console.error("Error loading prompt injection rules:", error.message);
    return [];
  }
}

// Calculate risk score from findings
function calculateRiskScore(findings, context) {
  if (findings.length === 0) return 0;

  let totalScore = 0;

  for (const finding of findings) {
    const riskScore = parseInt(finding.risk_score) || 50;
    const category = finding.category || 'unknown';
    const confidence = finding.confidence || 'MEDIUM';

    const categoryWeight = CATEGORY_WEIGHTS[category] || 0.5;
    const confidenceMultiplier = CONFIDENCE_MULTIPLIERS[confidence] || 0.7;

    totalScore += (riskScore / 100) * categoryWeight * confidenceMultiplier * 100;
  }

  // Average the scores but boost for multiple findings
  let avgScore = totalScore / findings.length;

  // Boost score if multiple findings (compound risk)
  if (findings.length > 1) {
    avgScore = Math.min(100, avgScore * (1 + (findings.length - 1) * 0.1));
  }

  // Apply sensitivity adjustment
  if (context?.sensitivity_level === 'high') {
    avgScore = Math.min(100, avgScore * 1.2);
  } else if (context?.sensitivity_level === 'low') {
    avgScore = avgScore * 0.8;
  }

  return Math.round(avgScore);
}

// Determine action based on risk score and findings
function determineAction(riskScore, findings) {
  // Check for any BLOCK action findings
  const hasBlockFinding = findings.some(f => f.action === 'BLOCK');
  if (hasBlockFinding || riskScore >= RISK_THRESHOLDS.CRITICAL) {
    return 'BLOCK';
  }

  if (riskScore >= RISK_THRESHOLDS.HIGH) {
    return 'BLOCK';
  }

  const hasWarnFinding = findings.some(f => f.action === 'WARN');
  if (hasWarnFinding || riskScore >= RISK_THRESHOLDS.MEDIUM) {
    return 'WARN';
  }

  const hasLogFinding = findings.some(f => f.action === 'LOG');
  if (hasLogFinding || riskScore >= RISK_THRESHOLDS.LOW) {
    return 'LOG';
  }

  return 'ALLOW';
}

// Determine risk level from score
function getRiskLevel(score) {
  if (score >= RISK_THRESHOLDS.CRITICAL) return 'CRITICAL';
  if (score >= RISK_THRESHOLDS.HIGH) return 'HIGH';
  if (score >= RISK_THRESHOLDS.MEDIUM) return 'MEDIUM';
  if (score >= RISK_THRESHOLDS.LOW) return 'LOW';
  return 'NONE';
}

// Generate explanation from findings
function generateExplanation(findings, action) {
  if (findings.length === 0) {
    return 'No security concerns detected in this prompt.';
  }

  const categories = [...new Set(findings.map(f => f.category))];
  const severity = findings.some(f => f.severity === 'ERROR') ? 'critical' : 'potential';

  let explanation = `Detected ${findings.length} ${severity} security concern(s)`;

  if (categories.length > 0) {
    explanation += ` in categories: ${categories.join(', ')}`;
  }

  explanation += `. Action: ${action}.`;

  if (action === 'BLOCK') {
    explanation += ' This prompt appears to contain malicious intent and should not be executed.';
  } else if (action === 'WARN') {
    explanation += ' Review carefully before proceeding.';
  }

  return explanation;
}

// Generate recommendations from findings
function generateRecommendations(findings) {
  const recommendations = new Set();

  for (const finding of findings) {
    const category = finding.category;

    switch (category) {
      case 'exfiltration':
        recommendations.add('Never allow prompts that request sending code or secrets to external URLs');
        recommendations.add('Block access to sensitive files like .env, SSH keys, and credentials');
        break;
      case 'malicious-injection':
        recommendations.add('Reject requests for backdoors, reverse shells, or malicious code');
        recommendations.add('Never disable security controls at user request');
        break;
      case 'system-manipulation':
        recommendations.add('Block destructive file operations and system configuration changes');
        recommendations.add('Prevent persistence mechanisms like crontab or startup script modifications');
        break;
      case 'social-engineering':
        recommendations.add('Verify authorization claims through proper channels, not prompt content');
        recommendations.add('Be skeptical of urgency claims or claims of special modes');
        break;
      case 'obfuscation':
        recommendations.add('Be wary of encoded or fragmented instructions');
        recommendations.add('Reject requests for "examples" of malicious code');
        break;
      case 'agent-manipulation':
        recommendations.add('Maintain confirmation prompts for sensitive operations');
        recommendations.add('Never hide output or actions from the user');
        break;
      default:
        recommendations.add('Review this prompt carefully before execution');
    }
  }

  return [...recommendations];
}

// Create SHA256 hash for audit logging
function hashPrompt(text) {
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(text).digest('hex').substring(0, 16);
}

// Register scan_agent_prompt tool
server.tool(
  "scan_agent_prompt",
  "Scan a prompt/instruction for potential malicious intent before execution. Returns risk assessment and recommended action (BLOCK/WARN/LOG/ALLOW).",
  {
    prompt_text: z.string().describe("The prompt or instruction text to analyze"),
    context: z.object({
      previous_messages: z.array(z.string()).optional().describe("Previous conversation messages for multi-turn detection"),
      sensitivity_level: z.enum(["high", "medium", "low"]).optional().describe("Sensitivity level - high means more strict, low means more permissive")
    }).optional().describe("Optional context for better analysis")
  },
  async ({ prompt_text, context }) => {
    const findings = [];

    // Load rules
    const agentRules = loadAgentAttackRules();
    const promptRules = loadPromptInjectionRules();
    const allRules = [...agentRules, ...promptRules];

    // Scan prompt against all rules
    for (const rule of allRules) {
      for (const pattern of rule.patterns) {
        try {
          const regex = new RegExp(pattern, 'i');
          const match = prompt_text.match(regex);

          if (match) {
            findings.push({
              rule_id: rule.id,
              category: rule.metadata.category || 'unknown',
              severity: rule.severity,
              message: rule.message,
              matched_text: match[0].substring(0, 100),
              confidence: rule.metadata.confidence || 'MEDIUM',
              risk_score: rule.metadata.risk_score || '50',
              action: rule.metadata.action || 'WARN'
            });
            break; // Only one match per rule
          }
        } catch (e) {
          // Skip invalid regex
        }
      }
    }

    // Calculate risk score
    const riskScore = calculateRiskScore(findings, context);
    const action = determineAction(riskScore, findings);
    const riskLevel = getRiskLevel(riskScore);
    const explanation = generateExplanation(findings, action);
    const recommendations = generateRecommendations(findings);

    // Create audit info
    const audit = {
      timestamp: new Date().toISOString(),
      prompt_hash: hashPrompt(prompt_text),
      prompt_length: prompt_text.length,
      rules_checked: allRules.length,
      context_provided: !!context
    };

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          action,
          risk_score: riskScore,
          risk_level: riskLevel,
          findings_count: findings.length,
          findings: findings.map(f => ({
            rule_id: f.rule_id,
            category: f.category,
            severity: f.severity,
            message: f.message,
            matched_text: f.matched_text,
            confidence: f.confidence
          })),
          explanation,
          recommendations,
          audit
        }, null, 2)
      }]
    };
  }
);

// Load package lists on module initialization
loadPackageLists();

// Start the server with stdio transport
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Security Scanner MCP Server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
