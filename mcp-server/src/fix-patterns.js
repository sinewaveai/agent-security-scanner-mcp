// Helper: return correct env var access syntax per language
export function envVarReplacement(envName, lang) {
  switch(lang) {
    case 'python': return `os.environ.get("${envName}")`;
    case 'go': return `os.Getenv("${envName}")`;
    case 'java': return `System.getenv("${envName}")`;
    case 'php': return `getenv('${envName}')`;
    case 'ruby': return `ENV["${envName}"]`;
    case 'csharp': return `Environment.GetEnvironmentVariable("${envName}")`;
    case 'rust': return `std::env::var("${envName}").unwrap_or_default()`;
    case 'c': case 'cpp': return `getenv("${envName}")`;
    default: return `process.env.${envName}`;
  }
}

// Security fix templates - comprehensive coverage for 165+ rules
export const FIX_TEMPLATES = {
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
    fix: (line, lang) => line.replace(/=\s*["'][^"']+["']/, `= ${envVarReplacement("SECRET", lang)}`)
  },
  "api-key": {
    description: "Use environment variables for API keys",
    fix: (line, lang) => line.replace(/=\s*["'][^"']+["']/, `= ${envVarReplacement("API_KEY", lang)}`)
  },
  "password": {
    description: "Use environment variables for passwords",
    fix: (line, lang) => line.replace(/=\s*["'][^"']+["']/, `= ${envVarReplacement("PASSWORD", lang)}`)
  },
  "secret-key": {
    description: "Use environment variables for secret keys",
    fix: (line, lang) => line.replace(/=\s*["'][^"']+["']/, `= ${envVarReplacement("SECRET_KEY", lang)}`)
  },
  "aws-access": {
    description: "Use AWS credentials from environment or IAM roles",
    fix: (line, lang) => line.replace(/=\s*["']AKIA[^"']+["']/, `= ${envVarReplacement("AWS_ACCESS_KEY_ID", lang)}`)
  },
  "aws-secret": {
    description: "Use AWS credentials from environment or IAM roles",
    fix: (line, lang) => line.replace(/=\s*["'][^"']{40}["']/, `= ${envVarReplacement("AWS_SECRET_ACCESS_KEY", lang)}`)
  },
  "stripe": {
    description: "Use environment variables for Stripe keys",
    fix: (line, lang) => line.replace(/=\s*["']sk_(live|test)_[^"']+["']/, `= ${envVarReplacement("STRIPE_SECRET_KEY", lang)}`)
  },
  "github": {
    description: "Use environment variables for GitHub tokens",
    fix: (line, lang) => line.replace(/=\s*["'](ghp_|github_pat_)[^"']+["']/, `= ${envVarReplacement("GITHUB_TOKEN", lang)}`)
  },
  "openai": {
    description: "Use environment variables for OpenAI keys",
    fix: (line, lang) => line.replace(/=\s*["']sk-[^"']+["']/, `= ${envVarReplacement("OPENAI_API_KEY", lang)}`)
  },
  "slack": {
    description: "Use environment variables for Slack tokens",
    fix: (line, lang) => line.replace(/=\s*["']xox[baprs]-[^"']+["']/, `= ${envVarReplacement("SLACK_TOKEN", lang)}`)
  },
  "jwt-token": {
    description: "Use environment variables for JWT secrets",
    fix: (line, lang) => line.replace(/=\s*["'][^"']+["']/, `= ${envVarReplacement("JWT_SECRET", lang)}`)
  },
  "private-key": {
    description: "Load private keys from secure file or vault",
    fix: (line, lang) => {
      if (lang === 'python') return line.replace(/=\s*["']-----BEGIN[^"']+["']/, `= load_key_from_file(${envVarReplacement("PRIVATE_KEY_PATH", lang)})`);
      if (lang === 'go' || lang === 'java' || lang === 'csharp' || lang === 'rust' || lang === 'c' || lang === 'cpp')
        return line.replace(/=\s*["']-----BEGIN[^"']+["']/, `= ${envVarReplacement("PRIVATE_KEY_PATH", lang)}`);
      return line.replace(/=\s*["']-----BEGIN[^"']+["']/, '= fs.readFileSync(process.env.PRIVATE_KEY_PATH)');
    }
  },
  "database-url": {
    description: "Use environment variables for database URLs",
    fix: (line, lang) => line.replace(/=\s*["'][^"']+["']/, `= ${envVarReplacement("DATABASE_URL", lang)}`)
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
