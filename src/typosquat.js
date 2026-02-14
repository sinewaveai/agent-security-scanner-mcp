// Typosquatting detection for package hallucination
// Checks suspicious package names against known popular packages per ecosystem

// Top popular packages per ecosystem for typosquat comparison
const TOP_PACKAGES = {
  npm: [
    'express', 'react', 'lodash', 'axios', 'chalk', 'commander', 'debug',
    'moment', 'request', 'uuid', 'bluebird', 'async', 'underscore', 'semver',
    'glob', 'minimist', 'yargs', 'mkdirp', 'rimraf', 'colors', 'webpack',
    'babel-core', 'typescript', 'eslint', 'jest', 'mocha', 'chai', 'sinon',
    'prettier', 'next', 'vue', 'angular', 'svelte', 'dotenv', 'cors',
    'helmet', 'mongoose', 'redis', 'pg', 'mysql2', 'socket.io', 'ws',
    'jsonwebtoken', 'bcrypt', 'passport', 'nodemon', 'pm2', 'gulp', 'grunt',
    'bower'
  ],
  pypi: [
    'requests', 'flask', 'django', 'numpy', 'pandas', 'scipy', 'boto3',
    'setuptools', 'pip', 'wheel', 'six', 'urllib3', 'certifi', 'idna',
    'chardet', 'pyyaml', 'jinja2', 'cryptography', 'pillow', 'matplotlib',
    'sqlalchemy', 'celery', 'redis', 'pytest', 'click', 'rich', 'fastapi',
    'pydantic', 'httpx', 'aiohttp', 'tornado', 'gunicorn', 'uvicorn',
    'black', 'mypy', 'pylint', 'flake8', 'tox', 'coverage', 'sphinx',
    'beautifulsoup4', 'scrapy', 'selenium', 'paramiko', 'fabric', 'ansible',
    'tensorflow', 'pytorch', 'scikit-learn'
  ],
  rubygems: [
    'rails', 'rake', 'bundler', 'rspec', 'sinatra', 'puma', 'unicorn',
    'devise', 'pundit', 'sidekiq', 'redis', 'pg', 'mysql2', 'activerecord',
    'actionpack', 'activesupport', 'nokogiri', 'httparty', 'faraday',
    'rest-client', 'json', 'minitest', 'capybara', 'factory_bot', 'faker',
    'rubocop', 'solargraph', 'pry', 'byebug', 'dotenv', 'figaro', 'jwt',
    'bcrypt', 'omniauth', 'paperclip', 'carrierwave', 'aws-sdk', 'stripe',
    'graphql', 'grape'
  ],
  crates: [
    'serde', 'tokio', 'clap', 'rand', 'log', 'reqwest', 'hyper',
    'actix-web', 'regex', 'lazy_static', 'chrono', 'uuid', 'futures',
    'async-std', 'anyhow', 'thiserror', 'tracing', 'env_logger', 'config',
    'diesel', 'sqlx', 'sea-orm', 'rocket', 'axum', 'warp', 'tower',
    'bytes', 'url', 'http', 'serde_json', 'toml', 'base64', 'sha2',
    'ring', 'rustls', 'rayon', 'crossbeam', 'parking_lot', 'dashmap',
    'once_cell'
  ]
};

/**
 * Compute the Levenshtein edit distance between two strings.
 * Uses a standard dynamic programming approach with O(min(m,n)) space.
 * @param {string} a - First string
 * @param {string} b - Second string
 * @returns {number} The edit distance between a and b
 */
export function levenshteinDistance(a, b) {
  // Ensure a is the shorter string to optimize space usage
  if (a.length > b.length) {
    [a, b] = [b, a];
  }

  const m = a.length;
  const n = b.length;

  // Early termination: if one string is empty, distance is the other's length
  if (m === 0) return n;

  // Use single row with rolling updates (O(min(m,n)) space)
  let prev = new Array(m + 1);
  let curr = new Array(m + 1);

  // Initialize first row
  for (let i = 0; i <= m; i++) {
    prev[i] = i;
  }

  for (let j = 1; j <= n; j++) {
    curr[0] = j;
    for (let i = 1; i <= m; i++) {
      if (a[i - 1] === b[j - 1]) {
        curr[i] = prev[i - 1];
      } else {
        curr[i] = 1 + Math.min(
          prev[i],      // deletion
          curr[i - 1],  // insertion
          prev[i - 1]   // substitution
        );
      }
    }
    // Swap rows
    [prev, curr] = [curr, prev];
  }

  return prev[m];
}

/**
 * Find popular packages that are similar to the given (possibly misspelled) package name.
 * Used to detect potential typosquatting attacks where a malicious package has a name
 * very close to a legitimate popular package.
 *
 * @param {string} packageName - The package name to check (not found in registry)
 * @param {string} ecosystem - The package ecosystem: 'npm', 'pypi', 'rubygems', or 'crates'
 * @param {number} [maxDistance=2] - Maximum Levenshtein distance to consider a match
 * @param {number} [limit=5] - Maximum number of similar packages to return
 * @returns {Array<{name: string, distance: number, warning: string}>} Similar packages sorted by distance
 */
export function findSimilarPackages(packageName, ecosystem, maxDistance = 2, limit = 5) {
  const knownPackages = TOP_PACKAGES[ecosystem];
  if (!knownPackages) {
    return [];
  }

  const normalizedInput = packageName.toLowerCase();
  const matches = [];

  for (const known of knownPackages) {
    const normalizedKnown = known.toLowerCase();

    // Skip exact matches -- the package exists, not a typosquat
    if (normalizedInput === normalizedKnown) {
      continue;
    }

    // Quick length-based pruning: if length difference exceeds maxDistance,
    // the edit distance must be at least that large
    if (Math.abs(normalizedInput.length - normalizedKnown.length) > maxDistance) {
      continue;
    }

    const distance = levenshteinDistance(normalizedInput, normalizedKnown);

    if (distance >= 1 && distance <= maxDistance) {
      matches.push({
        name: known,
        distance,
        warning: `Did you mean '${known}'? Possible typosquatting attack (edit distance: ${distance})`
      });
    }
  }

  // Sort by distance (closest first), then alphabetically for stable ordering
  matches.sort((a, b) => a.distance - b.distance || a.name.localeCompare(b.name));

  return matches.slice(0, limit);
}

// Common internal/private naming prefixes that may indicate dependency confusion risk
const INTERNAL_PREFIXES = [
  'internal-',
  'private-',
  'priv-',
  'corp-',
  'company-',
  'org-',
  'dev-',
  'local-'
];

// Pattern for scoped package names that look like company-internal packages
const SCOPED_PACKAGE_RE = /^@([a-z0-9-]+)\//;

/**
 * Check whether a package name shows signs of dependency confusion risk.
 * Dependency confusion attacks exploit the case where an internal (private) package
 * name is also published on a public registry, allowing an attacker to trick
 * package managers into installing the malicious public version.
 *
 * @param {string} packageName - The package name to check
 * @returns {{ risk: boolean, warning: string | null }} Risk assessment
 */
export function checkDependencyConfusion(packageName) {
  // Check for scoped packages (@company/X) -- the unscoped name X could exist publicly
  const scopedMatch = packageName.match(SCOPED_PACKAGE_RE);
  if (scopedMatch) {
    const scope = scopedMatch[1];
    const unscopedName = packageName.replace(SCOPED_PACKAGE_RE, '');

    // Check if the unscoped portion matches a known popular package
    for (const ecosystem of Object.keys(TOP_PACKAGES)) {
      const knownPackages = TOP_PACKAGES[ecosystem];
      if (knownPackages.includes(unscopedName)) {
        return {
          risk: true,
          warning: `Scoped package '${packageName}' contains unscoped name '${unscopedName}' which is a known public package. Verify this is the intended package to avoid dependency confusion.`
        };
      }
    }

    // Even without a known match, scoped names with common company-like scopes
    // are worth flagging as they follow internal naming patterns
    return {
      risk: true,
      warning: `Scoped package '${packageName}' follows an internal naming pattern (@${scope}/...). Ensure the scope is authentic and the package is not a dependency confusion attack targeting an internal package.`
    };
  }

  // Check for internal-looking prefixes
  const lowerName = packageName.toLowerCase();
  for (const prefix of INTERNAL_PREFIXES) {
    if (lowerName.startsWith(prefix)) {
      const baseName = lowerName.slice(prefix.length);
      if (baseName.length > 0) {
        return {
          risk: true,
          warning: `Package '${packageName}' uses the '${prefix}' prefix which suggests an internal/private package. If this is intended to be a public package, it may be a dependency confusion attack targeting the internal '${baseName}' package.`
        };
      }
    }
  }

  return { risk: false, warning: null };
}
