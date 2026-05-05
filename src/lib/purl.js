// Package URL (PURL) builder — https://github.com/package-url/purl-spec

const ECOSYSTEM_TO_PURL_TYPE = {
  npm: 'npm',
  pypi: 'pypi',
  rubygems: 'gem',
  crates: 'cargo',
  go: 'golang',
  java: 'maven',
  dart: 'pub',
  perl: 'cpan',
  raku: 'cpan',
};

const PURL_TYPE_TO_ECOSYSTEM = {
  npm: 'npm',
  pypi: 'pypi',
  gem: 'rubygems',
  cargo: 'crates',
  golang: 'go',
  maven: 'java',
  pub: 'dart',
  cpan: 'perl',
};

/**
 * Build a Package URL string.
 * @param {string} ecosystem - Internal ecosystem name (npm, pypi, etc.)
 * @param {string} name - Package name
 * @param {string} [version] - Package version
 * @param {string} [namespace] - Optional namespace (e.g. Maven groupId)
 * @returns {string} PURL string like pkg:npm/express@4.18.2
 */
export function buildPurl(ecosystem, name, version, namespace) {
  const type = ECOSYSTEM_TO_PURL_TYPE[ecosystem] || ecosystem;
  if (!name) return '';

  let qualifiedName;

  if (type === 'npm' && name.startsWith('@')) {
    // Scoped npm: @scope/name → namespace=scope, name=name
    const [scope, pkg] = name.split('/');
    qualifiedName = `${encodeURIComponent(scope)}/${pkg}`;
  } else if (type === 'maven' && namespace) {
    qualifiedName = `${namespace}/${name}`;
  } else if (type === 'golang') {
    // Go modules use the full module path as-is
    qualifiedName = name;
  } else {
    qualifiedName = name;
  }

  return version
    ? `pkg:${type}/${qualifiedName}@${version}`
    : `pkg:${type}/${qualifiedName}`;
}

/**
 * Parse a PURL string back into components.
 * @param {string} purl
 * @returns {{ type: string, namespace?: string, name: string, version?: string } | null}
 */
export function parsePurl(purl) {
  const match = purl.match(/^pkg:([^/]+)\/(.+?)(?:@(.+))?$/);
  if (!match) return null;

  const [, type, qualifiedName, version] = match;
  const slashIdx = qualifiedName.lastIndexOf('/');

  if (slashIdx !== -1) {
    return {
      type,
      namespace: decodeURIComponent(qualifiedName.slice(0, slashIdx)),
      name: qualifiedName.slice(slashIdx + 1),
      ...(version && { version }),
    };
  }

  return {
    type,
    name: qualifiedName,
    ...(version && { version }),
  };
}

export function ecosystemFromPurlType(type) {
  return PURL_TYPE_TO_ECOSYSTEM[type] || type;
}

export { ECOSYSTEM_TO_PURL_TYPE, PURL_TYPE_TO_ECOSYSTEM };
