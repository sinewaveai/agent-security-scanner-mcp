// OSV.dev API client for vulnerability enrichment.
// M1 scope: OSV only. NVD/GHSA as future providers.

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { buildPurl } from './purl.js';

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const BATCH_SIZE = 1000;
const FETCH_TIMEOUT = 30000;
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Query OSV.dev for vulnerabilities affecting a list of packages.
 * Accepts normalized components (with purl, namespace) to avoid lossy flattening.
 * Uses local cache to avoid redundant network calls.
 * @param {Array<{ name: string, version: string, ecosystem: string, purl?: string, namespace?: string }>} packages
 * @param {{ cacheDir?: string }} [options={}]
 * @returns {Promise<Map<string, object[]>>} Map of cacheKey → vulnerability list
 */
export async function queryBatch(packages, options = {}) {
  const { cacheDir } = options;
  const results = new Map();
  const uncached = [];

  // Check cache first
  for (const pkg of packages) {
    const cacheKey = getPackageIdentity(pkg);
    const cached = readCache(cacheDir, cacheKey);
    if (cached !== null) {
      if (cached.length > 0) results.set(cacheKey, cached);
      continue;
    }
    uncached.push(pkg);
  }

  if (uncached.length === 0) return results;

  // Map ecosystem names to OSV ecosystem names
  const ecosystemMap = {
    npm: 'npm',
    pypi: 'PyPI',
    rubygems: 'RubyGems',
    crates: 'crates.io',
    go: 'Go',
    java: 'Maven',
    dart: 'Pub',
  };

  // Batch into chunks of BATCH_SIZE
  for (let i = 0; i < uncached.length; i += BATCH_SIZE) {
    const chunk = uncached.slice(i, i + BATCH_SIZE);
    const queries = chunk.map(pkg => ({
      package: {
        name: pkg.ecosystem === 'java' && pkg.namespace
          ? `${pkg.namespace}:${pkg.name}` : pkg.name,
        ecosystem: ecosystemMap[pkg.ecosystem] || pkg.ecosystem,
      },
      version: pkg.version,
    }));

    try {
      const response = await fetchWithRetry(OSV_BATCH_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queries }),
      });

      if (!response.ok) continue;

      const data = await response.json();
      const batchResults = data.results || [];

      for (let j = 0; j < chunk.length; j++) {
        const pkg = chunk[j];
        const cacheKey = getPackageIdentity(pkg);
        const vulns = (batchResults[j] && batchResults[j].vulns) || [];
        const mapped = vulns.map(v => mapOsvVulnerability(v, pkg));

        writeCache(cacheDir, cacheKey, mapped);
        if (mapped.length > 0) results.set(cacheKey, mapped);
      }
    } catch {
      // Network error — skip this batch, don't cache
    }
  }

  return results;
}

async function fetchWithRetry(url, options, retries = 1) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT);

  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(timeout);
    if (response.status === 429 && retries > 0) {
      await new Promise(r => setTimeout(r, 2000));
      return fetchWithRetry(url, options, retries - 1);
    }
    return response;
  } catch (err) {
    clearTimeout(timeout);
    if (retries > 0) {
      await new Promise(r => setTimeout(r, 1000));
      return fetchWithRetry(url, options, retries - 1);
    }
    throw err;
  }
}

/**
 * Map an OSV vulnerability to CycloneDX vulnerability format.
 */
function mapOsvVulnerability(osvEntry, pkg) {
  const cveId = (osvEntry.aliases || []).find(a => a.startsWith('CVE-')) || osvEntry.id;
  const severity = extractSeverity(osvEntry);
  const fixedVersion = extractFixedVersion(osvEntry, pkg);

  return {
    id: cveId,
    source: { name: 'OSV', url: `https://osv.dev/vulnerability/${osvEntry.id}` },
    ratings: [{
      score: severity.score,
      severity: severity.level,
      method: severity.method || 'other',
    }],
    description: osvEntry.summary || osvEntry.details || '',
    affects: [{
      ref: getPackageIdentity(pkg),
    }],
    ...(fixedVersion && {
      recommendation: `Upgrade to ${fixedVersion}`,
    }),
    properties: [
      { name: 'osv:id', value: osvEntry.id },
      ...(osvEntry.aliases || []).filter(a => a !== cveId).map(a => ({ name: 'alias', value: a })),
    ],
  };
}

function getPackageIdentity(pkg) {
  if (pkg.purl) return pkg.purl;

  const purl = buildPurl(pkg.ecosystem, pkg.name, pkg.version, pkg.namespace);
  if (purl) return purl;

  if (pkg.namespace) {
    return `${pkg.ecosystem}:${pkg.namespace}:${pkg.name}@${pkg.version}`;
  }
  return `${pkg.ecosystem}:${pkg.name}@${pkg.version}`;
}

function extractSeverity(osvEntry) {
  // Try CVSS from severity array
  if (osvEntry.severity && osvEntry.severity.length > 0) {
    for (const sev of osvEntry.severity) {
      if (sev.type === 'CVSS_V3') {
        const score = parseCvssScore(sev.score);
        if (score !== null) {
          return { score, level: scoreToLevel(score), method: 'CVSSv3' };
        }
      }
    }
  }
  // Try database_specific
  if (osvEntry.database_specific && osvEntry.database_specific.severity) {
    const level = osvEntry.database_specific.severity.toLowerCase();
    return { score: levelToScore(level), level, method: 'other' };
  }
  return { score: 0, level: 'unknown', method: 'other' };
}

function parseCvssScore(cvssString) {
  if (typeof cvssString === 'number') return cvssString;
  // CVSS vector strings don't contain the score directly; try to extract from a numeric prefix
  const num = parseFloat(cvssString);
  return isNaN(num) ? null : num;
}

/**
 * Map CVSS score to severity level.
 * @param {number} score
 * @returns {string}
 */
export function scoreToLevel(score) {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score > 0) return 'low';
  return 'unknown';
}

function levelToScore(level) {
  switch (level) {
    case 'critical': return 9.5;
    case 'high': return 7.5;
    case 'medium': return 5.0;
    case 'moderate': return 5.0;
    case 'low': return 2.5;
    default: return 0;
  }
}

function extractFixedVersion(osvEntry, pkg) {
  if (!osvEntry.affected) return null;
  for (const affected of osvEntry.affected) {
    if (affected.package && affected.package.name === pkg.name) {
      for (const range of affected.ranges || []) {
        for (const event of range.events || []) {
          if (event.fixed) return event.fixed;
        }
      }
    }
  }
  return null;
}

// ─── Local cache ─────────────────────────────────────────────────────

function getCachePath(cacheDir, key) {
  if (!cacheDir) return null;
  // Sanitize key for filesystem
  const safe = key.replace(/[^a-zA-Z0-9@._-]/g, '_');
  return join(cacheDir, `${safe}.json`);
}

function readCache(cacheDir, key) {
  const path = getCachePath(cacheDir, key);
  if (!path || !existsSync(path)) return null;

  try {
    const data = JSON.parse(readFileSync(path, 'utf-8'));
    if (Date.now() - data.timestamp > CACHE_TTL_MS) return null; // expired
    return data.vulns;
  } catch {
    return null;
  }
}

function writeCache(cacheDir, key, vulns) {
  const path = getCachePath(cacheDir, key);
  if (!path) return;

  try {
    if (!existsSync(cacheDir)) {
      mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
    }
    writeFileSync(path, JSON.stringify({ timestamp: Date.now(), vulns }, null, 2), { mode: 0o600 });
  } catch {
    // Cache write failure is non-fatal
  }
}
