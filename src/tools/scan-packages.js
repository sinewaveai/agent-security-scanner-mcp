import { z } from "zod";
import { readFileSync, existsSync } from "fs";
import { isHallucinated, getTotalPackages } from './check-package.js';

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

// Extract package names from code
export function extractPackages(code, ecosystem) {
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

// Schema for scan_packages tool
export const scanPackagesSchema = {
  file_path: z.string().describe("Path to the file to scan"),
  ecosystem: z.enum(["dart", "perl", "raku", "npm", "pypi", "rubygems", "crates"]).describe("The package ecosystem (dart=pub.dev, perl=CPAN, raku=raku.land, npm=npmjs, pypi=PyPI, rubygems=RubyGems, crates=crates.io)")
};

// Handler for scan_packages tool
export async function scanPackages({ file_path, ecosystem }) {
  if (!existsSync(file_path)) {
    return {
      content: [{ type: "text", text: JSON.stringify({ error: "File not found" }) }]
    };
  }

  const code = readFileSync(file_path, 'utf-8');
  const packages = extractPackages(code, ecosystem);

  const results = packages.map(pkg => {
    const check = isHallucinated(pkg, ecosystem);
    if (check.unknown) {
      return { package: pkg, status: "unknown", reason: check.reason };
    }
    return {
      package: pkg,
      legitimate: !check.hallucinated,
      hallucinated: check.hallucinated,
      bloom_filter: !!check.bloomFilter,
      confidence: check.bloomFilter ? "medium" : "high"
    };
  });

  const hallucinated = results.filter(r => r.hallucinated);
  const legitimate = results.filter(r => r.legitimate);
  const unknown = results.filter(r => r.status === "unknown");
  const totalKnown = getTotalPackages(ecosystem);

  return {
    content: [{
      type: "text",
      text: JSON.stringify({
        file: file_path,
        ecosystem,
        total_packages_found: packages.length,
        legitimate_count: legitimate.length,
        hallucinated_count: hallucinated.length,
        unknown_count: unknown.length,
        known_packages_in_registry: totalKnown,
        hallucinated_packages: hallucinated.map(r => r.package),
        legitimate_packages: legitimate.map(r => r.package),
        all_results: results,
        recommendation: hallucinated.length > 0
          ? `⚠️ Found ${hallucinated.length} potentially hallucinated package(s): ${hallucinated.map(r => r.package).join(', ')}`
          : unknown.length > 0
            ? `⚠️ ${unknown.length} package(s) could not be verified (no data available for ${ecosystem})`
            : "✅ All packages verified as legitimate"
      }, null, 2)
    }]
  };
}
