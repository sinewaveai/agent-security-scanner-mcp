import { z } from "zod";
import { readFileSync, existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import bloomFilters from "bloom-filters";
const { BloomFilter } = bloomFilters;

// Handle both ESM and CJS bundling (Smithery bundles to CJS)
let __dirname;
try {
  __dirname = dirname(fileURLToPath(import.meta.url));
} catch {
  __dirname = process.cwd();
}

// Load legitimate package lists into memory (hash sets for O(1) lookup)
const LEGITIMATE_PACKAGES = {
  dart: new Set(),
  perl: new Set(),
  raku: new Set(),
  npm: new Set(),
  pypi: new Set(),
  rubygems: new Set(),
  crates: new Set()
};

// Bloom filters for large package lists (memory-efficient probabilistic lookup)
const BLOOM_FILTERS = {
  npm: null,
  pypi: null,
  rubygems: null
};

// Load package lists on startup
export function loadPackageLists() {
  const packagesDir = join(__dirname, '..', '..', 'packages');

  for (const ecosystem of Object.keys(LEGITIMATE_PACKAGES)) {
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

  // Load bloom filters for large ecosystems (npm, pypi, rubygems)
  for (const ecosystem of Object.keys(BLOOM_FILTERS)) {
    const bloomPath = join(packagesDir, `${ecosystem}-bloom.json`);
    try {
      if (existsSync(bloomPath)) {
        const bloomData = JSON.parse(readFileSync(bloomPath, 'utf-8'));
        BLOOM_FILTERS[ecosystem] = BloomFilter.fromJSON(bloomData);
        console.error(`Loaded ${ecosystem} bloom filter (${bloomData._size} bits)`);
      }
    } catch (error) {
      console.error(`Warning: Could not load ${ecosystem} bloom filter: ${error.message}`);
    }
  }
}

// Check if a package is hallucinated
export function isHallucinated(packageName, ecosystem) {
  const legitPackages = LEGITIMATE_PACKAGES[ecosystem];

  // First check Set-based lookup (exact match)
  if (legitPackages && legitPackages.size > 0) {
    return { hallucinated: !legitPackages.has(packageName) };
  }

  // Fall back to bloom filter for large ecosystems (npm, pypi, rubygems)
  const bloomFilter = BLOOM_FILTERS[ecosystem];
  if (bloomFilter) {
    // Bloom filter: false = definitely not in set, true = probably in set
    const mightExist = bloomFilter.has(packageName);
    return {
      hallucinated: !mightExist,
      bloomFilter: true,
      note: mightExist ? "Package likely exists (bloom filter match)" : "Package not found in bloom filter"
    };
  }

  return { unknown: true, reason: `No package list loaded for ${ecosystem}` };
}

// Get total packages count for an ecosystem
export function getTotalPackages(ecosystem) {
  return LEGITIMATE_PACKAGES[ecosystem]?.size || 0;
}

// Get all package stats
export function getPackageStats() {
  const stats = Object.entries(LEGITIMATE_PACKAGES).map(([ecosystem, packages]) => {
    const bloomFilter = BLOOM_FILTERS[ecosystem];
    const setSize = packages.size;
    const hasBloom = !!bloomFilter;
    return {
      ecosystem,
      packages_loaded: setSize,
      bloom_filter_loaded: hasBloom,
      status: setSize > 0 ? 'ready' : hasBloom ? 'ready (bloom filter)' : 'not loaded'
    };
  });

  const totalSet = stats.reduce((sum, s) => sum + s.packages_loaded, 0);
  const bloomEcosystems = stats.filter(s => s.bloom_filter_loaded).map(s => s.ecosystem);

  return {
    package_lists: stats,
    total_packages: totalSet,
    bloom_filter_ecosystems: bloomEcosystems,
    note: bloomEcosystems.length > 0
      ? `Bloom filters provide coverage for: ${bloomEcosystems.join(', ')} (not counted in total_packages)`
      : undefined
  };
}

// Schema for check_package tool
export const checkPackageSchema = {
  package_name: z.string().describe("The package name to verify"),
  ecosystem: z.enum(["dart", "perl", "raku", "npm", "pypi", "rubygems", "crates"]).describe("The package ecosystem (dart=pub.dev, perl=CPAN, raku=raku.land, npm=npmjs, pypi=PyPI, rubygems=RubyGems, crates=crates.io)")
};

// Handler for check_package tool
export async function checkPackage({ package_name, ecosystem }) {
  const result = isHallucinated(package_name, ecosystem);

  if (result.unknown) {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          package: package_name,
          ecosystem,
          status: "unknown",
          reason: result.reason,
          suggestion: "Load package list or verify manually at the package registry"
        }, null, 2)
      }]
    };
  }

  const exists = !result.hallucinated;
  const confidence = result.bloomFilter ? "medium" : "high";
  const totalPackages = getTotalPackages(ecosystem);

  return {
    content: [{
      type: "text",
      text: JSON.stringify({
        package: package_name,
        ecosystem,
        legitimate: exists,
        hallucinated: !exists,
        confidence,
        bloom_filter: !!result.bloomFilter,
        total_known_packages: totalPackages,
        recommendation: exists
          ? "Package exists in registry - safe to use"
          : "⚠️ POTENTIAL HALLUCINATION - Package not found in registry. Verify before using!"
      }, null, 2)
    }]
  };
}
