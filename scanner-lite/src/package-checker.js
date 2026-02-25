// src/package-checker.js — check_package tool handler with lazy bloom filter loading
import { z } from "zod";
import { findSimilarPackages, checkDependencyConfusion } from './typosquat.js';
import { loadBloomFilter } from './bloom-loader.js';

export const checkPackageSchema = {
  package_name: z.string().describe("The package name to verify"),
  ecosystem: z.enum(["dart", "perl", "raku", "npm", "pypi", "rubygems", "crates"]).describe("The package ecosystem (dart=pub.dev, perl=CPAN, raku=raku.land, npm=npmjs, pypi=PyPI, rubygems=RubyGems, crates=crates.io)")
};

// Check if a package is hallucinated using bloom filters (lazy loaded)
function checkPackageBloom(packageName, ecosystem) {
  const bloom = loadBloomFilter(ecosystem);
  if (!bloom) {
    return { unknown: true, reason: `No bloom filter data for ${ecosystem}. Run 'scanner-lite download-data' to enable package verification.` };
  }
  const exists = bloom.has(packageName);
  return {
    hallucinated: !exists,
    verified: exists,
    bloomFilter: true
  };
}

export function isHallucinated(packageName, ecosystem) {
  return checkPackageBloom(packageName, ecosystem);
}

export function getTotalPackages(ecosystem) {
  const bloom = loadBloomFilter(ecosystem);
  return bloom ? bloom.count : 0;
}

export function getPackageStats() {
  const ecosystems = ['npm', 'pypi', 'rubygems', 'crates', 'dart', 'perl', 'raku'];
  const stats = ecosystems.map(ecosystem => {
    const bloom = loadBloomFilter(ecosystem);
    return {
      ecosystem,
      packages_loaded: bloom ? bloom.count : 0,
      status: bloom ? 'ready (bloom)' : 'not loaded'
    };
  });

  const total = stats.reduce((sum, s) => sum + s.packages_loaded, 0);
  return { package_lists: stats, total_packages: total };
}

export async function checkPackage({ package_name, ecosystem }) {
  const result = isHallucinated(package_name, ecosystem);

  if (result.unknown) {
    // Fall back to typosquatting + dependency confusion heuristics
    const similar = findSimilarPackages(package_name, ecosystem);
    const confusionCheck = checkDependencyConfusion(package_name);

    const response = {
      package: package_name,
      ecosystem,
      status: "heuristic-only",
      reason: result.reason,
      recommendation: similar.length > 0
        ? `Package '${package_name}' is similar to: ${similar.map(s => s.name).join(', ')}. Possible typosquatting.`
        : "Cannot verify package existence. Use typosquatting heuristics only."
    };

    if (similar.length > 0) {
      response.typosquatting = { similar_packages: similar };
    }
    if (confusionCheck.risk) {
      response.dependency_confusion = { risk: true, warning: confusionCheck.warning };
    }

    return {
      content: [{ type: "text", text: JSON.stringify(response, null, 2) }]
    };
  }

  const exists = !result.hallucinated;
  const response = {
    package: package_name,
    ecosystem,
    legitimate: exists,
    hallucinated: !exists,
    confidence: result.bloomFilter ? "medium" : "high",
    total_known_packages: getTotalPackages(ecosystem),
    recommendation: exists
      ? "Package exists in registry - safe to use"
      : "POTENTIAL HALLUCINATION - Package not found in registry. Verify before using!"
  };

  if (!exists) {
    const similar = findSimilarPackages(package_name, ecosystem);
    if (similar.length > 0) {
      response.typosquatting = {
        similar_packages: similar,
        warning: `Package '${package_name}' is similar to known packages. This could be a typosquatting attack.`
      };
    }
  }

  const confusionCheck = checkDependencyConfusion(package_name);
  if (confusionCheck.risk) {
    response.dependency_confusion = { risk: true, warning: confusionCheck.warning };
  }

  return {
    content: [{ type: "text", text: JSON.stringify(response, null, 2) }]
  };
}
