#!/usr/bin/env node
/**
 * Test hallucination detection across all ecosystems
 */

import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const packagesDir = join(__dirname, '..', 'packages');

// Load all package lists
const PACKAGES = {};
const ecosystems = ['dart', 'perl', 'raku', 'npm', 'pypi', 'rubygems', 'crates'];

console.log('Loading package lists...\n');
for (const eco of ecosystems) {
  const filePath = join(packagesDir, `${eco}.txt`);
  if (existsSync(filePath)) {
    const content = readFileSync(filePath, 'utf-8');
    PACKAGES[eco] = new Set(content.split('\n').filter(p => p.trim()));
    console.log(`  ${eco.padEnd(10)} ${PACKAGES[eco].size.toLocaleString().padStart(12)} packages`);
  } else {
    console.log(`  ${eco.padEnd(10)} NOT FOUND`);
  }
}

// Calculate total
const total = Object.values(PACKAGES).reduce((sum, set) => sum + set.size, 0);
console.log(`  ${'─'.repeat(25)}`);
console.log(`  ${'TOTAL'.padEnd(10)} ${total.toLocaleString().padStart(12)} packages\n`);

// Test cases
const testCases = {
  pypi: {
    real: ['requests', 'numpy', 'pandas', 'flask', 'django'],
    fake: ['super_ai_helper_magic', 'ultra_data_processor_fake']
  },
  npm: {
    real: ['express', 'lodash', 'axios', 'react', 'vue'],
    fake: ['super-ai-helper-magic', 'ultra-data-parser-fake']
  },
  rubygems: {
    real: ['rails', 'sinatra', 'nokogiri', 'rspec', 'puma'],
    fake: ['super_ai_helper_magic', 'ultra_data_processor_fake']
  },
  crates: {
    real: ['serde', 'tokio', 'reqwest', 'clap', 'log'],
    fake: ['super_ai_helper_magic', 'ultra_data_processor_fake']
  },
  dart: {
    real: ['http', 'provider', 'dio', 'flutter', 'path'],
    fake: ['flutter_super_animations_xyz', 'dart_ai_helper_magic']
  },
  perl: {
    real: ['DBI', 'Moose', 'DateTime', 'JSON', 'LWP'],
    fake: ['AI::MagicHelper::Pro', 'Super::FastParser::Ultra']
  },
  raku: {
    real: ['Cro', 'JSON::Fast', 'HTTP::UserAgent'],
    fake: ['AI::MagicHelper::Pro', 'Super::FastParser::Ultra']
  }
};

console.log('='*60);
console.log('HALLUCINATION DETECTION TESTS');
console.log('='*60);

let totalTests = 0;
let passed = 0;

for (const [eco, tests] of Object.entries(testCases)) {
  console.log(`\n─── ${eco.toUpperCase()} ───`);
  const pkgSet = PACKAGES[eco];

  if (!pkgSet || pkgSet.size === 0) {
    console.log('  ⚠️  No packages loaded, skipping');
    continue;
  }

  // Test real packages
  for (const pkg of tests.real) {
    totalTests++;
    const found = pkgSet.has(pkg);
    if (found) {
      console.log(`  ✅ ${pkg} - correctly identified as REAL`);
      passed++;
    } else {
      console.log(`  ❌ ${pkg} - FALSE NEGATIVE (should be real)`);
    }
  }

  // Test fake packages
  for (const pkg of tests.fake) {
    totalTests++;
    const found = pkgSet.has(pkg);
    if (!found) {
      console.log(`  ✅ ${pkg} - correctly identified as FAKE`);
      passed++;
    } else {
      console.log(`  ❌ ${pkg} - FALSE POSITIVE (should be fake)`);
    }
  }
}

console.log(`\n${'='*60}`);
console.log(`RESULTS: ${passed}/${totalTests} tests passed (${(passed/totalTests*100).toFixed(1)}%)`);
console.log('='*60);
