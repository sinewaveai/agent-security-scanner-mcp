#!/usr/bin/env node
/**
 * Build Bloom Filters for large package ecosystems
 * Reduces package size significantly while maintaining fast lookups
 */

import pkg from 'bloom-filters';
const { BloomFilter } = pkg;
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const packagesDir = join(__dirname, '..', 'packages');

// Ecosystems to convert to Bloom Filters (large ones)
const ECOSYSTEMS = ['npm', 'pypi', 'rubygems'];
const FALSE_POSITIVE_RATE = 0.001; // 0.1%

console.log('Building Bloom Filters for package ecosystems...\n');
console.log(`False positive rate: ${(FALSE_POSITIVE_RATE * 100).toFixed(2)}%\n`);

let totalOriginal = 0;
let totalBloom = 0;

for (const ecosystem of ECOSYSTEMS) {
  const txtFile = join(packagesDir, `${ecosystem}.txt`);
  const bloomFile = join(packagesDir, `${ecosystem}-bloom.json`);

  if (!existsSync(txtFile)) {
    console.log(`⚠️  ${ecosystem}.txt not found, skipping\n`);
    continue;
  }

  console.log(`=== ${ecosystem.toUpperCase()} ===`);

  // Read packages
  console.log(`Reading ${ecosystem}.txt...`);
  const content = readFileSync(txtFile, 'utf-8');
  const packages = content.split('\n').filter(p => p.trim());
  console.log(`  Found ${packages.length.toLocaleString()} packages`);

  // Create Bloom Filter
  console.log(`Creating Bloom Filter...`);
  const filter = BloomFilter.create(packages.length, FALSE_POSITIVE_RATE);

  // Add all packages
  for (const pkg of packages) {
    filter.add(pkg);
  }

  // Export filter
  const exported = filter.saveAsJSON();
  writeFileSync(bloomFile, JSON.stringify(exported));

  // Calculate sizes
  const originalSize = readFileSync(txtFile).length;
  const bloomSize = readFileSync(bloomFile).length;
  const reduction = ((1 - bloomSize / originalSize) * 100).toFixed(1);

  totalOriginal += originalSize;
  totalBloom += bloomSize;

  console.log(`  Original: ${(originalSize / 1024 / 1024).toFixed(2)} MB`);
  console.log(`  Bloom:    ${(bloomSize / 1024 / 1024).toFixed(2)} MB`);
  console.log(`  Reduction: ${reduction}%`);

  // Verify
  const testPkgs = packages.slice(0, 5);
  const allFound = testPkgs.every(p => filter.has(p));
  console.log(`  Verification: ${allFound ? '✓ PASSED' : '✗ FAILED'}\n`);
}

console.log('=== SUMMARY ===');
console.log(`Total original: ${(totalOriginal / 1024 / 1024).toFixed(2)} MB`);
console.log(`Total bloom:    ${(totalBloom / 1024 / 1024).toFixed(2)} MB`);
console.log(`Total reduction: ${((1 - totalBloom / totalOriginal) * 100).toFixed(1)}%`);
console.log(`\nBloom filters saved to packages/*-bloom.json`);
