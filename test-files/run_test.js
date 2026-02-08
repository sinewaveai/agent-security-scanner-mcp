#!/usr/bin/env node
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

const __dirname = process.cwd();

// Load packages into hash sets
const PACKAGES = {};
const ecosystems = ['dart', 'perl', 'raku'];

console.log('Loading package lists...\n');
for (const eco of ecosystems) {
  const filePath = join(__dirname, 'packages', `${eco}.txt`);
  if (existsSync(filePath)) {
    const content = readFileSync(filePath, 'utf-8');
    PACKAGES[eco] = new Set(content.split('\n').filter(p => p.trim()));
    console.log(`  ${eco}: ${PACKAGES[eco].size.toLocaleString()} packages`);
  }
}

// Extract packages from code
function extractPackages(code, ecosystem) {
  const packages = [];
  const lines = code.split('\n');

  for (const line of lines) {
    let match;

    if (ecosystem === 'dart') {
      // Match: import 'package:name/...'
      match = line.match(/import\s+['"]package:([^\/'"]+)/);
      if (match) packages.push(match[1]);
    } else if (ecosystem === 'perl') {
      // Match: use Module::Name
      match = line.match(/^use\s+([\w:]+)\s*;/);
      if (match && !['strict', 'warnings'].includes(match[1])) {
        packages.push(match[1]);
      }
    } else if (ecosystem === 'raku') {
      // Match: use Module::Name
      match = line.match(/^use\s+([\w:]+)\s*;/);
      if (match) packages.push(match[1]);
    }
  }

  return packages;
}

// Test files
const testFiles = [
  { file: 'test-files/test_hallucination.dart', eco: 'dart' },
  { file: 'test-files/test_hallucination.pl', eco: 'perl' },
  { file: 'test-files/test_hallucination.raku', eco: 'raku' }
];

console.log('\n' + '='.repeat(60));
console.log('HALLUCINATION DETECTION TEST');
console.log('='.repeat(60));

for (const { file, eco } of testFiles) {
  console.log(`\n${'─'.repeat(60)}`);
  console.log(`Testing: ${file} (${eco})`);
  console.log('─'.repeat(60));

  const content = readFileSync(file, 'utf-8');
  const packages = extractPackages(content, eco);
  const legitSet = PACKAGES[eco];

  const legitimate = [];
  const hallucinated = [];

  for (const pkg of packages) {
    if (legitSet.has(pkg)) {
      legitimate.push(pkg);
    } else {
      hallucinated.push(pkg);
    }
  }

  console.log(`\nPackages found: ${packages.length}`);
  console.log(`  ✅ Legitimate: ${legitimate.length}`);
  console.log(`  ⚠️  Hallucinated: ${hallucinated.length}`);

  if (legitimate.length > 0) {
    console.log('\n✅ Legitimate packages:');
    for (const pkg of legitimate) {
      console.log(`   • ${pkg}`);
    }
  }

  if (hallucinated.length > 0) {
    console.log('\n⚠️  HALLUCINATED packages (not in registry):');
    for (const pkg of hallucinated) {
      console.log(`   • ${pkg}`);
    }
  }
}

console.log('\n' + '='.repeat(60));
console.log('TEST COMPLETE');
console.log('='.repeat(60));
