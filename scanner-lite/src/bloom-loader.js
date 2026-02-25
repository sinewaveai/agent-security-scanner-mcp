// src/bloom-loader.js — Lazy bloom filter loading from ~/.prooflayer/data/
// Minimal bloom filter has() implementation (~30 lines) to avoid adding a dependency
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';

const DATA_DIR = join(process.env.HOME || process.env.USERPROFILE || '.', '.prooflayer', 'data');

// Cache loaded bloom filters
const _cache = new Map();

// Minimal bloom filter implementation
class BloomFilter {
  constructor(buffer) {
    this.buffer = buffer;
    this.bitCount = buffer.length * 8;
    // Count is stored in the last 4 bytes (uint32 LE)
    if (buffer.length >= 4) {
      this.count = buffer.readUInt32LE(buffer.length - 4);
      this.data = buffer.subarray(0, buffer.length - 4);
      this.bitCount = this.data.length * 8;
    } else {
      this.count = 0;
      this.data = buffer;
    }
  }

  // FNV-1a hash with seed
  _hash(str, seed) {
    let h = 2166136261 ^ seed;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = (h * 16777619) >>> 0;
    }
    return h % this.bitCount;
  }

  has(item) {
    // Check 3 hash functions
    for (let seed = 0; seed < 3; seed++) {
      const bit = this._hash(item, seed);
      const byteIdx = Math.floor(bit / 8);
      const bitIdx = bit % 8;
      if (byteIdx >= this.data.length) return false;
      if (!(this.data[byteIdx] & (1 << bitIdx))) return false;
    }
    return true; // May be a false positive
  }
}

/**
 * Load a bloom filter for the given ecosystem.
 * Returns null if no data file is available.
 * @param {string} ecosystem - npm, pypi, rubygems, crates, etc.
 * @returns {BloomFilter|null}
 */
export function loadBloomFilter(ecosystem) {
  if (_cache.has(ecosystem)) return _cache.get(ecosystem);

  const filePath = join(DATA_DIR, `${ecosystem}.bloom`);
  if (!existsSync(filePath)) {
    _cache.set(ecosystem, null);
    return null;
  }

  try {
    const buffer = readFileSync(filePath);
    if (buffer.length < 8) {
      _cache.set(ecosystem, null);
      return null;
    }
    const bloom = new BloomFilter(buffer);
    _cache.set(ecosystem, bloom);
    return bloom;
  } catch {
    _cache.set(ecosystem, null);
    return null;
  }
}

/**
 * Clear the bloom filter cache (for testing)
 */
export function clearBloomCache() {
  _cache.clear();
}
