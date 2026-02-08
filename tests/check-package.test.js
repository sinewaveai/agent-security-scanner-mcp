import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { MCPTestClient } from './helpers.js';

describe('check_package tool', () => {
  let client;

  beforeAll(async () => {
    client = new MCPTestClient();
    await client.start();
  }, 30000);

  afterAll(async () => {
    await client.stop();
  });

  // Bloom filter ecosystems (pypi, rubygems)
  it('should detect requests as legitimate pypi package via bloom filter', async () => {
    const result = await client.callTool('check_package', {
      package_name: 'requests',
      ecosystem: 'pypi'
    });
    expect(result.legitimate).toBe(true);
    expect(result.hallucinated).toBe(false);
    expect(result.bloom_filter).toBe(true);
  });

  it('should detect fake-pkg-xyz as hallucinated pypi package', async () => {
    const result = await client.callTool('check_package', {
      package_name: 'fake-ai-helper-pkg-xyz-nonexistent',
      ecosystem: 'pypi'
    });
    expect(result.hallucinated).toBe(true);
  });

  it('should detect rails as legitimate rubygems package via bloom filter', async () => {
    const result = await client.callTool('check_package', {
      package_name: 'rails',
      ecosystem: 'rubygems'
    });
    expect(result.legitimate).toBe(true);
    expect(result.bloom_filter).toBe(true);
  });

  // npm ecosystem returns unknown (no bloom filter shipped to reduce package size)
  it('should return unknown status for npm packages (no bloom filter)', async () => {
    const result = await client.callTool('check_package', {
      package_name: 'express',
      ecosystem: 'npm'
    });
    expect(result.status).toBe('unknown');
  });

  // Text-based ecosystems (dart, crates)
  it('should detect flutter as legitimate dart package', async () => {
    const result = await client.callTool('check_package', {
      package_name: 'flutter',
      ecosystem: 'dart'
    });
    expect(result.legitimate).toBe(true);
    expect(result.hallucinated).toBe(false);
    expect(result.confidence).toBe('high');
  });

  it('should detect flutter_test as legitimate dart package', async () => {
    const result = await client.callTool('check_package', {
      package_name: 'flutter_test',
      ecosystem: 'dart'
    });
    expect(result.legitimate).toBe(true);
  });

  it('should report bloom_filter flag for bloom-based lookups', async () => {
    const result = await client.callTool('check_package', {
      package_name: 'numpy',
      ecosystem: 'pypi'
    });
    expect(result.bloom_filter).toBe(true);
    expect(result.confidence).toBe('medium');
  });

  it('should report confidence "high" for text-based ecosystems', async () => {
    const result = await client.callTool('check_package', {
      package_name: 'flutter',
      ecosystem: 'dart'
    });
    expect(result.confidence).toBe('high');
    expect(result.bloom_filter).toBe(false);
  });
});
