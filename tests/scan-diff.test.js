import { describe, it, expect } from 'vitest';
import { existsSync } from 'fs';

describe('scan-diff module', () => {
  it('should export scanDiffSchema and scanDiff', async () => {
    const mod = await import('../src/tools/scan-diff.js');
    expect(mod.scanDiffSchema).toBeDefined();
    expect(mod.scanDiffSchema.base_ref).toBeDefined();
    expect(mod.scanDiffSchema.target_ref).toBeDefined();
    expect(mod.scanDiffSchema.verbosity).toBeDefined();
    expect(typeof mod.scanDiff).toBe('function');
  });

  it('should handle no changes gracefully', async () => {
    const { scanDiff } = await import('../src/tools/scan-diff.js');
    // HEAD...HEAD should produce no diff
    const result = await scanDiff({ base_ref: 'HEAD', target_ref: 'HEAD', verbosity: 'minimal' });
    const output = JSON.parse(result.content[0].text);
    expect(output.issues_count !== undefined || output.total !== undefined || output.message).toBeTruthy();
  });
});
