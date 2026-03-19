import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { buildProjectContext } from '../../src/context/project.js';

describe('buildProjectContext', () => {
  it('detects language from nested source files when manifests are absent', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-project-'));
    try {
      fs.mkdirSync(path.join(tmpDir, 'src'));
      fs.writeFileSync(path.join(tmpDir, 'src', 'server.js'), 'console.log(1);');

      const context = buildProjectContext(tmpDir);
      expect(context.language).toBe('javascript/typescript');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
