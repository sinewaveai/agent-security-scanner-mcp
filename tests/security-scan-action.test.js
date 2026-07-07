import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';

const ACTION = readFileSync(
  join(process.cwd(), '.github/actions/security-scan/action.yml'),
  'utf8'
);

const TEMPLATE = readFileSync(
  join(process.cwd(), 'templates/github-action-security.yml'),
  'utf8'
);

describe('security-scan composite action CI behavior', () => {
  it('forces scheduled runs to use full-project scanning', () => {
    expect(ACTION).toContain('Scheduled run detected; using full project scan.');
    expect(ACTION).toMatch(
      /if \[ "\$\{\{ github\.event_name \}\}" = "schedule" \]; then\s+EFFECTIVE_SCAN_DIFF_ONLY="false"/
    );
  });

  it('uses all tracked files for package checks in full-project mode', () => {
    expect(ACTION).toContain('CHANGED_FILES=$(git ls-files)');
    expect(ACTION).toContain('checks all tracked source files so scheduled scans catch old imports too');
  });

  it('documents the scheduled full-project scan in the public workflow template', () => {
    expect(TEMPLATE).toContain('Weekly full-project scan.');
    expect(TEMPLATE).toContain('scheduled runs to full-project mode');
    expect(TEMPLATE).toContain('cron: "0 9 * * 1"');
  });
});

