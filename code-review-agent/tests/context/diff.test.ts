import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { parseDiff, formatHunkRanges, getChangedFiles, readFileAtRef } from '../../src/context/diff.js';

describe('parseDiff', () => {
  it('parses a single-hunk modification', () => {
    const diff = `diff --git a/src/util.ts b/src/util.ts
index 1111111..2222222 100644
--- a/src/util.ts
+++ b/src/util.ts
@@ -10,7 +10,9 @@ export function helper() {
   const a = 1;
   const b = 2;
-  return a + b;
+  const c = a + b;
+  console.log(c);
+  return c;
 }
`;
    const files = parseDiff(diff);
    expect(files).toHaveLength(1);
    expect(files[0].filePath).toBe('src/util.ts');
    expect(files[0].hunks).toEqual([{ startLine: 10, endLine: 18 }]);
    expect(files[0].diffText).toContain('diff --git a/src/util.ts b/src/util.ts');
  });

  it('parses multiple hunks in the same file', () => {
    const diff = `diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -5,3 +5,4 @@ def foo():
     pass
+    # note
@@ -40,2 +41,3 @@ def bar():
     pass
+    # another note
`;
    const files = parseDiff(diff);
    expect(files).toHaveLength(1);
    expect(files[0].hunks).toEqual([
      { startLine: 5, endLine: 8 },
      { startLine: 41, endLine: 43 },
    ]);
  });

  it('parses multiple changed files in one diff', () => {
    const diff = `diff --git a/a.js b/a.js
index 1111111..2222222 100644
--- a/a.js
+++ b/a.js
@@ -1,2 +1,3 @@
 const x = 1;
+const y = 2;
diff --git a/b.js b/b.js
index 3333333..4444444 100644
--- a/b.js
+++ b/b.js
@@ -1,1 +1,2 @@
 const z = 3;
+const w = 4;
`;
    const files = parseDiff(diff);
    expect(files.map((f) => f.filePath)).toEqual(['a.js', 'b.js']);
  });

  it('handles a newly added file (hunk starts at line 1 from /dev/null)', () => {
    const diff = `diff --git a/src/new.ts b/src/new.ts
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/src/new.ts
@@ -0,0 +1,3 @@
+export function fresh() {
+  return true;
+}
`;
    const files = parseDiff(diff);
    expect(files).toHaveLength(1);
    expect(files[0].filePath).toBe('src/new.ts');
    expect(files[0].hunks).toEqual([{ startLine: 1, endLine: 3 }]);
  });

  it('skips deleted files entirely — nothing to review in the new version', () => {
    const diff = `diff --git a/old.ts b/old.ts
deleted file mode 100644
index 1111111..0000000
--- a/old.ts
+++ /dev/null
@@ -1,3 +0,0 @@
-export function gone() {
-  return false;
-}
`;
    const files = parseDiff(diff);
    expect(files).toHaveLength(0);
  });

  it('skips binary files — no meaningful line-level diff to scope to', () => {
    const diff = `diff --git a/image.png b/image.png
index 1111111..2222222 100644
Binary files a/image.png and b/image.png differ
`;
    const files = parseDiff(diff);
    expect(files).toHaveLength(0);
  });

  it('returns an empty array for an empty diff', () => {
    expect(parseDiff('')).toEqual([]);
  });

  it('uses the post-change (b/) path so renames resolve to the new name', () => {
    const diff = `diff --git a/old-name.ts b/new-name.ts
similarity index 95%
rename from old-name.ts
rename to new-name.ts
index 1111111..2222222 100644
--- a/old-name.ts
+++ b/new-name.ts
@@ -1,2 +1,3 @@
 const x = 1;
+const y = 2;
`;
    const files = parseDiff(diff);
    expect(files).toHaveLength(1);
    expect(files[0].filePath).toBe('new-name.ts');
  });
});

describe('formatHunkRanges', () => {
  it('formats single-line hunks without a dash', () => {
    expect(formatHunkRanges([{ startLine: 5, endLine: 5 }])).toBe('5');
  });

  it('formats multi-line hunks as a range', () => {
    expect(formatHunkRanges([{ startLine: 10, endLine: 18 }])).toBe('10-18');
  });

  it('joins multiple hunks with a comma', () => {
    expect(
      formatHunkRanges([
        { startLine: 5, endLine: 8 },
        { startLine: 41, endLine: 43 },
      ]),
    ).toBe('5-8, 41-43');
  });

  it('returns an empty string for no hunks', () => {
    expect(formatHunkRanges([])).toBe('');
  });
});

// Regression coverage for a real bug: readFileAtRef/getChangedFiles must work
// correctly even when the working tree has a DIFFERENT commit checked out
// than the diff's head — e.g. a fresh clone defaults to whatever the
// default branch is, not the specific commit being reviewed. This exact
// scenario broke a real benchmark run (cr-agent silently found 0 files for
// every instance) before readFileAtRef was added: buildFileContext used to
// read file content via fs.readFileSync against the working tree, which
// either read the wrong version of a file or found nothing at all for
// files whose content/existence differs between the checked-out commit and
// the diff's actual head.
describe('readFileAtRef and getChangedFiles against a real git repo', () => {
  let repoDir: string;

  function git(args: string[]): string {
    return execFileSync('git', args, { cwd: repoDir, encoding: 'utf-8' });
  }

  beforeAll(() => {
    repoDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-agent-diff-test-'));
    git(['init', '--quiet']);
    git(['config', 'user.email', 'test@example.com']);
    git(['config', 'user.name', 'Test']);

    // Base commit: a file with original content.
    fs.writeFileSync(path.join(repoDir, 'app.py'), 'def greet():\n    return "hello"\n');
    git(['add', '.']);
    git(['commit', '--quiet', '-m', 'base']);
    const baseCommit = git(['rev-parse', 'HEAD']).trim();

    // Head commit: modify the file (this is the "PR" being reviewed).
    fs.writeFileSync(path.join(repoDir, 'app.py'), 'def greet(name):\n    return f"hello {name}"\n');
    git(['commit', '--quiet', '-am', 'head']);
    const headCommit = git(['rev-parse', 'HEAD']).trim();

    // Simulate the actual bug scenario: after the diff is computed, the
    // working tree ends up on a THIRD, unrelated commit — e.g. a fresh
    // clone checked out to a default branch, or someone just has a
    // different commit checked out locally. Content and even file
    // existence can differ from both base and head.
    fs.writeFileSync(path.join(repoDir, 'app.py'), 'def unrelated():\n    pass\n');
    fs.writeFileSync(path.join(repoDir, 'only-on-third-commit.py'), 'x = 1\n');
    git(['add', '.']);
    git(['commit', '--quiet', '-m', 'unrelated third commit']);

    (globalThis as unknown as { __testCommits: { base: string; head: string } }).__testCommits = {
      base: baseCommit,
      head: headCommit,
    };
  });

  afterAll(() => {
    fs.rmSync(repoDir, { recursive: true, force: true });
  });

  it('getChangedFiles finds the diff correctly regardless of what is currently checked out', () => {
    const { base, head } = (globalThis as unknown as { __testCommits: { base: string; head: string } }).__testCommits;
    const files = getChangedFiles(repoDir, base, head);
    expect(files.map((f) => f.filePath)).toEqual(['app.py']);
  });

  it('readFileAtRef reads content at head, not the currently checked-out working tree', () => {
    const { head } = (globalThis as unknown as { __testCommits: { base: string; head: string } }).__testCommits;

    // Sanity check: the working tree really is on the unrelated third
    // commit right now, not head — otherwise this test wouldn't actually
    // exercise the bug scenario.
    const workingTreeContent = fs.readFileSync(path.join(repoDir, 'app.py'), 'utf-8');
    expect(workingTreeContent).toContain('unrelated');

    const headContent = readFileAtRef(repoDir, head, 'app.py');
    expect(headContent).toContain('def greet(name):');
    expect(headContent).not.toContain('unrelated');
  });

  it('readFileAtRef reads content at base too, distinct from head', () => {
    const { base } = (globalThis as unknown as { __testCommits: { base: string; head: string } }).__testCommits;
    const baseContent = readFileAtRef(repoDir, base, 'app.py');
    expect(baseContent).toBe('def greet():\n    return "hello"\n');
  });

  it('readFileAtRef throws for a file that does not exist at the given ref', () => {
    const { base } = (globalThis as unknown as { __testCommits: { base: string; head: string } }).__testCommits;
    // only-on-third-commit.py exists in the working tree's current commit
    // but not at `base` — reading it there must fail loudly, not silently
    // return the working-tree version.
    expect(() => readFileAtRef(repoDir, base, 'only-on-third-commit.py')).toThrow();
  });
});
