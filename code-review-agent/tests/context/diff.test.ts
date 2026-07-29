import { describe, it, expect } from 'vitest';
import { parseDiff, formatHunkRanges } from '../../src/context/diff.js';

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
