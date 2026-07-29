import { execFileSync } from 'node:child_process';

export interface DiffHunk {
  /** 1-indexed start line in the NEW (post-change) version of the file. */
  startLine: number;
  /** 1-indexed end line in the NEW (post-change) version of the file. */
  endLine: number;
}

export interface FileDiff {
  /** Path relative to the repo root, matching FileContext.filePath. */
  filePath: string;
  /** The raw unified diff block for this file, shown to the LLM verbatim. */
  diffText: string;
  /** Changed line ranges in the new version of the file. */
  hunks: DiffHunk[];
}

/**
 * Runs `git diff` between two refs and parses it into per-file hunks.
 *
 * Uses three-dot diff (base...head), which diffs against the merge-base of
 * the two refs rather than a direct two-ref comparison — this matches how a
 * PR's diff is conventionally computed (the same convention the other
 * review tools in this repo's benchmarking use, e.g. `git diff $(git
 * merge-base base head) head`).
 */
export function getChangedFiles(projectRoot: string, base: string, head: string): FileDiff[] {
  let raw: string;
  try {
    raw = execFileSync(
      'git',
      // --relative: report paths relative to `projectRoot` (the cwd below),
      // not the repo root. Without this, a diff run from a subdirectory of
      // a larger repo returns paths like "code-review-agent/src/foo.ts"
      // instead of "src/foo.ts", which would double up when the engine
      // later resolves them as path.resolve(projectRoot, filePath). This
      // also correctly scopes the diff to changes within projectRoot only.
      ['diff', '--no-color', '--relative', '--unified=3', `${base}...${head}`],
      { cwd: projectRoot, encoding: 'utf-8', maxBuffer: 64 * 1024 * 1024 },
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to compute git diff ${base}...${head} in ${projectRoot}: ${msg.split('\n')[0]}`);
  }

  return parseDiff(raw);
}

/**
 * Parses unified diff output (as produced by `git diff`) into per-file
 * hunks. Hunk line numbers refer to the NEW (post-change) version of the
 * file, since that's the version the analysis engine reads content from.
 */
export function parseDiff(diffText: string): FileDiff[] {
  const files: FileDiff[] = [];
  const fileBlocks = diffText.split(/^diff --git /m).filter(Boolean);

  for (const block of fileBlocks) {
    const headerLine = block.split('\n', 1)[0];
    // Header looks like: a/path/to/file.ts b/path/to/file.ts
    // Use the b/ (post-change) path — matches renames and new files correctly.
    const match = headerLine.match(/ b\/(.+?)\s*$/);
    if (!match) continue;
    const filePath = match[1];

    // Skip deleted files — nothing to review in the new version.
    if (/^deleted file mode/m.test(block)) continue;
    // Skip binary files — no meaningful line-level diff to scope to.
    if (/^Binary files /m.test(block)) continue;

    const hunks: DiffHunk[] = [];
    // Hunk headers look like: @@ -12,7 +15,9 @@ optional trailing context
    const hunkRe = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm;
    let hm: RegExpExecArray | null;
    while ((hm = hunkRe.exec(block)) !== null) {
      const startLine = parseInt(hm[1], 10);
      const lineCount = hm[2] !== undefined ? parseInt(hm[2], 10) : 1;
      hunks.push({
        startLine,
        endLine: Math.max(startLine, startLine + lineCount - 1),
      });
    }

    if (hunks.length > 0) {
      files.push({
        filePath,
        diffText: `diff --git ${block}`.trimEnd(),
        hunks,
      });
    }
  }

  return files;
}

/** Formats hunks as a compact human-readable line-range list, e.g. "12-19, 45-45". */
export function formatHunkRanges(hunks: DiffHunk[]): string {
  return hunks.map((h) => (h.startLine === h.endLine ? `${h.startLine}` : `${h.startLine}-${h.endLine}`)).join(', ');
}
