// src/python.js — Cross-platform Python command resolution.
// Resolves the correct Python 3 command for the current platform:
//   Windows: py -3 → python3 → python
//   Unix:    python3 → python

import { execFileSync } from 'child_process';
import { platform } from 'os';

let _cached = null;

/**
 * Resolve the Python 3 command available on this system.
 * Caches the result for the lifetime of the process.
 * Returns 'python3' as a last-resort default if nothing is found
 * (so callers get a clear "command not found" error rather than silence).
 */
export function resolvePythonCommand() {
  if (_cached !== null) return _cached;

  const candidates = platform() === 'win32'
    ? [['py', ['-3', '--version']], ['python3', ['--version']], ['python', ['--version']]]
    : [['python3', ['--version']], ['python', ['--version']]];

  for (const [cmd, args] of candidates) {
    try {
      const out = execFileSync(cmd, args, {
        encoding: 'utf-8',
        timeout: 5000,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      if (out.includes('3.')) {
        // For `py -3`, the actual command to use at runtime is ['py', '-3']
        _cached = cmd === 'py' ? 'py' : cmd;
        return _cached;
      }
    } catch {
      // Not available, try next
    }
  }

  // Fallback — callers will get "command not found" with a clear error
  _cached = 'python3';
  return _cached;
}

/**
 * Returns the argument array prefix for invoking Python.
 * For Windows `py -3`, returns ['-3']; otherwise returns [].
 * Use: execFileSync(resolvePythonCommand(), [...pythonArgs(), scriptPath, ...])
 */
export function pythonArgs() {
  const cmd = resolvePythonCommand();
  return cmd === 'py' ? ['-3'] : [];
}
