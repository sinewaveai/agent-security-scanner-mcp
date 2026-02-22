// src/daemon-client.js — Node.js client managing daemon lifecycle and JSONL communication.
import { spawn } from 'child_process';
import { createInterface } from 'readline';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { resolvePythonCommand, pythonArgs } from './python.js';

let __dirname;
try {
  __dirname = dirname(fileURLToPath(import.meta.url));
} catch {
  __dirname = process.cwd();
}

const DAEMON_SCRIPT = join(__dirname, '..', 'daemon.py');
const READY_TIMEOUT = 15000;   // 15s to wait for __ready__ signal
const REQUEST_TIMEOUT = 45000; // 45s per request (increased for large files in Codex/complex analysis)
const MAX_RESTARTS = 3;
const RESTART_WINDOW = 60000;  // 60s window for restart counting

let _reqCounter = 0;
function nextId() {
  return `req-${++_reqCounter}`;
}

class DaemonClient {
  constructor() {
    this._proc = null;
    this._rl = null;
    this._pending = new Map(); // id -> { resolve, reject, timer }
    this._dead = false;        // permanently dead after too many restarts
    this._restarts = [];       // timestamps of recent restarts
    this._starting = null;     // promise while startup in progress
  }

  get isAvailable() {
    return !this._dead;
  }

  async ensureRunning() {
    if (this._dead) throw new Error('Daemon permanently unavailable');
    if (this._proc && !this._proc.killed && this._proc.exitCode === null) return;
    if (this._starting) return this._starting;

    this._starting = this._spawn();
    try {
      await this._starting;
    } finally {
      this._starting = null;
    }
  }

  _spawn() {
    return new Promise((resolve, reject) => {
      // Track restarts
      const now = Date.now();
      this._restarts = this._restarts.filter(t => now - t < RESTART_WINDOW);
      if (this._restarts.length >= MAX_RESTARTS) {
        this._dead = true;
        reject(new Error('Daemon exceeded max restarts, falling back to sync'));
        return;
      }
      this._restarts.push(now);

      // Cleanup any previous process
      this._cleanup();

      const pyCmd = resolvePythonCommand();
      const proc = spawn(pyCmd, [...pythonArgs(), DAEMON_SCRIPT], {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { ...process.env, PYTHONUNBUFFERED: '1' },
      });

      this._proc = proc;

      // stderr goes to process.stderr for debug logging
      proc.stderr.on('data', (chunk) => {
        if (process.env.DAEMON_DEBUG) {
          process.stderr.write(`[daemon] ${chunk}`);
        }
      });

      // Handle process exit
      proc.on('exit', (code, signal) => {
        // Reject all pending requests
        for (const [id, entry] of this._pending) {
          clearTimeout(entry.timer);
          entry.reject(new Error(`Daemon exited (code=${code}, signal=${signal})`));
        }
        this._pending.clear();
        this._proc = null;
        this._rl = null;
      });

      proc.on('error', (err) => {
        this._dead = true;
        reject(err);
      });

      // Read JSONL from stdout
      const rl = createInterface({ input: proc.stdout });
      this._rl = rl;

      // Wait for __ready__ signal with timeout
      const readyTimer = setTimeout(() => {
        this._cleanup();
        reject(new Error('Daemon startup timed out'));
      }, READY_TIMEOUT);

      let readyResolved = false;

      rl.on('line', (line) => {
        let msg;
        try {
          msg = JSON.parse(line);
        } catch {
          return; // skip non-JSON lines
        }

        // Handle ready signal
        if (!readyResolved && msg.id === '__ready__') {
          readyResolved = true;
          clearTimeout(readyTimer);
          resolve();
          return;
        }

        // Route response to pending request
        const id = msg.id;
        if (id && this._pending.has(id)) {
          const entry = this._pending.get(id);
          this._pending.delete(id);
          clearTimeout(entry.timer);
          if (msg.success) {
            entry.resolve(msg);
          } else {
            entry.reject(new Error(msg.error || 'Daemon request failed'));
          }
        }
      });

      rl.on('close', () => {
        if (!readyResolved) {
          clearTimeout(readyTimer);
          reject(new Error('Daemon stdout closed before ready'));
        }
      });
    });
  }

  _cleanup() {
    if (this._rl) {
      try { this._rl.close(); } catch { /* ignore */ }
      this._rl = null;
    }
    if (this._proc) {
      try { this._proc.kill(); } catch { /* ignore */ }
      this._proc = null;
    }
  }

  _send(obj) {
    return new Promise((resolve, reject) => {
      const id = obj.id || nextId();
      obj.id = id;

      const timer = setTimeout(() => {
        this._pending.delete(id);
        reject(new Error(`Daemon request timed out (id=${id})`));
      }, REQUEST_TIMEOUT);

      this._pending.set(id, { resolve, reject, timer });

      try {
        this._proc.stdin.write(JSON.stringify(obj) + '\n');
      } catch (err) {
        this._pending.delete(id);
        clearTimeout(timer);
        reject(err);
      }
    });
  }

  async analyze(filePath, engine = 'auto') {
    await this.ensureRunning();
    const resp = await this._send({
      action: 'analyze',
      file_path: filePath,
      engine,
    });
    return resp.result;
  }

  async crossFileAnalyze(filePaths) {
    await this.ensureRunning();
    const resp = await this._send({
      action: 'cross_file_analyze',
      file_paths: filePaths,
    });
    return resp.result;
  }

  async health() {
    await this.ensureRunning();
    const resp = await this._send({ action: 'health' });
    return resp.result;
  }

  async preWarm() {
    if (this._dead) return;
    try {
      await this.ensureRunning();
      await this.health();
    } catch {
      // Pre-warm failure is non-fatal
    }
  }

  async shutdown() {
    if (!this._proc || this._proc.killed || this._proc.exitCode !== null) return;
    try {
      await this._send({ action: 'shutdown' });
    } catch {
      // ignore — process may already be gone
    }
    this._cleanup();
  }
}

// Singleton instance
let _instance = null;

export function getDaemonClient() {
  if (!_instance) {
    _instance = new DaemonClient();
  }
  return _instance;
}

export async function shutdownDaemon() {
  if (_instance) {
    await _instance.shutdown();
    _instance = null;
  }
}
