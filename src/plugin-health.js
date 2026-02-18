// src/plugin-health.js — Plugin health check endpoint

import { getDaemonClient } from './daemon-client.js';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

let __dirname;
try {
  __dirname = dirname(fileURLToPath(import.meta.url));
} catch {
  __dirname = process.cwd();
}

export async function getHealthStatus() {
  let version = '0.0.0';
  try {
    const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf-8'));
    version = pkg.version || '0.0.0';
  } catch { /* ignore */ }

  let daemonHealth = null;
  try {
    const client = getDaemonClient();
    if (client.isAvailable) {
      daemonHealth = await client.health();
    }
  } catch { /* daemon not available */ }

  // Try to get package stats without failing
  let packageStats = null;
  try {
    const { getPackageStats } = await import('./tools/check-package.js');
    packageStats = getPackageStats();
  } catch { /* packages not loaded */ }

  return {
    name: 'agent-security-scanner-mcp',
    version,
    daemon: daemonHealth ? {
      status: 'running',
      pid: daemonHealth.pid,
      cache_size: daemonHealth.cache_size,
      uptime_seconds: Math.round(daemonHealth.uptime),
    } : { status: 'not running' },
    packages: packageStats,
    timestamp: new Date().toISOString(),
  };
}
