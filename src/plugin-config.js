// src/plugin-config.js — Plugin configuration loader
// Loads config from ~/.openclaw/scanner-config.json, .scannerrc.json, or .clawproofrc.json

import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const DEFAULT_PLUGIN_CONFIG = {
  version: 1,
  features: {
    scan_on_write: true,
    scan_on_skill_install: true,
    prompt_firewall: true,
    package_hallucination: true,
    config_audit: true,
  },
  severity_threshold: 'warning',
  auto_block: true,
  output_format: 'json',
  daemon: {
    prewarm: true,
    cache_size: 200,
  },
};

export function loadPluginConfig() {
  const paths = [
    join(homedir(), '.openclaw', 'scanner-config.json'),
    join(process.cwd(), '.clawproofrc.json'),
    join(process.cwd(), '.scannerrc.json'),
  ];

  for (const configPath of paths) {
    if (existsSync(configPath)) {
      try {
        const raw = readFileSync(configPath, 'utf-8');
        const parsed = JSON.parse(raw);
        return { ...DEFAULT_PLUGIN_CONFIG, ...parsed, _source: configPath };
      } catch {
        // Malformed config, fall through
      }
    }
  }

  return { ...DEFAULT_PLUGIN_CONFIG, _source: null };
}

export function getDefaultPluginConfig() {
  return { ...DEFAULT_PLUGIN_CONFIG };
}
