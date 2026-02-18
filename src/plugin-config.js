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

        if (!parsed || typeof parsed !== 'object') {
          continue;
        }

        const parsedFeatures = parsed.features && typeof parsed.features === 'object' ? parsed.features : {};
        const parsedDaemon = parsed.daemon && typeof parsed.daemon === 'object' ? parsed.daemon : {};

        return {
          version: typeof parsed.version === 'number' ? parsed.version : DEFAULT_PLUGIN_CONFIG.version,
          features: {
            scan_on_write: parsedFeatures.scan_on_write ?? DEFAULT_PLUGIN_CONFIG.features.scan_on_write,
            scan_on_skill_install: parsedFeatures.scan_on_skill_install ?? DEFAULT_PLUGIN_CONFIG.features.scan_on_skill_install,
            prompt_firewall: parsedFeatures.prompt_firewall ?? DEFAULT_PLUGIN_CONFIG.features.prompt_firewall,
            package_hallucination: parsedFeatures.package_hallucination ?? DEFAULT_PLUGIN_CONFIG.features.package_hallucination,
            config_audit: parsedFeatures.config_audit ?? DEFAULT_PLUGIN_CONFIG.features.config_audit,
          },
          severity_threshold: ['info', 'warning', 'error'].includes(parsed.severity_threshold)
            ? parsed.severity_threshold : DEFAULT_PLUGIN_CONFIG.severity_threshold,
          auto_block: typeof parsed.auto_block === 'boolean' ? parsed.auto_block : DEFAULT_PLUGIN_CONFIG.auto_block,
          output_format: ['json', 'text'].includes(parsed.output_format)
            ? parsed.output_format : DEFAULT_PLUGIN_CONFIG.output_format,
          daemon: {
            prewarm: parsedDaemon.prewarm ?? DEFAULT_PLUGIN_CONFIG.daemon.prewarm,
            cache_size: typeof parsedDaemon.cache_size === 'number' ? parsedDaemon.cache_size : DEFAULT_PLUGIN_CONFIG.daemon.cache_size,
          },
          _source: configPath,
        };
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
