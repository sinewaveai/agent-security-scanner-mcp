import { z } from 'zod';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { discoverDependencies } from '../lib/lockfile-parsers.js';
import { serialize } from '../lib/cyclonedx.js';
import { componentFromBomComponent } from '../lib/sbom-component.js';
import { queryBatch } from '../lib/osv-client.js';

export const sbomReportSchema = {
  directory_path: z.string().optional().describe('Path to project root (generates fresh SBOM)'),
  sbom_path: z.string().optional().describe('Path to existing SBOM file'),
  format: z.enum(['html', 'json']).optional().describe('Report format (default: html)'),
  include_vulnerabilities: z.boolean().optional().describe('Include vulnerability scan in report (default: true)'),
  output_path: z.string().optional().describe('Path to write report file. Absent = no write.'),
  verbosity: z.enum(['minimal', 'compact', 'full']).optional().describe('Response detail level (default: compact)'),
};

export async function sbomExportReport({ directory_path, sbom_path, format, include_vulnerabilities, output_path, verbosity }) {
  // Enforce exactly one of directory_path or sbom_path
  if (directory_path && sbom_path) {
    return error('Provide either directory_path or sbom_path, not both.');
  }
  if (!directory_path && !sbom_path) {
    return error('Provide either directory_path or sbom_path.');
  }

  const outputFormat = format || 'html';
  const includeVulns = include_vulnerabilities !== false;

  // Load or generate SBOM
  let bom;
  let components;
  let scanComponents;
  if (sbom_path) {
    if (!existsSync(sbom_path)) return error(`SBOM file not found: ${sbom_path}`);
    bom = JSON.parse(readFileSync(sbom_path, 'utf-8'));
    components = bom.components || [];
    scanComponents = components.map(componentFromBomComponent);
  } else {
    if (!existsSync(directory_path)) return error(`Directory not found: ${directory_path}`);
    const componentList = discoverDependencies(directory_path);
    bom = serialize(componentList);
    components = bom.components || [];
    scanComponents = componentList.components;
  }

  // Vulnerability enrichment
  let vulnerabilities = [];
  let vulnSummary = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  if (includeVulns && scanComponents.length > 0) {
    const cacheDir = directory_path ? join(directory_path, '.scanner', 'cache', 'vuln') : null;
    const results = await queryBatch(scanComponents, { cacheDir });
    for (const vulns of results.values()) {
      for (const v of vulns) {
        vulnerabilities.push(v);
        const level = v.ratings?.[0]?.severity || 'unknown';
        vulnSummary[level] = (vulnSummary[level] || 0) + 1;
      }
    }
  }

  const projectName = bom.metadata?.component?.name || 'unknown';
  const projectVersion = bom.metadata?.component?.version || '0.0.0';

  if (outputFormat === 'json') {
    const response = {
      project: projectName,
      version: projectVersion,
      total_components: components.length,
      total_vulnerabilities: vulnerabilities.length,
      by_severity: vulnSummary,
      bom,
      vulnerabilities,
    };
    if (output_path) {
      writeReport(output_path, JSON.stringify(response, null, 2));
    }
    return {
      content: [{ type: 'text', text: JSON.stringify(response, null, 2) }],
    };
  }

  // Generate HTML report
  const html = generateSbomHtml(projectName, projectVersion, components, vulnerabilities, vulnSummary);

  if (output_path) {
    writeReport(output_path, html);
  }

  const level = verbosity || 'compact';
  let response;
  switch (level) {
    case 'minimal':
      response = {
        project: projectName,
        total_components: components.length,
        total_vulnerabilities: vulnerabilities.length,
        by_severity: vulnSummary,
        ...(output_path && { saved_to: output_path }),
      };
      break;
    case 'full':
      response = {
        project: projectName,
        total_components: components.length,
        total_vulnerabilities: vulnerabilities.length,
        by_severity: vulnSummary,
        html,
        ...(output_path && { saved_to: output_path }),
      };
      break;
    case 'compact':
    default:
      response = {
        project: projectName,
        total_components: components.length,
        total_vulnerabilities: vulnerabilities.length,
        by_severity: vulnSummary,
        top_vulnerabilities: vulnerabilities.slice(0, 10).map(v => ({
          id: v.id,
          severity: v.ratings?.[0]?.severity || 'unknown',
          description: (v.description || '').substring(0, 150),
        })),
        ...(output_path && { saved_to: output_path }),
      };
      break;
  }

  return {
    content: [{ type: 'text', text: JSON.stringify(response, null, 2) }],
  };
}

function extractEcosystem(component) {
  if (component.properties) {
    const eco = component.properties.find(p => p.name === 'cdx:ecosystem');
    if (eco) return eco.value;
  }
  if (component.purl) {
    const match = component.purl.match(/^pkg:([^/]+)/);
    if (match) {
      const purlToEco = { npm: 'npm', pypi: 'pypi', gem: 'rubygems', cargo: 'crates', golang: 'go', maven: 'java', pub: 'dart' };
      return purlToEco[match[1]] || match[1];
    }
  }
  return 'unknown';
}

function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function writeReport(filePath, content) {
  const dir = filePath.substring(0, filePath.lastIndexOf('/'));
  if (dir && !existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  writeFileSync(filePath, content, { mode: 0o600 });
}

function generateSbomHtml(projectName, projectVersion, components, vulnerabilities, vulnSummary) {
  const totalVulns = vulnerabilities.length;
  const severityColors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', unknown: '#9ca3af' };

  // Group components by ecosystem
  const byEcosystem = {};
  for (const c of components) {
    const eco = extractEcosystem(c);
    if (!byEcosystem[eco]) byEcosystem[eco] = [];
    byEcosystem[eco].push(c);
  }

  // Build severity bar chart SVG
  const maxCount = Math.max(vulnSummary.critical, vulnSummary.high, vulnSummary.medium, vulnSummary.low, 1);
  const barWidth = 200;
  const barHeight = 24;
  const gap = 8;
  const labelWidth = 70;
  const bars = [
    { label: 'Critical', count: vulnSummary.critical, color: severityColors.critical },
    { label: 'High', count: vulnSummary.high, color: severityColors.high },
    { label: 'Medium', count: vulnSummary.medium, color: severityColors.medium },
    { label: 'Low', count: vulnSummary.low, color: severityColors.low },
  ];
  const svgH = bars.length * (barHeight + gap) + gap;
  let svg = `<svg width="340" height="${svgH}" xmlns="http://www.w3.org/2000/svg" style="font-family:sans-serif;font-size:13px;">`;
  bars.forEach((b, i) => {
    const y = gap + i * (barHeight + gap);
    const w = maxCount > 0 ? (b.count / maxCount) * barWidth : 0;
    svg += `<text x="0" y="${y + 17}" fill="#333">${b.label}</text>`;
    svg += `<rect x="${labelWidth}" y="${y}" width="${w}" height="${barHeight}" rx="4" fill="${b.color}" />`;
    svg += `<text x="${labelWidth + w + 8}" y="${y + 17}" fill="#333">${b.count}</text>`;
  });
  svg += '</svg>';

  // Build component table
  let componentRows = '';
  for (const c of components.slice(0, 200)) {
    const eco = extractEcosystem(c);
    const scope = c.scope || 'required';
    componentRows += `<tr><td>${escapeHtml(c.name)}</td><td>${escapeHtml(c.version)}</td><td>${escapeHtml(eco)}</td><td>${scope}</td></tr>`;
  }

  // Build vulnerability table
  let vulnRows = '';
  for (const v of vulnerabilities.slice(0, 100)) {
    const severity = v.ratings?.[0]?.severity || 'unknown';
    const color = severityColors[severity] || '#9ca3af';
    vulnRows += `<tr><td><span style="color:${color};font-weight:600">${escapeHtml(severity.toUpperCase())}</span></td><td>${escapeHtml(v.id)}</td><td>${escapeHtml((v.description || '').substring(0, 200))}</td><td>${escapeHtml(v.recommendation || '')}</td></tr>`;
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SBOM Report — ${escapeHtml(projectName)}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f8fafc; color: #1e293b; }
  .header { background: linear-gradient(135deg, #1e293b 0%, #334155 100%); color: white; padding: 24px 32px; border-radius: 12px; margin-bottom: 24px; }
  .header h1 { margin: 0 0 8px; font-size: 24px; }
  .header p { margin: 0; opacity: 0.8; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .card { background: white; border-radius: 8px; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); text-align: center; }
  .card .value { font-size: 28px; font-weight: 700; }
  .card .label { font-size: 12px; color: #64748b; margin-top: 4px; }
  .section { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  .section h2 { margin-top: 0; font-size: 18px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }
  th { background: #f8fafc; font-weight: 600; color: #475569; }
  .footer { text-align: center; color: #94a3b8; font-size: 12px; margin-top: 24px; }
</style>
</head>
<body>
<div class="header">
  <h1>SBOM Report</h1>
  <p>${escapeHtml(projectName)} v${escapeHtml(projectVersion)} — Generated ${new Date().toISOString().split('T')[0]}</p>
</div>

<div class="cards">
  <div class="card"><div class="value">${components.length}</div><div class="label">Components</div></div>
  <div class="card"><div class="value" style="color:${totalVulns > 0 ? '#ef4444' : '#22c55e'}">${totalVulns}</div><div class="label">Vulnerabilities</div></div>
  <div class="card"><div class="value" style="color:#ef4444">${vulnSummary.critical}</div><div class="label">Critical</div></div>
  <div class="card"><div class="value" style="color:#f97316">${vulnSummary.high}</div><div class="label">High</div></div>
  <div class="card"><div class="value">${Object.keys(byEcosystem).length}</div><div class="label">Ecosystems</div></div>
</div>

${totalVulns > 0 ? `<div class="section"><h2>Vulnerability Severity</h2>${svg}</div>` : ''}

${vulnRows ? `<div class="section"><h2>Vulnerabilities (${vulnerabilities.length})</h2><table><thead><tr><th>Severity</th><th>ID</th><th>Description</th><th>Fix</th></tr></thead><tbody>${vulnRows}</tbody></table>${vulnerabilities.length > 100 ? '<p style="color:#94a3b8;font-size:12px">Showing first 100 of ' + vulnerabilities.length + '</p>' : ''}</div>` : ''}

<div class="section">
  <h2>Component Inventory (${components.length})</h2>
  <table>
    <thead><tr><th>Name</th><th>Version</th><th>Ecosystem</th><th>Scope</th></tr></thead>
    <tbody>${componentRows}</tbody>
  </table>
  ${components.length > 200 ? '<p style="color:#94a3b8;font-size:12px">Showing first 200 of ' + components.length + '</p>' : ''}
</div>

<div class="footer">
  Generated by ProofLayer agent-security-scanner-mcp — CycloneDX v1.5 — ${new Date().toISOString()}
</div>
</body>
</html>`;
}

function error(msg) {
  return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }] };
}
