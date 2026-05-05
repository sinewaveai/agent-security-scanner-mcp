// src/tools/compliance-controls.js — get_compliance_controls MCP tool (thin wrapper)

import { z } from 'zod';
import { loadControls, filterControls, listFrameworks } from '../lib/compliance-controls.js';

export const complianceControlsSchema = {
  framework: z.string().optional().describe("Framework to query (default: aiuc-1). Use 'soc2-technical', 'gdpr-technical', etc."),
  domain: z.string().optional().describe("Filter by domain (e.g. 'security', 'safety', 'all'). Accepted values depend on the framework."),
  control_ids: z.array(z.string()).optional().describe("Specific control IDs to retrieve"),
  owasp_filter: z.array(z.string()).optional().describe("Filter by OWASP LLM tags (e.g. LLM01)"),
  verbosity: z.enum(['minimal', 'compact', 'full']).optional().describe("Response detail level"),
};

export async function getComplianceControls({ framework, domain, control_ids, owasp_filter, verbosity }) {
  const fw = framework || 'aiuc-1';
  const level = verbosity || 'compact';

  const controls = filterControls({
    framework: fw,
    domain: domain || 'all',
    controlIds: control_ids,
    owaspFilter: owasp_filter,
  });

  const registry = loadControls(fw);

  let output;
  switch (level) {
    case 'minimal':
      output = {
        framework: registry.framework,
        domains: registry.domains,
        controls_count: controls.length,
        controls: controls.map(c => ({ id: c.id, title: c.title, domain: c.domain })),
      };
      break;

    case 'full':
      output = {
        framework: registry.framework,
        schema_version: registry.schema_version,
        source: registry.source,
        source_snapshot: registry.source_snapshot,
        domains: registry.domains,
        available_frameworks: listFrameworks(),
        controls_count: controls.length,
        controls,
      };
      break;

    case 'compact':
    default:
      output = {
        framework: registry.framework,
        controls_count: controls.length,
        controls: controls.map(c => {
          const out = {
            id: c.id,
            title: c.title,
            domain: c.domain,
            scanner_tools: c.scanner_tools,
            evaluation: c.evaluation,
          };
          if (c.owasp_llm) out.owasp_llm = c.owasp_llm;
          if (c.references) out.references = c.references;
          return out;
        }),
      };
  }

  return {
    content: [{
      type: 'text',
      text: JSON.stringify(output, null, 2),
    }],
  };
}
