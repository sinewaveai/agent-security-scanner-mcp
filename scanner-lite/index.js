#!/usr/bin/env node

// @prooflayer/scanner-lite
// Lightweight MCP security scanner for AI coding agents
// MIT License | https://github.com/sinewaveai/agent-security-scanner-mcp

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { getVersion } from './src/utils.js';

// Import tool handlers
import { scanSecurity, scanSecuritySchema } from './src/scanner.js';
import { fixSecurity, fixSecuritySchema } from './src/fix-engine.js';
import { checkPackage, checkPackageSchema } from './src/package-checker.js';
import { scanPackages, scanPackagesSchema } from './src/scan-packages.js';
import { scanAgentPrompt, scanAgentPromptSchema } from './src/prompt-scanner.js';
import { scanMcpServer, scanMcpServerSchema } from './src/tool-poisoning.js';
import { deepAudit, deepAuditSchema } from './src/llm-audit.js';
import { inspectMcpServer, inspectMcpServerSchema } from './src/inspector.js';

const server = new Server(
  {
    name: "@prooflayer/scanner-lite",
    version: getVersion(),
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

console.error(`[@prooflayer/scanner-lite v${getVersion()}] Ready. Engine: regex (zero-Python, fully offline)`);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "scan_security",
        description: "Scan code for security vulnerabilities using 400+ YAML rules. Detects SQL injection, XSS, secrets, command injection, and 30+ vulnerability types. Returns findings with severity, line numbers, and auto-fix suggestions.",
        inputSchema: {
          type: "object",
          properties: scanSecuritySchema,
          required: ["file_path"]
        }
      },
      {
        name: "fix_security",
        description: "Generate secure code fixes for vulnerabilities. Provides language-specific remediation for detected issues with explanations.",
        inputSchema: {
          type: "object",
          properties: fixSecuritySchema,
          required: ["file_path"]
        }
      },
      {
        name: "check_package",
        description: "Verify if a package exists in official registries (npm, PyPI, RubyGems, crates.io, CPAN, pub.dev, raku.land). Detects package hallucination and typosquatting.",
        inputSchema: {
          type: "object",
          properties: checkPackageSchema,
          required: ["package_name", "ecosystem"]
        }
      },
      {
        name: "scan_packages",
        description: "Scan all package imports in a file for hallucination and typosquatting. Returns verification status for each dependency.",
        inputSchema: {
          type: "object",
          properties: scanPackagesSchema,
          required: ["file_path", "ecosystem"]
        }
      },
      {
        name: "scan_agent_prompt",
        description: "Detect prompt injection, jailbreaks, and social engineering in AI agent prompts. Covers 40+ attack patterns including base64 encoding, role manipulation, and exfiltration attempts.",
        inputSchema: {
          type: "object",
          properties: scanAgentPromptSchema,
          required: ["prompt_text"]
        }
      },
      {
        name: "scan_mcp_server",
        description: "Audit MCP server source code for security vulnerabilities, tool name spoofing, description injection, unicode poisoning, and rug pull detection. Returns A-F security grade.",
        inputSchema: {
          type: "object",
          properties: scanMcpServerSchema,
          required: ["server_path"]
        }
      },
      {
        name: "deep_audit",
        description: "Optional LLM-powered deep security audit. Sends code to an AI model for analysis beyond what regex rules can detect. Requires API key and explicit consent (PROOFLAYER_LLM_CONSENT=1).",
        inputSchema: {
          type: "object",
          properties: deepAuditSchema,
          required: ["file_path"]
        }
      },
      {
        name: "inspect_mcp_server",
        description: "Launch a live MCP server process, connect via stdio, call tools/list, and scan returned tool definitions for poisoning (description injection, name spoofing, unicode attacks, schema manipulation). Read-only probe — never calls any tools.",
        inputSchema: {
          type: "object",
          properties: inspectMcpServerSchema,
          required: ["command"]
        }
      }
    ]
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "scan_security":
        return await scanSecurity(args);
      case "fix_security":
        return await fixSecurity(args);
      case "check_package":
        return await checkPackage(args);
      case "scan_packages":
        return await scanPackages(args);
      case "scan_agent_prompt":
        return await scanAgentPrompt(args);
      case "scan_mcp_server":
        return await scanMcpServer(args);
      case "deep_audit":
        return await deepAudit(args);
      case "inspect_mcp_server":
        return await inspectMcpServer(args);
      default:
        return {
          content: [{ type: "text", text: JSON.stringify({ error: `Unknown tool: ${name}` }) }]
        };
    }
  } catch (error) {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          error: error.message,
          tool: name,
          timestamp: new Date().toISOString()
        })
      }],
      isError: true
    };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[@prooflayer/scanner-lite] MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
