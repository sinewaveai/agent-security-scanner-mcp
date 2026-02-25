// src/llm-audit.js — Multi-provider LLM deep security audit
// Supports: Anthropic, OpenAI, Gemini, Ollama, OpenRouter
// Uses Node 18+ built-in fetch() — zero extra dependencies
import { z } from "zod";
import { readFileSync, existsSync } from "fs";
import { basename } from "path";

export const deepAuditSchema = {
  file_path: z.string().describe("Path to the file to audit"),
  provider: z.enum(['anthropic', 'openai', 'gemini', 'ollama', 'openrouter']).optional().describe("LLM provider (default: auto-detect from available API keys)"),
  model: z.string().optional().describe("Model name override (default: provider-specific default)")
};

// Provider configurations
const PROVIDERS = {
  anthropic: {
    envKey: 'ANTHROPIC_API_KEY',
    url: 'https://api.anthropic.com/v1/messages',
    defaultModel: 'claude-sonnet-4-20250514',
    buildRequest: (apiKey, model, prompt) => ({
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model,
        max_tokens: 4096,
        messages: [{ role: 'user', content: prompt }]
      })
    }),
    extractText: (data) => data.content?.[0]?.text || ''
  },
  openai: {
    envKey: 'OPENAI_API_KEY',
    url: 'https://api.openai.com/v1/chat/completions',
    defaultModel: 'gpt-4o',
    buildRequest: (apiKey, model, prompt) => ({
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model,
        messages: [{ role: 'user', content: prompt }],
        max_tokens: 4096,
        temperature: 0.1
      })
    }),
    extractText: (data) => data.choices?.[0]?.message?.content || ''
  },
  gemini: {
    envKey: 'GEMINI_API_KEY',
    url: 'https://generativelanguage.googleapis.com/v1beta/models',
    defaultModel: 'gemini-2.0-flash',
    buildRequest: (apiKey, model, prompt) => ({
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { maxOutputTokens: 4096, temperature: 0.1 }
      }),
      // URL includes model and key
      url: `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`
    }),
    extractText: (data) => data.candidates?.[0]?.content?.parts?.[0]?.text || ''
  },
  ollama: {
    envKey: null, // no key needed
    url: 'http://localhost:11434/api/generate',
    defaultModel: 'llama3.2',
    buildRequest: (_apiKey, model, prompt) => ({
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        prompt,
        stream: false,
        options: { temperature: 0.1 }
      })
    }),
    extractText: (data) => data.response || ''
  },
  openrouter: {
    envKey: 'OPENROUTER_API_KEY',
    url: 'https://openrouter.ai/api/v1/chat/completions',
    defaultModel: 'anthropic/claude-sonnet-4',
    buildRequest: (apiKey, model, prompt) => ({
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
        'HTTP-Referer': 'https://www.proof-layer.com',
        'X-Title': 'ProofLayer Scanner'
      },
      body: JSON.stringify({
        model,
        messages: [{ role: 'user', content: prompt }],
        max_tokens: 4096,
        temperature: 0.1
      })
    }),
    extractText: (data) => data.choices?.[0]?.message?.content || ''
  }
};

// Auto-detect provider from available API keys
function detectProvider() {
  for (const [name, config] of Object.entries(PROVIDERS)) {
    if (name === 'ollama') continue; // try ollama last
    if (config.envKey && process.env[config.envKey]) return name;
  }
  return 'ollama'; // fallback to local
}

// Build the 3-pass audit prompt
function buildAuditPrompt(code, filename) {
  return `You are a senior application security engineer performing a deep security audit.

METHODOLOGY: Follow these 3 passes on the code below:

## Pass 1: UNDERSTAND
- Identify the purpose of this code
- Map all inputs, outputs, and data flows
- Note all external interactions (network, file, DB, env)

## Pass 2: DETECT
- Look for vulnerabilities that regex scanners miss:
  - Logic flaws and race conditions
  - Broken authentication / authorization
  - Insecure defaults and misconfigurations
  - Business logic vulnerabilities
  - Time-of-check-time-of-use (TOCTOU)
  - Information leakage through error messages
  - Missing security headers or controls
- For MCP servers specifically:
  - Tool poisoning via description injection
  - Tool name spoofing / homoglyph attacks
  - Excessive permissions (shell, file, network)
  - Data exfiltration through tool responses
  - Rug pull potential (schema mutation)

## Pass 3: CLASSIFY
For each finding, provide:
- severity: "critical", "high", "medium", "low", or "info"
- title: short description
- description: detailed explanation
- cwe: CWE identifier if applicable
- confidence: "high", "medium", or "low"
- attack_scenario: how an attacker could exploit this
- recommendation: how to fix it

Respond with a valid JSON object (no markdown fences):
{
  "summary": "brief overall assessment",
  "findings": [
    {
      "severity": "...",
      "title": "...",
      "description": "...",
      "cwe": "CWE-XXX",
      "confidence": "...",
      "attack_scenario": "...",
      "recommendation": "...",
      "line": null
    }
  ]
}

If no issues found, return: {"summary": "No security issues found", "findings": []}

## File: ${filename}
\`\`\`
${code.substring(0, 50000)}
\`\`\``;
}

// Parse LLM response into structured findings
function parseResponse(text) {
  // Try to extract JSON from the response
  const jsonMatch = text.match(/\{[\s\S]*\}/);
  if (!jsonMatch) {
    return { summary: 'Failed to parse LLM response', findings: [], raw: text.substring(0, 500) };
  }

  try {
    const parsed = JSON.parse(jsonMatch[0]);
    return {
      summary: parsed.summary || 'Audit complete',
      findings: Array.isArray(parsed.findings) ? parsed.findings : []
    };
  } catch {
    return { summary: 'Failed to parse LLM response as JSON', findings: [], raw: text.substring(0, 500) };
  }
}

export async function deepAudit({ file_path, provider, model }) {
  // Check consent
  if (!process.env.PROOFLAYER_LLM_CONSENT) {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          error: "LLM audit requires explicit consent. Set PROOFLAYER_LLM_CONSENT=1 to enable. This will send code to an external AI provider for analysis.",
          action_required: "Set environment variable PROOFLAYER_LLM_CONSENT=1"
        }, null, 2)
      }]
    };
  }

  if (!existsSync(file_path)) {
    return {
      content: [{ type: "text", text: JSON.stringify({ error: "File not found" }) }]
    };
  }

  const code = readFileSync(file_path, 'utf-8');
  const filename = basename(file_path);

  // Resolve provider
  const providerName = provider || detectProvider();
  const providerConfig = PROVIDERS[providerName];
  if (!providerConfig) {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({ error: `Unknown provider: ${providerName}. Supported: ${Object.keys(PROVIDERS).join(', ')}` })
      }]
    };
  }

  // Check API key (except ollama)
  const apiKey = providerConfig.envKey ? process.env[providerConfig.envKey] : null;
  if (providerConfig.envKey && !apiKey) {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          error: `API key not found. Set ${providerConfig.envKey} environment variable.`,
          provider: providerName
        })
      }]
    };
  }

  const modelName = model || providerConfig.defaultModel;
  const prompt = buildAuditPrompt(code, filename);
  const requestConfig = providerConfig.buildRequest(apiKey, modelName, prompt);

  // Use custom URL for Gemini
  const url = requestConfig.url || providerConfig.url;

  try {
    const response = await fetch(url, {
      method: requestConfig.method,
      headers: requestConfig.headers,
      body: requestConfig.body
    });

    if (!response.ok) {
      const errorText = await response.text();
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            error: `${providerName} API returned ${response.status}: ${errorText.substring(0, 200)}`,
            provider: providerName,
            model: modelName
          })
        }]
      };
    }

    const data = await response.json();
    const text = providerConfig.extractText(data);
    const result = parseResponse(text);

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          ...result,
          provider: providerName,
          model: modelName,
          file: file_path,
          timestamp: new Date().toISOString()
        }, null, 2)
      }]
    };
  } catch (error) {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          error: `${providerName} API call failed: ${error.message}`,
          provider: providerName,
          model: modelName,
          suggestion: providerName === 'ollama' ? 'Is Ollama running? Start it with: ollama serve' : 'Check your API key and network connection'
        })
      }]
    };
  }
}
