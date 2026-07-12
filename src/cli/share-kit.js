import { readFileSync, writeFileSync } from "fs";
import { buildQuickstartPlan } from "./quickstart.js";

const KNOWN_CLIENTS = new Set([
  "claude-code",
  "cursor",
  "claude-desktop",
  "windsurf",
  "cline",
  "kilo-code",
  "opencode",
  "cody",
]);

function parseFlags(args) {
  const flags = {
    json: false,
    client: "claude-code",
    output: null,
    grade: null,
    finding: null,
    scanResult: null,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--json") {
      flags.json = true;
    } else if (arg === "--client" && args[i + 1]) {
      flags.client = args[++i];
    } else if ((arg === "--output" || arg === "-o") && args[i + 1]) {
      flags.output = args[++i];
    } else if (arg === "--grade" && args[i + 1]) {
      flags.grade = args[++i].toUpperCase();
    } else if (arg === "--finding" && args[i + 1]) {
      flags.finding = args[++i];
    } else if (arg === "--scan-result" && args[i + 1]) {
      flags.scanResult = args[++i];
    }
  }

  if (!KNOWN_CLIENTS.has(flags.client)) {
    flags.client = "claude-code";
  }

  return flags;
}

function normalizeGrade(value) {
  if (!value) return null;
  const grade = String(value).trim().toUpperCase();
  return /^[A-F]$/.test(grade) ? grade : null;
}

function extractFindingText(finding) {
  if (!finding || typeof finding !== "object") return null;
  return finding.message || finding.rule || finding.rule_id || finding.category || null;
}

function normalizeScanSummary(input = {}) {
  const grade = normalizeGrade(input.grade);
  const findingsCount = Number.isInteger(input.findings_count)
    ? input.findings_count
    : Number.isInteger(input.findingsCount)
      ? input.findingsCount
      : null;
  const topFinding = input.top_finding
    || input.topFinding
    || input.finding
    || extractFindingText(Array.isArray(input.findings) ? input.findings[0] : null);

  if (!grade && findingsCount === null && !topFinding) return null;

  return {
    grade,
    findings_count: findingsCount,
    top_finding: topFinding ? String(topFinding).trim().slice(0, 180) : null,
  };
}

function loadScanSummary(scanResultPath) {
  if (!scanResultPath) return null;
  const parsed = JSON.parse(readFileSync(scanResultPath, "utf-8"));
  return normalizeScanSummary(parsed);
}

function commandById(plan, id) {
  return plan.commands.find((command) => command.id === id)?.command || null;
}

export function buildShareKit(cwd = process.cwd(), options = {}) {
  const client = KNOWN_CLIENTS.has(options.client) ? options.client : "claude-code";
  const scanSummary = normalizeScanSummary(options.scanSummary || {
    grade: options.grade,
    finding: options.finding,
  });
  const plan = buildQuickstartPlan(cwd, { client });
  const scanProject = commandById(plan, "scan-project");
  const scanMcp = commandById(plan, "scan-mcp");
  const scanSkill = commandById(plan, "scan-skill");
  const scanPackages = commandById(plan, "scan-packages");
  const sbomReport = commandById(plan, "sbom-report");
  const initClient = commandById(plan, "init-client");
  const initCi = commandById(plan, "init-ci");

  const primaryCommands = [
    scanProject,
    scanMcp,
    scanSkill,
    scanPackages,
    sbomReport,
    initClient,
    initCi,
  ].filter(Boolean);

  const shortPost = [
    `I am testing agent-security-scanner-mcp on ${plan.project}.`,
    "It gives AI-agent repos an A-F security grade and checks MCP servers, prompt injection, hallucinated packages, and CI gates before agent changes are trusted.",
    scanSummary?.grade ? `Current scan grade: ${scanSummary.grade}.` : null,
    scanSummary?.top_finding ? `Top finding: ${scanSummary.top_finding}.` : null,
    `First command: ${scanProject}`,
  ].filter(Boolean).join(" ");

  const issueTemplate = [
    "## Agent Security Smoke Test",
    "",
    "Run this before trusting AI-agent changes in this repo:",
    "",
    "```bash",
    scanProject,
    "```",
    "",
    "### Current result",
    "",
    `- Grade: ${scanSummary?.grade || "TBD"}`,
    `- Findings: ${scanSummary?.findings_count ?? "TBD"}`,
    `- Top finding: ${scanSummary?.top_finding || "TBD"}`,
    "",
    "Post the grade, top finding, and one fix you applied.",
    "",
    "Suggested follow-ups:",
    ...primaryCommands.slice(1).map((command) => `- \`${command}\``),
  ].join("\n");

  const directoryListing = [
    "agent-security-scanner-mcp is an npm audit tool for AI agents and MCP servers.",
    "It scans project code, MCP tools, prompts, AI-suggested package imports, skills, and SBOMs before agent workflows are trusted.",
    "Works with Claude Code, Cursor, Claude Desktop, Windsurf, Cline, Kilo Code, OpenCode, Cody, and CI.",
  ].join(" ");

  return {
    project: plan.project,
    client,
    detected: plan.detected,
    scan_summary: scanSummary,
    commands: primaryCommands,
    short_post: shortPost,
    issue_template: issueTemplate,
    directory_listing: directoryListing,
  };
}

export function renderShareKitMarkdown(kit) {
  const commands = kit.commands.map((command) => `- \`${command}\``).join("\n");

  return [
    "# agent-security-scanner-mcp Share Kit",
    "",
    `Project: ${kit.project}`,
    `Client: ${kit.client}`,
    "",
    "## Commands",
    "",
    commands,
    "",
    "## Short Post",
    "",
    kit.short_post,
    "",
    "## GitHub Issue",
    "",
    kit.issue_template,
    "",
    "## Directory Listing",
    "",
    kit.directory_listing,
    "",
  ].join("\n");
}

export async function runShareKit(args = [], options = {}) {
  const flags = parseFlags(args);
  const cwd = options.cwd || process.cwd();
  const scanSummary = loadScanSummary(flags.scanResult) || normalizeScanSummary({
    grade: flags.grade,
    finding: flags.finding,
  });
  const kit = buildShareKit(cwd, {
    client: flags.client,
    scanSummary,
  });
  const output = flags.json
    ? JSON.stringify(kit, null, 2)
    : renderShareKitMarkdown(kit);

  if (flags.output) {
    writeFileSync(flags.output, output + "\n", "utf-8");
    console.log(`Wrote share kit: ${flags.output}`);
  } else {
    console.log(output);
  }

  return kit;
}
