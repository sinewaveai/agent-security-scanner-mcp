import { writeFileSync } from "fs";
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
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--json") {
      flags.json = true;
    } else if (arg === "--client" && args[i + 1]) {
      flags.client = args[++i];
    } else if ((arg === "--output" || arg === "-o") && args[i + 1]) {
      flags.output = args[++i];
    }
  }

  if (!KNOWN_CLIENTS.has(flags.client)) {
    flags.client = "claude-code";
  }

  return flags;
}

function commandById(plan, id) {
  return plan.commands.find((command) => command.id === id)?.command || null;
}

export function buildShareKit(cwd = process.cwd(), options = {}) {
  const client = KNOWN_CLIENTS.has(options.client) ? options.client : "claude-code";
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
    `First command: ${scanProject}`,
  ].join(" ");

  const issueTemplate = [
    "## Agent Security Smoke Test",
    "",
    "Run this before trusting AI-agent changes in this repo:",
    "",
    "```bash",
    scanProject,
    "```",
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
  const kit = buildShareKit(cwd, { client: flags.client });
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
