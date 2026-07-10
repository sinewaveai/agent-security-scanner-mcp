import { existsSync, readFileSync, readdirSync, statSync } from "fs";
import { join, relative } from "path";

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

const SOURCE_EXTENSIONS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".java", ".rb", ".php", ".rs", ".cs",
]);

const LOCKFILES = [
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "requirements.txt",
  "poetry.lock",
  "Pipfile.lock",
  "Cargo.lock",
  "go.sum",
  "Gemfile.lock",
];

function parseFlags(args) {
  const flags = {
    json: false,
    client: "claude-code",
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--json") {
      flags.json = true;
    } else if (arg === "--client" && args[i + 1]) {
      flags.client = args[++i];
    }
  }

  if (!KNOWN_CLIENTS.has(flags.client)) {
    flags.client = "claude-code";
  }

  return flags;
}

function safeReadPackageJson(cwd) {
  const packagePath = join(cwd, "package.json");
  if (!existsSync(packagePath)) return null;

  try {
    return JSON.parse(readFileSync(packagePath, "utf-8"));
  } catch {
    return null;
  }
}

function hasAny(cwd, names) {
  return names.some((name) => existsSync(join(cwd, name)));
}

function hasSourceFiles(cwd) {
  let entries;
  try {
    entries = readdirSync(cwd);
  } catch {
    return false;
  }

  return entries.some((entry) => {
    const fullPath = join(cwd, entry);
    try {
      const stat = statSync(fullPath);
      if (stat.isDirectory()) {
        return ["src", "app", "lib", "server", "packages"].includes(entry);
      }
      return SOURCE_EXTENSIONS.has(entry.slice(entry.lastIndexOf(".")).toLowerCase());
    } catch {
      return false;
    }
  });
}

function packageUsesMcp(pkg) {
  if (!pkg) return false;
  const deps = {
    ...(pkg.dependencies || {}),
    ...(pkg.devDependencies || {}),
    ...(pkg.peerDependencies || {}),
    ...(pkg.optionalDependencies || {}),
  };
  return Object.keys(deps).some((name) => name.includes("@modelcontextprotocol/sdk"));
}

function addCommand(commands, id, label, command, why) {
  commands.push({ id, label, command, why });
}

export function buildQuickstartPlan(cwd = process.cwd(), options = {}) {
  const client = KNOWN_CLIENTS.has(options.client) ? options.client : "claude-code";
  const pkg = safeReadPackageJson(cwd);
  const detected = {
    package_json: Boolean(pkg),
    lockfile: hasAny(cwd, LOCKFILES),
    source_files: hasSourceFiles(cwd),
    mcp_server: packageUsesMcp(pkg) || hasAny(cwd, ["server.json", "mcp.json"]),
    skill: hasAny(cwd, ["SKILL.md", "skill.md"]),
    github_repo: existsSync(join(cwd, ".git")) || existsSync(join(cwd, ".github")),
  };

  const commands = [];

  addCommand(
    commands,
    "scan-project",
    "Grade the whole repo",
    "npx agent-security-scanner-mcp scan-project . --verbosity compact",
    "Fastest way to get an A-F security grade before trusting agent changes."
  );

  if (detected.mcp_server) {
    addCommand(
      commands,
      "scan-mcp",
      "Audit this MCP server",
      "npx agent-security-scanner-mcp scan-mcp . --verbosity compact",
      "This repo looks like an MCP server; check tool descriptions, permissions, shell usage, and validation."
    );
  }

  if (detected.skill) {
    addCommand(
      commands,
      "scan-skill",
      "Scan the local AI skill",
      "npx agent-security-scanner-mcp scan-skill . --verbosity compact",
      "A SKILL.md file is present; scan prompt instructions, code blocks, dependencies, and rug-pull risk."
    );
  }

  if (detected.package_json || detected.source_files) {
    addCommand(
      commands,
      "scan-packages",
      "Check AI-suggested imports",
      "npx agent-security-scanner-mcp scan-packages ./src/app.ts npm --verbosity compact",
      "Use this on a real source file after an agent adds imports to catch hallucinated packages."
    );
  }

  if (detected.lockfile || detected.package_json) {
    addCommand(
      commands,
      "sbom-report",
      "Create a dependency audit report",
      "npx agent-security-scanner-mcp sbom-report . --format html",
      "Generate an SBOM report with dependency inventory and vulnerability context."
    );
  }

  addCommand(
    commands,
    "init-client",
    `Install into ${client}`,
    `npx agent-security-scanner-mcp init ${client}`,
    "Adds the scanner to your AI coding client so checks are available inside the agent workflow."
  );

  if (detected.github_repo) {
    addCommand(
      commands,
      "init-ci",
      "Add GitHub Actions scan",
      "npx agent-security-scanner-mcp init-ci github",
      "Run security scans in pull requests and on a weekly schedule."
    );
  }

  return {
    cwd,
    project: pkg?.name || relative(process.cwd(), cwd) || ".",
    detected,
    recommended_first_command: commands[0].command,
    commands,
  };
}

function printPlan(plan) {
  console.log("\n  agent-security-scanner-mcp quickstart\n");
  console.log(`  Project: ${plan.project}`);
  console.log("  Detected:");
  for (const [key, value] of Object.entries(plan.detected)) {
    console.log(`    ${key.replace(/_/g, " ").padEnd(14)} ${value ? "yes" : "no"}`);
  }

  console.log("\n  Recommended commands:\n");
  for (const command of plan.commands) {
    console.log(`  ${command.label}`);
    console.log(`    ${command.command}`);
    console.log(`    ${command.why}\n`);
  }
}

export async function runQuickstart(args = [], options = {}) {
  const flags = parseFlags(args);
  const cwd = options.cwd || process.cwd();
  const plan = buildQuickstartPlan(cwd, { client: flags.client });

  if (flags.json) {
    console.log(JSON.stringify(plan, null, 2));
  } else {
    printPlan(plan);
  }

  return plan;
}
