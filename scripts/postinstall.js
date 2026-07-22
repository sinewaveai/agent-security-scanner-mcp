#!/usr/bin/env node
/**
 * postinstall.js - Setup script for agent-security-scanner-mcp
 * 1. Install Python dependencies for tree-sitter AST engine (optional)
 * 2. Install and build code-review-agent dependencies (optional)
 */
import { execFileSync, execSync } from "child_process";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { existsSync } from "fs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, "..");
const requirementsPath = join(rootDir, "requirements.txt");
const codeReviewAgentDir = join(rootDir, "code-review-agent");

// Check if Python 3 is available
function findPython() {
  for (const cmd of ["python3", "python"]) {
    try {
      const ver = execFileSync(cmd, ["--version"], { encoding: "utf-8", timeout: 5000, stdio: ["pipe", "pipe", "pipe"] }).trim();
      if (ver.includes("3.")) return cmd;
    } catch { /* not found */ }
  }
  return null;
}

// Check if tree-sitter is already installed
function isTreeSitterInstalled(pythonCmd) {
  try {
    execFileSync(pythonCmd, ["-c", "import tree_sitter; print(tree_sitter.__version__)"], {
      encoding: "utf-8", timeout: 5000, stdio: ["pipe", "pipe", "pipe"]
    });
    return true;
  } catch {
    return false;
  }
}

// Setup Python dependencies
const pythonCmd = findPython();

if (!pythonCmd) {
  console.log(
    "[postinstall] Python 3 not found. The scanner will run in regex-only mode.\n" +
    "             Install Python 3 and run: pip install -r requirements.txt"
  );
} else if (isTreeSitterInstalled(pythonCmd)) {
  console.log("[postinstall] tree-sitter already installed — AST engine enabled.");
} else {
  try {
    execFileSync(pythonCmd, ["-m", "pip", "install", "-r", requirementsPath, "--user", "--quiet"], {
      timeout: 120000,
      stdio: "inherit",
    });
    console.log("[postinstall] Python dependencies installed — AST engine enabled.");
  } catch {
    console.log(
      "[postinstall] Could not install Python dependencies (tree-sitter).\n" +
      "             The scanner will run in regex-only mode, which still catches common vulnerabilities.\n" +
      "             To enable AST analysis later, run: python3 -m pip install -r requirements.txt\n" +
      "             Or run: npx agent-security-scanner-mcp doctor --fix"
    );
  }
}

// Setup code-review-agent (LLM-powered semantic analysis)
if (existsSync(codeReviewAgentDir)) {
  // The published package ships a pre-built `dist/`, so checking only for
  // dist/bin/cr-agent.js is a false positive: that file is always present,
  // regardless of whether code-review-agent's own runtime dependencies
  // (commander, @anthropic-ai/sdk, openai, etc.) were ever installed —
  // node_modules is correctly never shipped, so it must be checked separately.
  const nodeModulesExists = existsSync(join(codeReviewAgentDir, "node_modules"));
  const distExists = existsSync(join(codeReviewAgentDir, "dist", "bin", "cr-agent.js"));

  if (nodeModulesExists && distExists) {
    console.log("[postinstall] code-review-agent already set up — cr-agent CLI available.");
  } else {
    console.log("[postinstall] Setting up code-review-agent (LLM-powered code review)...");
    try {
      if (!nodeModulesExists) {
        // Install dependencies
        execSync("npm install --omit=dev", {
          cwd: codeReviewAgentDir,
          timeout: 180000,
          stdio: ["pipe", "pipe", "pipe"]
        });
      }

      if (!distExists) {
        // Build TypeScript
        execSync("npm run build", {
          cwd: codeReviewAgentDir,
          timeout: 60000,
          stdio: ["pipe", "pipe", "pipe"]
        });
      }

      console.log("[postinstall] code-review-agent installed — run: npx cr-agent --help");
    } catch (err) {
      console.log(
        "[postinstall] Could not set up code-review-agent (optional LLM-powered review).\n" +
        "             The main scanner still works. To set up manually:\n" +
        "             cd node_modules/agent-security-scanner-mcp/code-review-agent && npm install && npm run build"
      );
    }
  }
}
