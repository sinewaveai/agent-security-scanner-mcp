#!/usr/bin/env node
/**
 * postinstall.js - Attempt to install Python dependencies for tree-sitter AST engine.
 * If installation fails, the scanner gracefully falls back to regex-only mode.
 */
import { execFileSync } from "child_process";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const requirementsPath = join(__dirname, "..", "requirements.txt");

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
