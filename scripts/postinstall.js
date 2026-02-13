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

try {
  execFileSync("python3", ["-m", "pip", "install", "-r", requirementsPath, "--user", "--quiet"], {
    timeout: 120000,
    stdio: "inherit",
  });
  console.log("[postinstall] Python dependencies installed - AST engine enabled.");
} catch {
  console.log(
    "[postinstall] Could not install Python dependencies (tree-sitter).\n" +
    "             The scanner will run in regex-only mode, which still catches common vulnerabilities.\n" +
    "             To enable AST analysis later, run: python3 -m pip install -r requirements.txt"
  );
}
