import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { dirname, join, resolve } from 'path';
import { fileURLToPath } from 'url';

function parseFlags(args) {
  const flags = {
    provider: 'github',
    dryRun: false,
    force: false,
    outputPath: null,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--dry-run') {
      flags.dryRun = true;
    } else if (arg === '--force') {
      flags.force = true;
    } else if (arg === '--path' && args[i + 1]) {
      flags.outputPath = args[++i];
    } else if (!arg.startsWith('-')) {
      flags.provider = arg;
    }
  }

  return flags;
}

function repoRootFromModule() {
  return resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
}

export async function runInitCi(args = [], options = {}) {
  const flags = parseFlags(args);
  const cwd = options.cwd || process.cwd();
  const repoRoot = options.repoRoot || repoRootFromModule();

  if (flags.provider !== 'github') {
    throw new Error(`unsupported CI provider: ${flags.provider}. Supported providers: github`);
  }

  const templatePath = join(repoRoot, 'templates', 'github-action-security.yml');
  const outputPath = resolve(cwd, flags.outputPath || join('.github', 'workflows', 'agent-security.yml'));

  if (!existsSync(templatePath)) {
    throw new Error(`GitHub Actions template not found: ${templatePath}`);
  }

  const template = readFileSync(templatePath, 'utf8');

  console.log('\n  agent-security-scanner-mcp CI setup\n');
  console.log(`  Provider: GitHub Actions`);
  console.log(`  Output:   ${outputPath}`);

  if (existsSync(outputPath) && !flags.force) {
    console.log('\n  Workflow already exists. Use --force to overwrite, or --path to choose another file.\n');
    return { written: false, outputPath, reason: 'exists' };
  }

  if (flags.dryRun) {
    console.log('\n  [dry-run] Would write workflow:\n');
    console.log(template);
    console.log('  No changes made.\n');
    return { written: false, outputPath, dryRun: true };
  }

  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, template, 'utf8');

  console.log('\n  Wrote GitHub Actions workflow.');
  console.log('  Next steps: commit the workflow and open a pull request to see scan comments.\n');

  return { written: true, outputPath };
}

