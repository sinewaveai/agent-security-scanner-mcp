// src/cli/audit.js — OpenClaw configuration security audit (stub)

export async function runAudit(args) {
  const allowStub = args.includes('--allow-stub');

  console.log('\n  Security Audit [NOT YET IMPLEMENTED]\n');
  console.log('  This command will check your OpenClaw configuration for security issues.');
  console.log('  Implementation is in progress.\n');
  console.log('  Planned checks (60+):');
  console.log('    - Gateway: bind mode, auth, token strength, HTTPS, CORS');
  console.log('    - Permissions: config files, credentials, session transcripts');
  console.log('    - Tool Policy: allowlist, sandbox, elevated tools');
  console.log('    - DM/Group: open access, pairing bypass, mention gating');
  console.log('    - Hooks: weak tokens, unsafe external content');
  console.log('    - mDNS: exposure, metadata leaks');
  console.log('    - Plugins: unsigned, permissive, outdated');
  console.log('    - Credentials: plaintext secrets, exposed API keys\n');
  console.log('  OWASP ASI Top 10 mapping for all findings.\n');

  if (!allowStub) {
    console.error('  ERROR: audit is not yet implemented. No checks were performed.');
    console.error('  Pass --allow-stub to suppress this error in CI.\n');
    throw new Error('audit command is not yet implemented');
  }
}
