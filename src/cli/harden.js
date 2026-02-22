// src/cli/harden.js — OpenClaw auto-hardening (stub)

export async function runHarden(args) {
  const allowStub = args.includes('--allow-stub');

  console.log('\n  Auto-Hardening [NOT YET IMPLEMENTED]\n');
  console.log('  This command will automatically fix security issues in your OpenClaw config.');
  console.log('  Implementation is in progress.\n');
  console.log('  Planned actions:');
  console.log('    - Bind gateway to 127.0.0.1');
  console.log('    - Enable token authentication');
  console.log('    - Set config file permissions to 600');
  console.log('    - Disable mDNS discovery');
  console.log('    - Remove plaintext credentials\n');
  console.log('  Usage: agent-security-scanner-mcp harden --fix [--dry-run]\n');

  if (!allowStub) {
    console.error('  ERROR: harden is not yet implemented. No actions were performed.');
    console.error('  Pass --allow-stub to suppress this error in CI.\n');
    throw new Error('harden command is not yet implemented');
  }
}
