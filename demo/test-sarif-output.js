// Test SARIF output directly
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

async function testSarifOutput() {
  const transport = new StdioClientTransport({
    command: 'node',
    args: [join(__dirname, '..', 'index.js')],
  });

  const client = new Client({
    name: 'sarif-test',
    version: '1.0.0',
  }, {
    capabilities: {}
  });

  await client.connect(transport);

  console.log('Testing SARIF output...\n');

  const result = await client.callTool({
    name: 'scan_security',
    arguments: {
      file_path: join(__dirname, 'sarif-test-comprehensive.py'),
      output_format: 'sarif'
    }
  });

  const sarif = JSON.parse(result.content[0].text);

  console.log('=== SARIF VALIDATION ===\n');

  // Check schema
  console.log('Schema:', sarif.$schema ? '✓' : '✗');
  console.log('Version:', sarif.version === '2.1.0' ? '✓ 2.1.0' : '✗');

  // Check runs
  console.log('Runs:', sarif.runs?.length === 1 ? '✓' : '✗');

  const run = sarif.runs[0];

  // Check tool
  console.log('\n=== TOOL INFO ===');
  console.log('Tool name:', run.tool?.driver?.name);
  console.log('Tool version:', run.tool?.driver?.version);
  console.log('Rules count:', run.tool?.driver?.rules?.length);

  // Check results
  console.log('\n=== RESULTS ===');
  console.log('Results count:', run.results?.length);

  // Validate each result
  let validResults = 0;
  let resultsWithFixes = 0;

  for (const result of run.results || []) {
    const hasRequiredFields =
      result.ruleId &&
      result.level &&
      result.message?.text &&
      result.locations?.[0]?.physicalLocation?.artifactLocation?.uri &&
      result.locations?.[0]?.physicalLocation?.region?.startLine;

    if (hasRequiredFields) validResults++;
    if (result.fixes?.length > 0) resultsWithFixes++;
  }

  console.log('Valid results:', validResults + '/' + run.results?.length);
  console.log('Results with fixes:', resultsWithFixes);

  // Check invocations
  console.log('\n=== INVOCATIONS ===');
  console.log('Execution successful:', run.invocations?.[0]?.executionSuccessful ? '✓' : '✗');
  console.log('End time:', run.invocations?.[0]?.endTimeUtc ? '✓' : '✗');

  // Check artifacts
  console.log('\n=== ARTIFACTS ===');
  console.log('Artifacts:', run.artifacts?.length > 0 ? '✓' : '✗');
  console.log('Source language:', run.artifacts?.[0]?.sourceLanguage);

  // Print sample result
  console.log('\n=== SAMPLE RESULT ===');
  console.log(JSON.stringify(run.results?.[0], null, 2));

  // Print sample rule
  console.log('\n=== SAMPLE RULE ===');
  console.log(JSON.stringify(run.tool?.driver?.rules?.[0], null, 2));

  await client.close();

  console.log('\n=== FULL SARIF OUTPUT ===');
  console.log(JSON.stringify(sarif, null, 2));
}

testSarifOutput().catch(console.error);
