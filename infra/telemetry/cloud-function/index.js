// Cloud Function: telemetry event ingestion
// Receives batched events from agent-security-scanner-mcp clients,
// validates and sanitizes them, then writes to BigQuery.

const { BigQuery } = require('@google-cloud/bigquery');

const bigquery = new BigQuery();
const DATASET = 'scanner_telemetry';
const TABLE = 'events';
const MAX_BATCH = 100;
const SCHEMA_VERSION = 1;

// Allowlisted event fields (defense in depth — strip anything unexpected)
const ALLOWED_FIELDS = new Set([
  'schema_version', 'event', 'timestamp', 'machine_id', 'session_id',
  'scanner_version', 'os_platform', 'os_arch', 'node_version', 'invocation_mode',
  'tool_name', 'verbosity', 'duration_ms', 'success', 'error_code', 'error_class',
  'engine_mode', 'daemon_used', 'language', 'languages', 'files_scanned',
  'issues_count', 'by_severity', 'grade', 'has_cross_file', 'output_format',
  'action', 'risk_level', 'findings_count', 'categories', 'action_type', 'has_context',
  'ecosystem', 'packages_checked', 'hallucinated_count',
  'engine_available', 'python_available', 'is_ci',
]);

// Required fields for all events
const REQUIRED_FIELDS = ['event', 'timestamp', 'machine_id'];

function sanitizeEvent(raw) {
  const clean = {};
  for (const key of Object.keys(raw)) {
    if (ALLOWED_FIELDS.has(key)) {
      clean[key] = raw[key];
    }
  }
  // Add server-side ingestion timestamp
  clean._ingested_at = new Date().toISOString();
  return clean;
}

function validateEvent(event) {
  if (event.schema_version !== SCHEMA_VERSION) return false;
  for (const field of REQUIRED_FIELDS) {
    if (!event[field]) return false;
  }
  return true;
}

exports.ingestEvents = async (req, res) => {
  // CORS headers
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(204).send('');
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const body = req.body;
  if (!body || !Array.isArray(body.events)) {
    return res.status(400).json({ error: 'Expected { events: [...] }' });
  }

  if (body.events.length > MAX_BATCH) {
    return res.status(400).json({ error: `Max ${MAX_BATCH} events per batch` });
  }

  const rows = [];
  let skipped = 0;

  for (const raw of body.events) {
    if (!validateEvent(raw)) {
      skipped++;
      continue;
    }
    rows.push(sanitizeEvent(raw));
  }

  if (rows.length === 0) {
    return res.status(200).json({ accepted: 0, skipped });
  }

  try {
    await bigquery.dataset(DATASET).table(TABLE).insert(rows);
    return res.status(200).json({ accepted: rows.length, skipped });
  } catch (err) {
    console.error('BigQuery insert error:', err.message);
    // Return 200 anyway — never let backend errors propagate to client
    return res.status(200).json({ accepted: 0, skipped: body.events.length, error: 'ingestion_failed' });
  }
};
