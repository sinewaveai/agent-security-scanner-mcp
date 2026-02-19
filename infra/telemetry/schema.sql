-- BigQuery schema for scanner telemetry events
-- Dataset: scanner_telemetry
-- Table: events

CREATE TABLE IF NOT EXISTS scanner_telemetry.events (
  schema_version INT64,
  event STRING NOT NULL,
  timestamp TIMESTAMP NOT NULL,
  machine_id STRING NOT NULL,
  session_id STRING,
  scanner_version STRING,
  os_platform STRING,
  os_arch STRING,
  node_version STRING,
  invocation_mode STRING,

  -- tool.invoked fields
  tool_name STRING,
  verbosity STRING,
  duration_ms INT64,
  success BOOL,
  error_code STRING,
  error_class STRING,

  -- scan.completed fields
  engine_mode STRING,
  daemon_used BOOL,
  language STRING,
  languages ARRAY<STRING>,
  files_scanned INT64,
  issues_count INT64,
  by_severity STRUCT<error INT64, warning INT64, info INT64>,
  grade STRING,
  has_cross_file BOOL,
  output_format STRING,

  -- prompt.scanned fields
  action STRING,
  risk_level STRING,
  findings_count INT64,
  categories ARRAY<STRING>,
  action_type STRING,
  has_context BOOL,

  -- package.checked fields
  ecosystem STRING,
  packages_checked INT64,
  hallucinated_count INT64,

  -- install fields
  engine_available STRING,
  python_available BOOL,
  is_ci BOOL,

  -- server-side metadata
  _ingested_at TIMESTAMP
)
PARTITION BY DATE(timestamp)
CLUSTER BY event, machine_id;

-- Set 90-day expiration on raw events
ALTER TABLE scanner_telemetry.events
SET OPTIONS (
  partition_expiration_days = 90
);
