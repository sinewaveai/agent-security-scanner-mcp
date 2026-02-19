-- Aggregate views for scanner telemetry dashboards

-- Daily tool usage: which tools are called, how often, by how many machines
CREATE OR REPLACE VIEW scanner_telemetry.daily_tool_usage AS
SELECT
  DATE(timestamp) AS date,
  tool_name,
  COUNT(*) AS invocations,
  COUNT(DISTINCT machine_id) AS unique_machines,
  ROUND(AVG(duration_ms), 0) AS avg_duration_ms,
  COUNTIF(success = TRUE) AS successes,
  COUNTIF(success = FALSE) AS failures
FROM scanner_telemetry.events
WHERE event = 'tool.invoked'
GROUP BY date, tool_name
ORDER BY date DESC, invocations DESC;

-- Daily scan stats: language distribution, engine health, scan effectiveness
CREATE OR REPLACE VIEW scanner_telemetry.daily_scan_stats AS
SELECT
  DATE(timestamp) AS date,
  language,
  engine_mode,
  COUNT(*) AS scans,
  ROUND(AVG(issues_count), 1) AS avg_issues,
  COUNTIF(grade = 'A') AS grade_a,
  COUNTIF(grade = 'B') AS grade_b,
  COUNTIF(grade = 'C') AS grade_c,
  COUNTIF(grade = 'D') AS grade_d,
  COUNTIF(grade = 'F') AS grade_f
FROM scanner_telemetry.events
WHERE event = 'scan.completed'
GROUP BY date, language, engine_mode
ORDER BY date DESC, scans DESC;

-- Weekly installs: volume, platform distribution, engine availability
CREATE OR REPLACE VIEW scanner_telemetry.weekly_installs AS
SELECT
  DATE_TRUNC(DATE(timestamp), WEEK) AS week,
  COUNT(*) AS installs,
  COUNTIF(os_platform = 'darwin') AS macos,
  COUNTIF(os_platform = 'linux') AS linux,
  COUNTIF(os_platform = 'win32') AS windows,
  COUNTIF(engine_available = 'ast') AS ast_available,
  COUNTIF(engine_available = 'regex') AS regex_only,
  COUNTIF(engine_available = 'regex-only') AS no_python,
  COUNTIF(is_ci = TRUE) AS ci_installs
FROM scanner_telemetry.events
WHERE event = 'install'
GROUP BY week
ORDER BY week DESC;

-- Monthly active machines: unique machines sending events per month
CREATE OR REPLACE VIEW scanner_telemetry.monthly_active_machines AS
SELECT
  DATE_TRUNC(DATE(timestamp), MONTH) AS month,
  COUNT(DISTINCT machine_id) AS unique_machines,
  COUNT(*) AS total_events
FROM scanner_telemetry.events
GROUP BY month
ORDER BY month DESC;
