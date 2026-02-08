# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.1] - 2026-02-06

### Added
- MIT LICENSE file (Copyright 2026 Sinewave AI)
- MCP Registry manifest (server.json) for mcp-publisher submission
- 4 new keywords: zed, prompt-firewall, auto-fix, hallucination (38 total)

### Changed
- SEO-optimized package.json description (accurate counts: 359 rules, 4.3M+ packages)
- Fixed author email format to npm canonical angle-bracket style
- Added LICENSE and server.json to npm files array

## [2.3.0] - 2026-02-06

### Added
- Vitest test framework with 51 tests across 7 test files
- Test fixtures for Python, JavaScript vulnerabilities and clean files
- GitHub Actions CI workflow (Node 18/20/22, Python 3.12)
- CHANGELOG.md following Keep a Changelog format
- Prerequisites section in README

### Changed
- Updated README with accurate package counts and rule counts
- Updated package.json author field
- Added test scripts to package.json

## [2.2.0] - 2026-02-06

### Added
- risk_score and action metadata to all 13 generic.prompt.* rules
- 6 new jailbreak-roleplay patterns (pretend you're a hacker, act as a hacker, etc.)
- 5 new ignore-previous-instructions patterns (ignore the above and instead, forget everything above, etc.)
- 7 new base64-encoded-injection patterns (follow decoded instructions, known base64 fragments, etc.)
- New rule: generic.prompt.security.codeblock-obfuscation (attacks hidden in code blocks)
- New rule: generic.prompt.security.natural-language-exfiltration (data exfiltration via natural language)
- Code block extraction preprocessing in scan_agent_prompt
- Runtime base64 decode-and-rescan in scan_agent_prompt
- 6 new CATEGORY_WEIGHTS entries (prompt-injection-encoded, -context, -privilege, -multi-turn, -output, unknown)

### Changed
- Lowered RISK_THRESHOLDS: HIGH 70→65, MEDIUM 50→40, LOW 25→20
- Bumped CATEGORY_WEIGHTS: prompt-injection-content 0.9→1.0, prompt-injection-jailbreak 0.85→1.0
- Enhanced compound boosting: cross-category boost (0.15), mixed-severity boost (1.1x)

### Fixed
- Prompt injection detection rate improved from ~33% to 80%+

## [2.1.0] - 2026-02-06

### Fixed
- check_package handler now calls isHallucinated() directly instead of short-circuiting on empty Set
- scan_packages handler now maps packages through isHallucinated() instead of short-circuiting
- Command injection vulnerability in runAnalyzer() - replaced execSync template string with execFileSync
- Added bloom_filter flag and confidence level to check_package/scan_packages responses
- Added unknown_count field to scan_packages response

### Added
- npm bloom filter (3.78M packages, 8.65MB) via generate-npm-bloom.js script
- Flutter SDK packages to dart.txt: flutter, flutter_driver, flutter_localizations, flutter_test, flutter_web_plugins

## [2.0.1] - 2026-01-15

### Initial
- MCP server with scan_security, fix_security, check_package, scan_packages, scan_agent_prompt tools
- Package hallucination detection via bloom filters (pypi, rubygems) and text lists (dart, perl, raku, crates)
- Prompt injection scanning with 13 generic.prompt rules
- 165+ security fix templates

## [1.0.0] - 2025-12-01

### Initial Release
- Core security scanning engine with Python analyzer
- YAML-based security rules (Python, JavaScript, Java, Go, Dockerfile, secrets)
- MCP server with stdio transport
