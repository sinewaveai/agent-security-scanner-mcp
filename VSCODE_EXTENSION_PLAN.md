# VS Code Extension Release Plan

## Goal
Release all features from `mcp-server-full/` as a comprehensive VS Code extension.

---

## Feature Gap Analysis

### Currently Implemented in VS Code Extension
| Feature | Status | File |
|---------|--------|------|
| Security vulnerability scanning | Partial | `extension.ts`, `analyzer.py` |
| Diagnostics display (squiggles) | Complete | `extension.ts` |
| Security Explorer sidebar | Complete | `securityProvider.ts` |
| Auto-fix suggestions (CodeActions) | Complete | `securityFixProvider.ts` |
| Fix templates | Complete | `fixTemplates.ts` |

### Missing Features (from mcp-server-full)
| Feature | MCP Tool | Priority |
|---------|----------|----------|
| Package hallucination detection | `check_package`, `scan_packages` | HIGH |
| Agent prompt security scanning | `scan_agent_prompt` | HIGH |
| Bloom filter package lookup | N/A (infrastructure) | HIGH |
| 357 security rules (12 YAML files) | `scan_security` | MEDIUM |
| Package statistics view | `list_package_stats` | LOW |

---

## Implementation Plan

### Phase 1: Core Infrastructure (Week 1)

#### 1.1 Update Package Dependencies
```json
// package.json additions
{
  "dependencies": {
    "js-yaml": "^4.1.0",
    "bloom-filters": "^3.0.0"
  }
}
```

#### 1.2 Bundle Package Data
Create `packages/` directory in extension with:
- `npm-bloom.json` (7.9 MB) - Optional, for "full" version
- `pypi-bloom.json` (1.3 MB)
- `rubygems-bloom.json` (0.4 MB)
- `crates.txt`, `dart.txt`, `perl.txt`, `raku.txt`

#### 1.3 Create Package Loader Module
New file: `src/packageLoader.ts`
```typescript
// Responsibilities:
// - Load Bloom filters for npm/pypi/rubygems
// - Load text files for smaller ecosystems
// - Provide O(1) lookup for package existence
// - Export: checkPackage(name, ecosystem) => boolean
```

---

### Phase 2: Package Hallucination Detection (Week 2)

#### 2.1 Create Hallucination Provider
New file: `src/hallucinationProvider.ts`
```typescript
// Features:
// - Scan imports in JS/TS/Python/Ruby/Rust files
// - Extract package names from import statements
// - Check against Bloom filters / package lists
// - Return list of potentially hallucinated packages
```

#### 2.2 Add Hallucination Diagnostics
Update `extension.ts`:
```typescript
// - Add new diagnostic collection for hallucinations
// - Show warning squiggles on suspicious imports
// - Add "Check Package" command
// - Add "Scan File for Hallucinations" command
```

#### 2.3 Update Sidebar
Update `securityProvider.ts`:
```typescript
// - Add "Hallucinated Packages" section
// - Show file -> package hierarchy
// - Add click-to-search action (open npmjs.com, pypi.org, etc.)
```

#### 2.4 Add Commands
```json
// package.json commands
{
  "command": "agentSecurity.checkPackage",
  "title": "Security: Check Package Legitimacy"
},
{
  "command": "agentSecurity.scanPackages",
  "title": "Security: Scan File for Hallucinated Packages"
},
{
  "command": "agentSecurity.showPackageStats",
  "title": "Security: Show Package Database Stats"
}
```

---

### Phase 3: Agent Prompt Security (Week 3)

#### 3.1 Create Prompt Scanner Module
New file: `src/promptScanner.ts`
```typescript
// Responsibilities:
// - Load agent-attacks.security.yaml rules
// - Load prompt-injection.security.yaml rules
// - Scan text/markdown/prompt files
// - Calculate risk score (0-100)
// - Return action: BLOCK / WARN / LOG / ALLOW
```

#### 3.2 Add Prompt Security Provider
New file: `src/promptSecurityProvider.ts`
```typescript
// Features:
// - Scan .txt, .md, .prompt, .jinja files
// - Show risk level in sidebar
// - Provide CodeActions for detected injections
// - Support inline suppression comments
```

#### 3.3 Add Status Bar Integration
```typescript
// Show prompt risk level in status bar when editing:
// - .prompt files
// - .jinja / .jinja2 files
// - Files containing LLM API calls
```

#### 3.4 Add Commands
```json
{
  "command": "agentSecurity.scanPrompt",
  "title": "Security: Scan Text for Prompt Injection"
},
{
  "command": "agentSecurity.analyzeRisk",
  "title": "Security: Analyze Prompt Risk Level"
}
```

---

### Phase 4: Enhanced Security Scanning (Week 4)

#### 4.1 Add Missing Rule Files
Ensure all 12 YAML rule files are bundled:
- `agent-attacks.security.yaml` (35.8 KB)
- `prompt-injection.security.yaml` (28.9 KB)
- `terraform.security.yaml` (19.5 KB)
- `c.security.yaml` (16.6 KB)
- `php.security.yaml` (18.0 KB)
- `ruby.security.yaml` (15.0 KB)
- Plus existing 6 files

#### 4.2 Add Language Support
Update `activationEvents` in `package.json`:
```json
"activationEvents": [
  "onLanguage:terraform",
  "onLanguage:hcl",
  "onLanguage:dockerfile",
  "onLanguage:yaml",
  "onLanguage:c",
  "onLanguage:cpp",
  "onLanguage:markdown",
  "onLanguage:plaintext"
]
```

#### 4.3 Add Configuration Options
```json
"agentSecurity.enableHallucinationDetection": {
  "type": "boolean",
  "default": true,
  "description": "Enable package hallucination detection"
},
"agentSecurity.enablePromptScanning": {
  "type": "boolean",
  "default": true,
  "description": "Enable prompt injection scanning"
},
"agentSecurity.promptSensitivity": {
  "type": "string",
  "enum": ["high", "medium", "low"],
  "default": "medium",
  "description": "Sensitivity level for prompt injection detection"
}
```

---

### Phase 5: UI/UX Enhancements (Week 5)

#### 5.1 Enhanced Sidebar
```
Agent Security
├── Security Issues (43)
│   ├── app.js (5 issues)
│   │   ├── [ERROR] SQL Injection (line 23)
│   │   └── [WARN] XSS via innerHTML (line 45)
│   └── auth.py (3 issues)
├── Hallucinated Packages (2)
│   ├── index.js
│   │   └── [WARN] "ai-helper-utils" not found in npm
│   └── main.py
│       └── [WARN] "fastapi-extensions" not found in PyPI
└── Prompt Security
    ├── system-prompt.txt [RISK: HIGH]
    └── user-template.jinja [RISK: LOW]
```

#### 5.2 Webview Dashboard
New file: `src/dashboardPanel.ts`
- Summary statistics
- Risk distribution chart
- Quick actions panel
- Historical trend (if data saved)

#### 5.3 Quick Fix Actions
Add CodeActions for:
- "Replace with verified package alternative"
- "Add to allowlist (suppress warning)"
- "Search package on registry"
- "Report false positive"

---

### Phase 6: Testing & Quality (Week 6)

#### 6.1 Unit Tests
New files in `src/test/`:
- `packageLoader.test.ts`
- `hallucinationProvider.test.ts`
- `promptScanner.test.ts`

#### 6.2 Integration Tests
- Test with benchmark corpus
- Verify 94.9% precision maintained
- Test all 7 package ecosystems

#### 6.3 Performance Testing
- Measure startup time with Bloom filters
- Ensure <100ms scan latency
- Memory footprint analysis

---

### Phase 7: Release Preparation (Week 7)

#### 7.1 Documentation
- Update README.md with new features
- Add CHANGELOG.md
- Create GIF demos for marketplace

#### 7.2 Marketplace Assets
- Icon (128x128 PNG)
- Banner (1280x640 PNG)
- Screenshots (1366x768)

#### 7.3 Publishing
```bash
# Install vsce
npm install -g @vscode/vsce

# Package extension
vsce package

# Publish to marketplace
vsce publish
```

#### 7.4 Two Package Versions
| Package | Size | npm Support | Target Users |
|---------|------|-------------|--------------|
| `agent-security-analyzer` | ~5 MB | No | Most users |
| `agent-security-analyzer-full` | ~13 MB | Yes (3.3M packages) | Node.js developers |

---

## File Structure After Implementation

```
src/
├── extension.ts              # Main entry point (updated)
├── analyzer.py               # Python security scanner
├── securityProvider.ts       # Sidebar tree view (updated)
├── securityFixProvider.ts    # CodeAction provider (updated)
├── fixTemplates.ts           # Fix templates (existing)
├── packageLoader.ts          # NEW: Bloom filter loader
├── hallucinationProvider.ts  # NEW: Package hallucination
├── promptScanner.ts          # NEW: Prompt injection scanner
├── promptSecurityProvider.ts # NEW: Prompt security UI
├── dashboardPanel.ts         # NEW: Webview dashboard
├── rules/                    # 12 YAML rule files
├── packages/                 # Package lists & Bloom filters
└── test/
    ├── packageLoader.test.ts
    ├── hallucinationProvider.test.ts
    └── promptScanner.test.ts
```

---

## Timeline Summary

| Phase | Duration | Deliverables |
|-------|----------|--------------|
| 1. Infrastructure | Week 1 | Package loader, Bloom filters |
| 2. Hallucination | Week 2 | Import scanning, diagnostics |
| 3. Prompt Security | Week 3 | Risk scoring, prompt scanning |
| 4. Enhanced Rules | Week 4 | All 357 rules, new languages |
| 5. UI/UX | Week 5 | Dashboard, enhanced sidebar |
| 6. Testing | Week 6 | Unit/integration tests |
| 7. Release | Week 7 | Docs, packaging, publish |

**Total: 7 weeks to feature parity with mcp-server-full**

---

## Success Metrics

| Metric | Target |
|--------|--------|
| Precision | ≥94% |
| Recall | ≥90% |
| Startup time | <500ms |
| Scan latency | <100ms per file |
| Package DB coverage | 4.3M packages |
| Marketplace rating | ≥4.5 stars |
