# VS Code Extension - Setup Guide

## Extension Structure Created

Your VS Code security analyzer extension skeleton is ready! Here's what was created:

### 📁 Project Structure
```
agent-security-layer/
├── src/
│   ├── extension.ts       # Main extension entry point
│   └── analyzer.ts        # Security analysis engine
├── .vscode/
│   └── launch.json        # Debug configuration
├── package.json           # Extension manifest
├── tsconfig.json          # TypeScript configuration
├── README.md             # Documentation
└── .vscodeignore         # Package exclusions
```

### 🔍 Features Implemented

**Security Rules**:
- ✅ SQL Injection detection
- ✅ Cross-Site Scripting (XSS) detection
- ✅ Path Traversal detection
- ✅ Command Injection detection
- ✅ Hardcoded Secrets detection

**Commands**:
- `Security: Scan Current File`
- `Security: Scan Entire Workspace`
- `Security: Clear All Warnings`

## 🚀 Next Steps

### 1. Install Node.js

You need Node.js to develop VS Code extensions. Download and install from:
- **Official site**: https://nodejs.org/ (recommended: LTS version)

After installation, verify with:
```bash
node --version
npm --version
```

### 2. Install Dependencies

Once Node.js is installed, run:
```bash
cd c:\Users\HK-Sinewave\Documents\GitHub\agent-security-layer
npm install
```

### 3. Compile TypeScript

Compile the extension:
```bash
npm run compile
```

Or run in watch mode (auto-compiles on changes):
```bash
npm run watch
```

### 4. Test the Extension

**Option A: Using F5 (Recommended)**
1. Open this folder in VS Code
2. Press `F5` to launch Extension Development Host
3. The extension will be active in the new window

**Option B: Manual Testing**
1. Compile with `npm run compile`
2. Open Command Palette (`Ctrl+Shift+P`)
3. Run `Developer: Reload Window`
4. Use `Security: Scan Current File` command

### 5. Try It Out

Create a test file with vulnerable code:

**test.js**:
```javascript
// This should trigger SQL injection warning
const query = "SELECT * FROM users WHERE id = " + userId;

// This should trigger XSS warning
element.innerHTML = userInput;

// This should trigger hardcoded secret warning
const apiKey = "stripe_test_FAKE_KEY_EXAMPLE";
```

Then run `Security: Scan Current File` - you should see warnings underlined in the editor!

## 📝 Configuration

Add to your VS Code settings:
```json
{
  "agentSecurity.enabledRules": [
    "sql-injection",
    "xss",
    "path-traversal",
    "command-injection",
    "hardcoded-secrets"
  ],
  "agentSecurity.severity": "warning",
  "agentSecurity.autoScan": true
}
```

## ❓ Questions?

Let me know if you need help with:
- Adding more security rules
- Improving detection patterns
- Adding code fixes/suggestions
- Supporting more languages
- Publishing the extension

The extension is ready to go once you install Node.js!
