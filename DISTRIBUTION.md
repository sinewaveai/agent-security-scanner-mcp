# Distribution Guide for Agent Security Scanner

This guide explains how to package and distribute the security scanner for Claude Code users.

## Option 1: MCP Server (Recommended for Claude Code)

The MCP (Model Context Protocol) server provides native integration with Claude Code.

### For Users: Installation

1. **Install the MCP server globally:**
   ```bash
   npm install -g @anthropic/security-scanner-mcp
   ```

2. **Configure Claude Code** - Add to `~/.claude/settings.json`:
   ```json
   {
     "mcpServers": {
       "security-scanner": {
         "command": "security-scanner-mcp",
         "args": []
       }
     }
   }
   ```

3. **Restart Claude Code** and use commands like:
   - "Scan this file for security issues"
   - "Fix all security vulnerabilities in main.py"

### For Publishers: Publishing to npm

1. **Update package.json** with your npm username:
   ```bash
   cd mcp-server
   npm login
   npm publish --access public
   ```

---

## Option 2: VS Code Extension Marketplace

Publish the VS Code extension for IDE integration with lightbulb quick-fixes.

### For Users: Installation

1. Open VS Code
2. Go to Extensions (`Cmd+Shift+X`)
3. Search for "Agent Security Analyzer"
4. Click Install

### For Publishers: Publishing to Marketplace

1. **Create a publisher account:**
   - Go to https://marketplace.visualstudio.com/manage
   - Create a publisher ID

2. **Update package.json:**
   ```json
   {
     "publisher": "your-publisher-id",
     "repository": {
       "type": "git",
       "url": "https://github.com/your-username/agent-security-layer"
     }
   }
   ```

3. **Create a Personal Access Token:**
   - Go to https://dev.azure.com
   - User Settings → Personal Access Tokens
   - Create token with "Marketplace (publish)" scope

4. **Publish:**
   ```bash
   npm install -g @vscode/vsce
   vsce login your-publisher-id
   vsce publish
   ```

---

## Option 3: Combined Distribution (Best Experience)

For the best user experience, publish both:

### User Setup

1. **Install VS Code Extension** (for IDE integration):
   ```
   ext install your-publisher.agent-security-analyzer
   ```

2. **Install MCP Server** (for Claude Code integration):
   ```bash
   npm install -g @anthropic/security-scanner-mcp
   ```

3. **Configure Claude Code** (`~/.claude/settings.json`):
   ```json
   {
     "mcpServers": {
       "security-scanner": {
         "command": "security-scanner-mcp"
       }
     }
   }
   ```

### What Users Get

| Feature | VS Code Extension | MCP Server |
|---------|------------------|------------|
| Real-time scanning | ✅ | ❌ |
| Lightbulb quick fixes | ✅ | ❌ |
| Sidebar security view | ✅ | ❌ |
| Claude Code integration | ❌ | ✅ |
| "Fix security issues" command | ❌ | ✅ |
| Automated fixes via Claude | ❌ | ✅ |

---

## Option 4: GitHub Distribution

For open-source distribution without npm/marketplace:

1. **Users clone the repo:**
   ```bash
   git clone https://github.com/your-username/agent-security-layer
   cd agent-security-layer
   npm install
   ```

2. **Install VS Code extension locally:**
   ```bash
   npx @vscode/vsce package
   code --install-extension agent-security-analyzer-*.vsix
   ```

3. **Configure MCP server locally** (`~/.claude/settings.json`):
   ```json
   {
     "mcpServers": {
       "security-scanner": {
         "command": "node",
         "args": ["/path/to/agent-security-layer/mcp-server/index.js"]
       }
     }
   }
   ```

---

## Quick Start for Publishers

```bash
# 1. Package VS Code extension
npx @vscode/vsce package

# 2. Publish to VS Code Marketplace
npx @vscode/vsce publish

# 3. Publish MCP server to npm
cd mcp-server
npm publish --access public
```

## Testing the Distribution

```bash
# Test VS Code extension
code --install-extension agent-security-analyzer-0.0.1.vsix

# Test MCP server
cd mcp-server && npm install && node index.js
```
