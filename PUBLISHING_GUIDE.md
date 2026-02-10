# VS Code Extension Publishing & Monetization Guide

## Overview

This guide covers how to package, publish, and monetize the Agent Security Analyzer extension.

---

## Part 1: Prepare for Publishing

### 1.1 Update Publisher Information

Edit `package.json`:
```json
{
  "name": "agent-security-analyzer",
  "displayName": "Agent Security Analyzer",
  "publisher": "your-company-name",
  "version": "1.0.0",
  "description": "Comprehensive security analyzer: vulnerability scanning, package hallucination detection, and prompt injection protection",
  "license": "SEE LICENSE IN LICENSE.md",
  "homepage": "https://your-product-website.com",
  "bugs": {
    "url": "https://github.com/your-org/agent-security-analyzer/issues"
  },
  "repository": {
    "type": "git",
    "url": "https://github.com/your-org/agent-security-analyzer"
  }
}
```

### 1.2 Create Required Assets

```bash
mkdir -p images
```

**Required files:**
| File | Size | Purpose |
|------|------|---------|
| `images/icon.png` | 128x128 | Extension icon |
| `images/banner.png` | 1280x640 | Marketplace banner |
| `LICENSE.md` | - | License terms |
| `CHANGELOG.md` | - | Version history |
| `README.md` | - | Marketplace description |

### 1.3 Create Marketplace README

Your `README.md` becomes your sales page. Include:
- Hero image/GIF showing the extension in action
- Feature list with screenshots
- Installation instructions
- Pricing information (if applicable)
- Support/contact information

### 1.4 Add .vscodeignore

Create `.vscodeignore` to reduce package size:
```
.vscode/**
.git/**
.github/**
src/**
benchmarks/**
mcp-server/**
mcp-server-full/**
node_modules/**
!node_modules/js-yaml/**
*.ts
*.map
.gitignore
tsconfig.json
*.md
!README.md
!CHANGELOG.md
!LICENSE.md
```

---

## Part 2: Monetization Options

### Option A: VS Code Marketplace (Free with Paid Tiers)

**How it works:**
- Publish free version to marketplace
- Gate premium features behind license key
- Sell licenses through your website

**Pros:**
- Maximum visibility (millions of VS Code users)
- Easy installation for users
- Automatic updates

**Cons:**
- Microsoft doesn't handle payments
- You manage licensing infrastructure
- Can't charge directly through marketplace

### Option B: Private Distribution (Direct Sales)

**How it works:**
- Package as `.vsix` file
- Sell through your website (Gumroad, Paddle, Stripe)
- Users install manually

**Pros:**
- Keep 100% revenue (minus payment processor)
- Full control over pricing
- No marketplace restrictions

**Cons:**
- Less discoverability
- Manual update process for users
- Users must trust sideloading

### Option C: Freemium Model (Recommended)

**How it works:**
- Free tier: Basic security scanning (limited rules)
- Pro tier ($9-19/month): Full 357 rules + hallucination detection
- Enterprise tier ($49-99/month): Prompt security + team features

**Implementation:**
```typescript
// src/licensing.ts
interface License {
  tier: 'free' | 'pro' | 'enterprise';
  email: string;
  expiresAt: Date;
  signature: string;
}

function validateLicense(key: string): License | null {
  // Verify signature with your server
  // Return license details or null
}

function isFeatureEnabled(feature: string, license: License | null): boolean {
  const freeFeatures = ['basic-security-scan'];
  const proFeatures = ['hallucination-detection', 'full-rules'];
  const enterpriseFeatures = ['prompt-security', 'team-dashboard'];

  if (!license) return freeFeatures.includes(feature);
  if (license.tier === 'pro') return [...freeFeatures, ...proFeatures].includes(feature);
  if (license.tier === 'enterprise') return true;
  return false;
}
```

---

## Part 3: Licensing Infrastructure

### 3.1 License Key System

**Option A: Simple signed keys (offline validation)**
```javascript
// Generate license key (server-side)
const crypto = require('crypto');

function generateLicense(email, tier, expiresAt) {
  const payload = JSON.stringify({ email, tier, expiresAt });
  const signature = crypto
    .createHmac('sha256', process.env.LICENSE_SECRET)
    .update(payload)
    .digest('hex');

  return Buffer.from(JSON.stringify({ payload, signature })).toString('base64');
}
```

**Option B: Online validation (more secure)**
- User enters license key
- Extension calls your API to validate
- Cache result locally for offline use

### 3.2 Payment Processing

**Recommended platforms:**

| Platform | Fees | Best For |
|----------|------|----------|
| **Gumroad** | 10% + $0.50 | Simple setup, handles taxes |
| **Paddle** | 5% + $0.50 | SaaS, handles VAT globally |
| **Stripe** | 2.9% + $0.30 | Full control, more setup |
| **LemonSqueezy** | 5% + $0.50 | Modern alternative to Gumroad |

### 3.3 License Delivery Flow

```
1. User purchases on your website (Gumroad/Paddle/Stripe)
2. Webhook triggers → Generate license key
3. Email license key to user
4. User enters key in VS Code extension settings
5. Extension validates and unlocks features
```

---

## Part 4: Publishing to VS Code Marketplace

### 4.1 Create Publisher Account

```bash
# 1. Go to https://marketplace.visualstudio.com/manage
# 2. Sign in with Microsoft account
# 3. Create a publisher (e.g., "your-company-name")
```

### 4.2 Get Personal Access Token

1. Go to https://dev.azure.com
2. User Settings → Personal Access Tokens
3. Create token with **Marketplace (Publish)** scope
4. Save the token securely

### 4.3 Install vsce CLI

```bash
npm install -g @vscode/vsce
```

### 4.4 Package the Extension

```bash
# Package to .vsix file
vsce package

# This creates: agent-security-analyzer-1.0.0.vsix
```

### 4.5 Publish to Marketplace

```bash
# Login with your PAT
vsce login your-company-name

# Publish
vsce publish

# Or publish specific version
vsce publish 1.0.0
```

### 4.6 Verify Publication

- Visit: https://marketplace.visualstudio.com/items?itemName=your-company-name.agent-security-analyzer
- Takes 5-10 minutes to appear

---

## Part 5: Pricing Strategy

### Competitive Analysis

| Competitor | Pricing | Features |
|------------|---------|----------|
| Snyk | Free / $25/dev/mo | Vulnerability scanning |
| SonarLint | Free / $15/dev/mo | Code quality + security |
| Checkmarx | Enterprise only | Full SAST |
| GitHub Copilot | $10/mo | AI coding (not security) |

### Recommended Pricing

| Tier | Price | Features |
|------|-------|----------|
| **Free** | $0 | 50 basic rules, 5 scans/day |
| **Pro** | $12/mo or $99/yr | All 357 rules, hallucination detection, unlimited scans |
| **Team** | $29/user/mo | Pro + prompt security, team dashboard, priority support |
| **Enterprise** | Custom | Self-hosted, SSO, audit logs, SLA |

### Pricing Psychology Tips

1. **Anchor high**: Show Enterprise first, then Pro seems affordable
2. **Annual discount**: 2 months free encourages commitment
3. **Free trial**: 14-day Pro trial converts well
4. **Money-back guarantee**: Reduces purchase friction

---

## Part 6: Marketing & Sales

### 6.1 Product Website

Create a landing page with:
- Hero section with value proposition
- Feature breakdown with screenshots
- Pricing table
- Testimonials/social proof
- FAQ section
- CTA buttons

**Tools:** Framer, Webflow, Next.js, or simple HTML

### 6.2 Content Marketing

- **Blog posts**: "Top 10 VS Code Security Issues", "How AI Hallucinates Package Names"
- **YouTube demos**: 5-min feature walkthroughs
- **Twitter/LinkedIn**: Share security tips, product updates
- **Dev.to/Hashnode**: Technical deep-dives

### 6.3 Distribution Channels

| Channel | Strategy |
|---------|----------|
| VS Code Marketplace | Optimize description, screenshots, keywords |
| Product Hunt | Launch with compelling story |
| Hacker News | Show HN post with technical angle |
| Reddit (r/vscode, r/programming) | Helpful comments, not spam |
| GitHub | Open-source core, premium features |

### 6.4 Sales Tactics

**For Individual Developers:**
- Free tier gets them hooked
- In-app prompts for Pro features
- Email drip campaign after signup

**For Teams/Enterprise:**
- LinkedIn outreach to security leads
- Case studies with metrics
- Free pilot programs
- Partner with security consultancies

---

## Part 7: Legal & Business

### 7.1 Business Structure

Options:
- **Sole Proprietorship**: Simple, you're personally liable
- **LLC**: Liability protection, pass-through taxation
- **Inc/Corp**: Best for raising investment, more complex

### 7.2 Terms of Service

Include:
- License grant (what users can/can't do)
- Payment terms and refund policy
- Limitation of liability
- Termination conditions

**Template sources:** Termly.io, GetTerms.io, or hire a lawyer

### 7.3 Privacy Policy

Required if you collect:
- Email addresses
- Usage analytics
- License validation data

### 7.4 Taxes

- **US**: Sales tax varies by state (use Paddle/Gumroad to handle)
- **EU**: VAT required (Paddle handles this)
- **Income tax**: Consult an accountant

---

## Part 8: Quick Start Checklist

### Before Publishing
- [ ] Update `package.json` with publisher info
- [ ] Create 128x128 icon
- [ ] Write compelling README.md
- [ ] Add CHANGELOG.md
- [ ] Create LICENSE.md
- [ ] Add `.vscodeignore`
- [ ] Test extension thoroughly

### Publishing
- [ ] Create Microsoft/Azure account
- [ ] Create publisher on marketplace
- [ ] Generate Personal Access Token
- [ ] Run `vsce package`
- [ ] Run `vsce publish`

### Monetization
- [ ] Choose pricing model
- [ ] Set up payment processor (Gumroad/Paddle/Stripe)
- [ ] Implement license validation
- [ ] Create product website
- [ ] Set up email for license delivery

### Launch
- [ ] Submit to Product Hunt
- [ ] Post on social media
- [ ] Email your network
- [ ] Monitor reviews and respond

---

## Commands Reference

```bash
# Install vsce
npm install -g @vscode/vsce

# Package extension
vsce package

# Publish to marketplace
vsce login your-publisher-name
vsce publish

# Publish with version bump
vsce publish minor  # 1.0.0 → 1.1.0
vsce publish patch  # 1.0.0 → 1.0.1

# Unpublish (careful!)
vsce unpublish your-publisher-name.agent-security-analyzer
```

---

## Revenue Projections

Conservative estimate for a well-marketed security extension:

| Metric | Month 1 | Month 6 | Month 12 |
|--------|---------|---------|----------|
| Free users | 500 | 5,000 | 15,000 |
| Pro subscribers | 10 | 100 | 300 |
| MRR @ $12/mo | $120 | $1,200 | $3,600 |
| ARR | - | $14,400 | $43,200 |

**Growth levers:**
- SEO for security-related searches
- Integration with popular frameworks
- Partnerships with bootcamps/courses
- Enterprise sales motion

---

## Support

For questions about this extension:
- GitHub Issues: [your-repo]/issues
- Email: support@your-domain.com
- Twitter: @your-handle
