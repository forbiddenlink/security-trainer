import type { Module } from "../../types";

export const supplyChainSecurity: Module = {
  id: "supply-chain-security",
  title: "Supply Chain Security",
  description:
    "Learn to identify and defend against software supply chain attacks including dependency confusion, typosquatting, and compromised packages.",
  difficulty: "Intermediate",
  xpReward: 350,
  locked: false,
  lessons: [
    {
      id: "supply-chain-intro",
      title: "The Software Supply Chain",
      type: "theory",
      content: `# The Software Supply Chain

Modern applications rely on hundreds of third-party dependencies. Each one is a potential entry point for attackers.

## The Dependency Tree

A typical web application:
\`\`\`
Your App
    ├── react (direct dependency)
    │   └── scheduler, loose-envify... (transitive)
    ├── express
    │   └── body-parser, cookie-parser, debug...
    ├── lodash
    └── 200+ other packages
        └── 1000+ transitive dependencies
\`\`\`

**You control your code. Do you control your dependencies?**

## Supply Chain Attack Vectors

### 1. Compromised Packages
- Maintainer accounts get hacked
- Malicious code added to legitimate packages
- Example: event-stream (2018) - 8M weekly downloads, crypto-stealing code

### 2. Typosquatting
- crossenv vs cross-env
- coffe-script vs coffee-script
- Attackers register similar names, wait for typos

### 3. Dependency Confusion
- Companies use private packages (@company/utils)
- Attacker publishes public package with same name
- Build systems may prefer public registry

### 4. Abandoned Packages
- Maintainer stops updating
- Vulnerabilities go unpatched
- Package gets transferred to malicious actor

## Real-World Incidents

| Year | Attack | Impact |
|------|--------|--------|
| 2018 | event-stream | Cryptocurrency theft |
| 2021 | ua-parser-js | Cryptominer in 7M+ downloads/week |
| 2022 | node-ipc | Protest-ware targeting Russia/Belarus |
| 2023 | pypi packages | AWS credential theft |

## Why This Matters

- **One compromised package** can affect thousands of apps
- **Transitive dependencies** are often overlooked
- **CI/CD pipelines** run with elevated privileges
- **Build servers** have access to secrets

Your security is only as strong as your weakest dependency.`,
    },
    {
      id: "supply-chain-typosquatting",
      title: "Typosquatting & Dependency Confusion",
      type: "theory",
      content: `# Typosquatting & Dependency Confusion

Two of the most effective supply chain attacks exploit how package managers resolve dependencies.

## Typosquatting

Attackers register packages with names similar to popular ones:

| Real Package | Typosquat |
|--------------|-----------|
| lodash | lodahs, lodashs |
| axios | axois, axioss |
| react | raect, reakt |
| express | expres, expresss |

**Attack flow:**
1. Developer types \`npm install lodashs\` (typo)
2. Malicious package installs
3. Package runs postinstall script
4. Credentials/data exfiltrated

### Detection
\`\`\`javascript
// Before installing, verify:
npm info lodash  // Check author, downloads
npm view lodash versions  // Check history
\`\`\`

## Dependency Confusion

Organizations use private packages:
\`\`\`json
{
  "dependencies": {
    "@company/auth": "1.0.0",  // Private registry
    "@company/utils": "2.1.0"  // Private registry
  }
}
\`\`\`

**Attack:**
1. Attacker discovers internal package name (@company/utils)
2. Publishes \`@company/utils\` on public npm with version 99.0.0
3. Build system sees higher version on public registry
4. Public (malicious) package installed instead

### Real Example: Alex Birsan (2021)
- Discovered internal package names via GitHub/error messages
- Published same-name packages to public npm
- Compromised Apple, Microsoft, PayPal, Tesla

## Defense Strategies

### 1. Pin Exact Versions
\`\`\`json
{
  "dependencies": {
    "lodash": "4.17.21"  // Not "^4.17.21" or "~4.17.21"
  }
}
\`\`\`

### 2. Use Lock Files
\`\`\`bash
# Always commit lock files
git add package-lock.json  # npm
git add yarn.lock          # yarn
git add pnpm-lock.yaml     # pnpm
\`\`\`

### 3. Registry Scoping
\`\`\`
// .npmrc
@company:registry=https://internal.registry.company.com
registry=https://registry.npmjs.org
\`\`\`

### 4. Namespace Reservation
Register your organization's scope on public registries even if you only use private ones.

### 5. Verify Before Install
\`\`\`bash
# Check package info
npm info <package>

# Verify publisher
npm owner ls <package>

# Check for typosquats
npx typosquatting-detector <package>
\`\`\``,
    },
    {
      id: "supply-chain-quiz-1",
      title: "Attack Identification",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "Your build suddenly fails with 'permission denied' errors. Investigation shows a new version of your internal package '@acme/logger' was installed from npmjs.org instead of your private registry. What attack occurred?",
        options: [
          "Typosquatting",
          "Dependency confusion",
          "Man-in-the-middle attack",
          "Lock file tampering",
        ],
        correctAnswer: 1,
        explanation:
          "This is dependency confusion. An attacker published a malicious package with the same name as your internal package (@acme/logger) to the public npm registry, likely with a higher version number. The build system preferred the public version. Defense: scope your private packages to your private registry in .npmrc.",
      },
    },
    {
      id: "supply-chain-sbom",
      title: "Software Bill of Materials (SBOM)",
      type: "theory",
      content: `# Software Bill of Materials (SBOM)

An SBOM is a complete inventory of all components in your software - like a nutrition label for code.

## What's in an SBOM?

\`\`\`json
{
  "bomFormat": "CycloneDX",
  "components": [
    {
      "name": "lodash",
      "version": "4.17.21",
      "purl": "pkg:npm/lodash@4.17.21",
      "licenses": [{ "id": "MIT" }],
      "hashes": [{ "alg": "SHA-256", "content": "abc123..." }]
    },
    // ... all other dependencies
  ]
}
\`\`\`

## Why SBOMs Matter

### 1. Vulnerability Response
When Log4j happened:
- Companies WITHOUT SBOM: "Do we even use Log4j? Let me check..."
- Companies WITH SBOM: "Yes, in services X, Y, Z. Patching now."

### 2. Compliance Requirements
- US Executive Order 14028 requires SBOMs for government software
- EU Cyber Resilience Act mandates SBOMs
- Many enterprises require SBOMs from vendors

### 3. License Compliance
Track which licenses are in your dependency tree:
\`\`\`
MIT: 450 packages
Apache-2.0: 120 packages
GPL-3.0: 2 packages  <-- May conflict with your license!
\`\`\`

## Generating SBOMs

### NPM/Node
\`\`\`bash
# Using CycloneDX
npx @cyclonedx/cyclonedx-npm --output-file sbom.json
\`\`\`

### Python
\`\`\`bash
cyclonedx-py --output sbom.json
\`\`\`

### Multi-language
\`\`\`bash
# Syft supports many ecosystems
syft . -o cyclonedx-json > sbom.json
\`\`\`

## Using SBOMs for Security

### Vulnerability Scanning
\`\`\`bash
# Scan SBOM against vulnerability database
grype sbom:sbom.json

# Output:
# lodash 4.17.15  CVE-2020-8203  HIGH  Prototype pollution
\`\`\`

### Continuous Monitoring
\`\`\`yaml
# CI/CD pipeline
- name: Generate SBOM
  run: syft . -o cyclonedx-json > sbom.json

- name: Scan for vulnerabilities
  run: grype sbom:sbom.json --fail-on high
\`\`\`

## SBOM Formats

| Format | Creator | Use Case |
|--------|---------|----------|
| CycloneDX | OWASP | Security-focused |
| SPDX | Linux Foundation | License compliance |
| SWID | ISO | Software identification |

**Start with CycloneDX** - it's the most security-focused and widely supported.`,
    },
    {
      id: "supply-chain-quiz-2",
      title: "SBOM Benefits",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "A critical vulnerability is announced in a widely-used library. What is the PRIMARY advantage of maintaining an SBOM?",
        options: [
          "It automatically patches the vulnerability",
          "It allows immediate identification of affected applications",
          "It prevents the vulnerability from being exploited",
          "It notifies the library maintainer",
        ],
        correctAnswer: 1,
        explanation:
          "The primary advantage of an SBOM during a vulnerability announcement is immediate identification of which applications are affected. Without an SBOM, teams must manually search codebases to determine if they use the vulnerable library. SBOMs don't patch vulnerabilities or prevent exploitation - they provide visibility for rapid response.",
      },
    },
    {
      id: "supply-chain-defenses",
      title: "Defense In Depth",
      type: "theory",
      content: `# Defense In Depth for Supply Chain

No single defense stops all supply chain attacks. Layer multiple protections.

## Layer 1: Prevention

### Pin Dependencies
\`\`\`json
{
  "dependencies": {
    "express": "4.18.2"  // Exact version
  }
}
\`\`\`

### Use Lock Files
\`\`\`bash
npm ci  # Installs exactly from lock file
# NOT: npm install (which updates lock file)
\`\`\`

### Registry Configuration
\`\`\`
# .npmrc - prevent dependency confusion
@mycompany:registry=https://npm.mycompany.com/
//npm.mycompany.com/:_authToken=\${NPM_TOKEN}
\`\`\`

## Layer 2: Detection

### Dependency Scanning in CI
\`\`\`yaml
# GitHub Actions example
- name: Audit dependencies
  run: npm audit --audit-level=high

- name: Scan with Snyk
  uses: snyk/actions/node@master
  env:
    SNYK_TOKEN: \${{ secrets.SNYK_TOKEN }}
\`\`\`

### Monitor for New Vulnerabilities
\`\`\`bash
# GitHub Dependabot
# Snyk monitoring
# npm audit in CI
\`\`\`

## Layer 3: Response

### Automated Updates
\`\`\`yaml
# dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
\`\`\`

### Incident Response Plan
1. Identify affected systems (SBOM query)
2. Assess impact and exposure
3. Patch or rollback
4. Verify fix deployment
5. Post-mortem

## Layer 4: Isolation

### Minimal Permissions
\`\`\`dockerfile
# Don't run as root
USER node

# Read-only filesystem where possible
--read-only
\`\`\`

### Network Segmentation
- Build servers shouldn't have production access
- Limit outbound network from CI/CD

### Sandboxed Builds
\`\`\`bash
# Run npm scripts in restricted environment
npm config set ignore-scripts true
\`\`\`

## Checklist

- [ ] Lock file committed and used in CI
- [ ] Exact versions pinned (no ^/~)
- [ ] Private registry scoped correctly
- [ ] Dependency scanning in CI
- [ ] SBOM generation automated
- [ ] Dependabot/Renovate enabled
- [ ] Build environment isolated
- [ ] Incident response plan documented`,
    },
    {
      id: "supply-chain-lab",
      title: "Lab: Secure Dependency Verification",
      type: "lab",
      content:
        "This build script installs dependencies without verification. Add checks to validate package integrity: verify the package exists in an allowlist, check that the version is pinned (no ^ or ~), and validate the package checksum matches expected values.",
      lab: {
        initialCode: `async function installDependency(packageName, version) {
  // VULNERABLE: No verification!
  console.log(\`Installing \${packageName}@\${version}...\`);
  await exec(\`npm install \${packageName}@\${version}\`);
  return { success: true };
}

// Usage
await installDependency('lodash', '^4.17.0');  // Vulnerable: Uses caret
await installDependency('my-package', '1.0.0');  // Unknown package`,
        solutionCode: `// Allowlist of approved packages with their checksums
const APPROVED_PACKAGES = {
  'lodash': {
    '4.17.21': 'sha512-abc123expectedhash'
  },
  'express': {
    '4.18.2': 'sha512-def456expectedhash'
  }
};

function isVersionPinned(version) {
  // Reject ^ and ~ prefixes
  return !version.startsWith('^') && !version.startsWith('~');
}

function isPackageApproved(packageName, version) {
  const pkg = APPROVED_PACKAGES[packageName];
  return pkg && pkg[version] !== undefined;
}

async function verifyChecksum(packageName, version) {
  const expected = APPROVED_PACKAGES[packageName][version];
  const actual = await getPackageChecksum(packageName, version);
  return actual === expected;
}

async function installDependency(packageName, version) {
  // Check if version is properly pinned
  if (!isVersionPinned(version)) {
    throw new Error('Version must be pinned (no ^ or ~)');
  }

  // Check if package is in allowlist
  if (!isPackageApproved(packageName, version)) {
    throw new Error('Package not in approved list');
  }

  // Verify checksum before installing
  const checksumValid = await verifyChecksum(packageName, version);
  if (!checksumValid) {
    throw new Error('Checksum verification failed');
  }

  console.log(\`Installing \${packageName}@\${version}...\`);
  await exec(\`npm install \${packageName}@\${version}\`);
  return { success: true };
}`,
        instructions:
          "1. Create an APPROVED_PACKAGES object as an allowlist with package names and versions. 2. Add isVersionPinned() that rejects versions starting with ^ or ~. 3. Add isPackageApproved() to check the allowlist. 4. Throw errors with 'Version must be pinned', 'Package not in approved list', or 'Checksum verification failed'.",
      },
    },
  ],
};
