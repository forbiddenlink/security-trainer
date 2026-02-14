import type { Module } from "../../types";

export const vulnerableComponentsModule: Module = {
  id: "vulnerable-components",
  title: "Vulnerable & Outdated Components",
  description:
    "Learn to identify and remediate vulnerable dependencies in your software supply chain.",
  difficulty: "Intermediate",
  xpReward: 350,
  locked: false,
  lessons: [
    {
      id: "vuln-comp-theory",
      title: "Understanding Supply Chain Security",
      type: "theory",
      content: `# Vulnerable and Outdated Components (OWASP A06)

## The Hidden Danger in Your Dependencies

Modern applications rely on hundreds of third-party dependencies. A single vulnerable package can compromise your entire application.

## Real-World Impact

### The Equifax Breach (2017)
- **Vulnerability**: Apache Struts CVE-2017-5638
- **Impact**: 147 million records exposed
- **Cost**: $700+ million in settlements
- **Root Cause**: Unpatched dependency with known vulnerability

### Log4Shell (2021)
- **Vulnerability**: Log4j CVE-2021-44228 (CVSS 10.0)
- **Impact**: Millions of applications worldwide
- **Exploit**: Remote code execution via JNDI lookup
- **Lesson**: Even logging libraries can be attack vectors

### event-stream Incident (2018)
- **Attack Type**: Supply chain compromise
- **Method**: Malicious maintainer injected cryptocurrency-stealing code
- **Lesson**: Trust but verify - even popular packages can be compromised

## Types of Component Vulnerabilities

### 1. Known Vulnerabilities (CVEs)
\`\`\`
❌ Vulnerable: lodash@4.17.15 (Prototype Pollution)
✅ Fixed: lodash@4.17.21
\`\`\`

### 2. Outdated Dependencies
- Missing security patches
- Unsupported versions
- End-of-life software

### 3. Supply Chain Attacks
- Typosquatting (e.g., \`crossenv\` vs \`cross-env\`)
- Account takeover of maintainers
- Malicious code injection

### 4. Transitive Dependencies
Your direct dependencies have their own dependencies:
\`\`\`
your-app
  └── express@4.18.0
       └── body-parser@1.20.0
            └── qs@6.10.3 ← Vulnerable!
\`\`\`

## Defense Strategies

### 1. Dependency Scanning
\`\`\`bash
# npm built-in audit
npm audit

# Fix automatically where possible
npm audit fix

# Generate detailed report
npm audit --json
\`\`\`

### 2. Software Composition Analysis (SCA) Tools
- **Snyk** - Real-time vulnerability detection
- **Dependabot** - Automated dependency updates
- **OWASP Dependency-Check** - Open source scanner
- **Socket.dev** - Supply chain attack detection

### 3. Version Pinning vs Ranges
\`\`\`json
// ❌ Risky: Allows any minor/patch update
"lodash": "^4.17.0"

// ✅ Safer: Exact version pinning
"lodash": "4.17.21"

// ⚠️ Balance: Lock file provides reproducibility
// Use package-lock.json or yarn.lock
\`\`\`

### 4. Software Bill of Materials (SBOM)
A complete inventory of all components in your software:
- Required by US Executive Order 14028
- Enables rapid response to new vulnerabilities
- Formats: SPDX, CycloneDX

## Best Practices

1. **Regular Updates**: Schedule dependency updates weekly/monthly
2. **Automated Scanning**: Integrate into CI/CD pipeline
3. **Monitor Advisories**: Subscribe to security mailing lists
4. **Minimize Dependencies**: Evaluate if you really need that package
5. **Review Before Adding**: Check package health, maintainers, downloads
6. **Use Lock Files**: Ensure reproducible builds
7. **Private Registry**: Consider vendoring critical dependencies`,
    },
    {
      id: "vuln-comp-quiz-1",
      title: "Quiz: Identifying Vulnerabilities",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "Which command shows known vulnerabilities in your npm dependencies?",
        options: ["npm audit", "npm check", "npm scan", "npm vulnerabilities"],
        correctAnswer: 0,
        explanation:
          "`npm audit` analyzes your dependency tree and reports known vulnerabilities with severity levels and remediation advice.",
      },
    },
    {
      id: "vuln-comp-quiz-2",
      title: "Quiz: Supply Chain Attacks",
      type: "quiz",
      content: "",
      quiz: {
        question: 'What is "typosquatting" in the context of npm packages?',
        options: [
          "A bug in package naming conventions",
          "Publishing malicious packages with names similar to popular ones",
          "A technique for faster package downloads",
          "An automated testing approach",
        ],
        correctAnswer: 1,
        explanation:
          'Typosquatting is when attackers publish packages with names that are slight misspellings of popular packages (e.g., "crossenv" instead of "cross-env"), hoping developers will accidentally install the malicious version.',
      },
    },
    {
      id: "vuln-comp-quiz-3",
      title: "Quiz: Transitive Dependencies",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "Why are transitive (indirect) dependencies a security concern?",
        options: [
          "They make builds slower",
          "They increase storage costs",
          "They can introduce vulnerabilities you are not directly aware of",
          "They require more RAM",
        ],
        correctAnswer: 2,
        explanation:
          "Transitive dependencies are packages that your direct dependencies rely on. A vulnerability in a deeply nested dependency can still compromise your application, even if you never explicitly installed that package.",
      },
    },
    {
      id: "vuln-comp-quiz-4",
      title: "Quiz: Version Pinning",
      type: "quiz",
      content: "",
      quiz: {
        question:
          'What is the main benefit of using exact version pinning (e.g., "lodash": "4.17.21") combined with a lock file?',
        options: [
          "Faster installation times",
          "Smaller bundle sizes",
          "Reproducible builds and protection from unexpected changes",
          "Better IDE integration",
        ],
        correctAnswer: 2,
        explanation:
          "Exact version pinning with lock files ensures that every build uses the exact same dependency versions, preventing surprise breaking changes or the introduction of vulnerabilities through automatic updates.",
      },
    },
    {
      id: "vuln-comp-lab",
      title: "Lab: Fix Vulnerable Dependencies",
      type: "lab",
      content: "",
      lab: {
        instructions:
          "Review the package.json below and identify the vulnerable packages. Update them to secure versions. The vulnerable packages are: lodash (needs 4.17.21+), axios (needs 0.21.2+), and minimist (needs 1.2.6+).",
        initialCode: `{
  "name": "vulnerable-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.15",
    "axios": "0.21.0",
    "minimist": "1.2.0",
    "helmet": "6.0.0"
  }
}`,
        solutionCode: `{
  "name": "vulnerable-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.21",
    "axios": "0.21.2",
    "minimist": "1.2.6",
    "helmet": "6.0.0"
  }
}`,
      },
    },
  ],
};
