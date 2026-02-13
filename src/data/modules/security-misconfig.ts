import type { Module } from '../../types';

export const securityMisconfig: Module = {
    id: 'security-misconfig',
    title: 'Security Misconfiguration',
    description: 'Identify and fix dangerous server configurations that expose your systems to attack.',
    difficulty: 'Intermediate',
    xpReward: 350,
    locked: false,
    lessons: [
        {
            id: 'misconfig-theory',
            title: 'The Silent Saboteur',
            type: 'theory',
            content: `
# Security Misconfiguration

Security misconfiguration is one of the most common and dangerous vulnerabilities in the OWASP Top 10. It occurs when security settings are defined, implemented, or maintained improperly—leaving your systems exposed to attack without a single line of vulnerable code.

## Mission Briefing: The Threat Landscape

Unlike vulnerabilities that require exploiting application logic, security misconfigurations are often **low-hanging fruit** for attackers. They scan for default credentials, verbose error messages, and unnecessary services—harvesting intel your own systems freely provide.

## Common Misconfiguration Vectors

### 1. Default Credentials
Factory-set usernames and passwords (admin/admin, root/password) are the first thing attackers try.

### 2. Verbose Error Messages
Stack traces and detailed error messages reveal your technology stack, file paths, and database structure.

### 3. Missing Security Headers
HTTP headers that browsers use to protect users are often not configured:
- **X-Content-Type-Options**: Prevents MIME-type sniffing attacks
- **X-Frame-Options**: Prevents clickjacking by blocking iframe embedding
- **Content-Security-Policy**: Controls what resources can be loaded
- **Strict-Transport-Security**: Forces HTTPS connections

### 4. Unnecessary Features Enabled
Debug modes, sample applications, and admin consoles left active in production.

## Case Files: Real-World Breaches

**Equifax Breach (2017)**: A vulnerable Apache Struts version was left unpatched. 147 million Americans had their personal data exposed.

**Capital One (2019)**: A misconfigured web application firewall (WAF) allowed an attacker to access S3 buckets, exposing 100 million customer accounts.
            `
        },
        {
            id: 'misconfig-quiz-1',
            title: 'Reconnaissance Assessment',
            type: 'quiz',
            content: '',
            quiz: {
                question: "During a security audit, you discover a production server returning stack traces with full file paths and database connection strings in error responses. What vulnerability category does this represent?",
                options: [
                    "SQL Injection",
                    "Broken Authentication",
                    "Security Misconfiguration (Information Disclosure)",
                    "Cross-Site Scripting"
                ],
                correctAnswer: 2,
                explanation: "Verbose error messages that expose internal system details are a classic example of security misconfiguration. This information disclosure helps attackers understand your technology stack, file structure, and potentially discover credentials—all without exploiting any code vulnerability."
            }
        },
        {
            id: 'misconfig-quiz-2',
            title: 'Header Defense Check',
            type: 'quiz',
            content: '',
            quiz: {
                question: "Which HTTP security header prevents your web page from being embedded in an iframe on a malicious site (clickjacking protection)?",
                options: [
                    "Content-Security-Policy",
                    "X-Frame-Options",
                    "X-Content-Type-Options",
                    "Strict-Transport-Security"
                ],
                correctAnswer: 1,
                explanation: "X-Frame-Options (with values like 'DENY' or 'SAMEORIGIN') prevents clickjacking attacks by controlling whether your page can be embedded in iframes."
            }
        },
        {
            id: 'misconfig-quiz-3',
            title: 'Attack Surface Analysis',
            type: 'quiz',
            content: '',
            quiz: {
                question: "You find an application with DEBUG=true in the production configuration. Which of the following is NOT a risk this creates?",
                options: [
                    "Detailed error messages may expose sensitive information",
                    "Performance may be degraded due to extra logging",
                    "Debug endpoints may allow code execution or data access",
                    "The application will automatically use weak encryption"
                ],
                correctAnswer: 3,
                explanation: "Debug mode typically causes information disclosure through verbose errors, performance impacts from extensive logging, and potentially exposes debug endpoints—but it does not automatically weaken encryption algorithms."
            }
        },
        {
            id: 'misconfig-quiz-4',
            title: 'Breach Analysis',
            type: 'quiz',
            content: '',
            quiz: {
                question: "The 2017 Equifax breach, which exposed 147 million Americans' data, was primarily caused by:",
                options: [
                    "A sophisticated zero-day exploit",
                    "An unpatched known vulnerability in Apache Struts",
                    "Social engineering of an employee",
                    "Weak password policies"
                ],
                correctAnswer: 1,
                explanation: "The Equifax breach was caused by an unpatched Apache Struts vulnerability (CVE-2017-5638). The patch had been available for two months before attackers exploited it."
            }
        },
        {
            id: 'misconfig-quiz-5',
            title: 'Defense Priority Assessment',
            type: 'quiz',
            content: '',
            quiz: {
                question: "Which approach is MOST effective for preventing security misconfigurations in a production environment?",
                options: [
                    "Relying on developers to manually check settings before deployment",
                    "Using automated security scanning in CI/CD pipelines with hardened configuration templates",
                    "Only allowing senior developers to deploy to production",
                    "Keeping all configuration files secret"
                ],
                correctAnswer: 1,
                explanation: "Automated scanning combined with hardened configuration templates provides consistent, repeatable security. Manual checks are error-prone."
            }
        },
        {
            id: 'misconfig-lab',
            title: 'Harden the Server Configuration',
            type: 'lab',
            content: 'Intelligence reports indicate this server configuration has multiple security issues: debug mode is enabled, default admin credentials are in place, and security headers are missing. Your mission: Fix all three vulnerabilities to secure the server.',
            lab: {
                initialCode: `
const serverConfig = {
  // Server settings
  port: 3000,
  environment: 'production',
  debug: true,  // VULNERABLE: Debug enabled in production

  // Admin credentials
  admin: {
    username: 'admin',
    password: 'admin'  // VULNERABLE: Default credentials
  },

  // Response headers
  headers: {
    'X-Powered-By': 'Express'
    // VULNERABLE: Missing security headers
  }
};

module.exports = serverConfig;
                `,
                solutionCode: `
const serverConfig = {
  // Server settings
  port: 3000,
  environment: 'production',
  debug: false,  // SECURE: Debug disabled in production

  // Admin credentials
  admin: {
    username: 'sysop_7x9k2',
    password: 'EXAMPLE_Str0ng_P@ss!'  // SECURE: Strong, unique credentials (example only)
  },

  // Response headers
  headers: {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
  }
};

module.exports = serverConfig;
                `,
                instructions: "Fix the configuration: 1) Set debug to false, 2) Change admin credentials to non-default values, 3) Add security headers: X-Content-Type-Options, X-Frame-Options, and remove X-Powered-By."
            }
        }
    ]
};
