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
    }
];
