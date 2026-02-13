import type { Module } from '../../types';

export const sensitiveDataExposure: Module = {
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

Sensitive Data Exposure occurs when applications fail to adequately protect sensitive information such as financial data, healthcare records, credentials, and personally identifiable information (PII).

## The Threat Landscape

### 1. Unencrypted Storage
Storing sensitive data in plaintext is like leaving classified documents on a park bench.

### 2. Weak Password Hashing
Using outdated algorithms (MD5, SHA-1) or hashing without salt is nearly as bad as plaintext.

### 3. Exposed API Keys and Secrets
Hardcoded secrets in source code or configuration files committed to version control.

### 4. Logging Sensitive Data
Debug logs that capture passwords, credit cards, or personal information.

### 5. Missing TLS/Encryption in Transit
Transmitting sensitive data over unencrypted connections.

## Case Files

**Marriott (2018):** 500 million guest records exposed, including unencrypted passport numbers.

**Adobe (2013):** 153 million passwords exposed. They used 3DES encryption with a single key, so identical passwords produced identical ciphertexts, enabling frequency analysis.

**GitHub Secret Scanning:** Detects millions of credentials exposed in git repositories per year.

## Defense Strategies

### 1. Hash Passwords with bcrypt or Argon2

\`\`\`javascript
const hashedPassword = await bcrypt.hash(password, 12);
\`\`\`

### 2. Encrypt PII at Rest

Use AES-256-GCM for data like SSNs:

\`\`\`javascript
const encryptedSSN = encrypt(ssn, process.env.ENCRYPTION_KEY);
\`\`\`

### 3. Use Environment Variables for Secrets

\`\`\`javascript
const apiKey = process.env.API_KEY;
\`\`\`

### 4. Sanitize All Logs

Replace sensitive data with '[REDACTED]' before logging:

\`\`\`javascript
console.log("User login", { email, password: '[REDACTED]' });
\`\`\`

### 5. Enforce HTTPS Everywhere
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
                explanation: "bcrypt is specifically designed for password hashing. It automatically handles salting, and the work factor makes brute-force attacks computationally expensive."
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
                explanation: "Marriott stored passport numbers in plaintext without any encryption. This is a textbook case of sensitive data exposure through lack of encryption at rest."
            }
        },
        {
            id: 'data-exposure-quiz-3',
            title: 'Breach Analysis: Adobe',
            type: 'quiz',
            content: '',
            quiz: {
                question: "Adobe's 2013 breach exposed 153 million passwords. What was the fundamental flaw in their password storage?",
                options: [
                    "They stored passwords in plaintext",
                    "They used encryption (not hashing) with a single key, so identical passwords produced identical ciphertexts",
                    "They used MD5 without salt",
                    "They stored passwords in a spreadsheet"
                ],
                correctAnswer: 1,
                explanation: "Adobe used 3DES encryption in ECB mode with a single key for ALL users. Identical passwords produced identical ciphertexts, enabling frequency analysis."
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
                explanation: "The FIRST priority is to rotate (revoke) the exposed credentials immediately. Automated scanners can exploit exposed secrets within minutes."
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
                explanation: "Logging the password creates a severe security risk. Passwords in logs can be exposed through log aggregation services, error reporting tools, or team members with log access."
            }
        },
        {
            id: 'data-exposure-lab',
            title: 'Secure the User Data Handler',
            type: 'lab',
            content: 'The code below has multiple sensitive data exposure vulnerabilities. Your mission: Fix all vulnerabilities by implementing proper password hashing, log sanitization, and PII encryption.',
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
                instructions: "Fix the vulnerabilities: 1) Sanitize the log by replacing password and ssn with '[REDACTED]', 2) Hash password using bcrypt.hash(password, 12), 3) Encrypt SSN using encrypt(ssn, process.env.ENCRYPTION_KEY)."
            }
        }
    ]
};
