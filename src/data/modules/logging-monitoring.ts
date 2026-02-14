import type { Module } from "../../types";

export const loggingMonitoringModule: Module = {
  id: "logging-monitoring",
  title: "Security Logging & Monitoring",
  description:
    "Learn to implement effective security logging and detect attacks before they cause damage.",
  difficulty: "Intermediate",
  xpReward: 350,
  locked: false,
  lessons: [
    {
      id: "logging-theory",
      title: "Security Logging Fundamentals",
      type: "theory",
      content: `# Security Logging and Monitoring Failures (OWASP A09)

## The Blind Spot in Security

Without proper logging and monitoring, attackers can:
- Operate undetected for months
- Exfiltrate data without triggering alerts
- Cover their tracks completely

## Real-World Failures

### Target Breach (2013)
- **Attack Duration**: Attackers had access for 19 days
- **Data Stolen**: 40 million credit cards
- **The Failure**: Security alerts were generated but ignored
- **Lesson**: Logging without monitoring is useless

### Yahoo Breach (2013-2014)
- **Discovery Delay**: Breaches discovered 2-3 years later
- **Impact**: 3 billion accounts compromised
- **The Failure**: Insufficient logging and detection capabilities

## What to Log

### Security-Critical Events

\`\`\`typescript
// ✅ MUST LOG these events:

// 1. Authentication Events
logger.info('auth.login.success', { userId, ip, userAgent });
logger.warn('auth.login.failure', { email, ip, reason: 'invalid_password' });
logger.info('auth.logout', { userId, sessionDuration });
logger.warn('auth.mfa.failure', { userId, ip });

// 2. Authorization Failures
logger.warn('authz.denied', {
  userId,
  resource: '/admin/users',
  action: 'DELETE',
  reason: 'insufficient_permissions'
});

// 3. Input Validation Failures
logger.warn('validation.suspicious', {
  field: 'username',
  value: '<script>alert(1)</script>', // Sanitized!
  ip,
  pattern: 'xss_attempt'
});

// 4. Business Logic Anomalies
logger.warn('business.anomaly', {
  userId,
  action: 'transfer',
  amount: 999999,
  reason: 'exceeds_daily_limit'
});
\`\`\`

## What NOT to Log

\`\`\`typescript
// ❌ NEVER LOG these:

// Passwords (even hashed ones in most cases)
logger.info('Login', { password: req.body.password }); // WRONG!

// Session tokens / API keys
logger.info('Request', { token: req.headers.authorization }); // WRONG!

// Credit card numbers
logger.info('Payment', { card: '4111111111111111' }); // WRONG!

// Personal health information
logger.info('User', { diagnosis: 'diabetes' }); // WRONG!

// Full SSN / Government IDs
logger.info('User', { ssn: '123-45-6789' }); // WRONG!

// ✅ Instead, log references or masked values:
logger.info('Payment', { cardLast4: '1111', transactionId: 'txn_abc123' });
\`\`\`

## Log Injection Prevention

Attackers can manipulate logs to hide evidence or inject false entries:

\`\`\`typescript
// ❌ Vulnerable to log injection
const username = req.body.username;
// If username = "admin\\n[INFO] Successful login for admin"
logger.info(\`Login attempt for \${username}\`);

// ✅ Safe: Use structured logging
logger.info('login.attempt', {
  username: sanitizeForLog(username),
  ip: req.ip
});

function sanitizeForLog(input: string): string {
  // Remove newlines, tabs, and control characters
  return input.replace(/[\\r\\n\\t]/g, '').slice(0, 100);
}
\`\`\`

## Structured Logging Best Practices

\`\`\`typescript
// ✅ Good structured log format
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "level": "warn",
  "event": "auth.login.failure",
  "correlationId": "req-abc123",
  "userId": null,
  "ip": "192.168.1.100",
  "userAgent": "Mozilla/5.0...",
  "details": {
    "email": "user@example.com",
    "reason": "invalid_password",
    "attemptCount": 3
  }
}
\`\`\`

## Monitoring & Alerting

### Key Metrics to Monitor

1. **Failed login rate** - Spike indicates brute force
2. **Error rate by endpoint** - May indicate probing
3. **Request rate by IP** - DDoS or scraping
4. **Geographic anomalies** - Login from unusual locations
5. **Privilege escalation attempts** - Access denied patterns

### Alert Thresholds (Examples)

\`\`\`
⚠️ WARNING: >5 failed logins from same IP in 5 minutes
🚨 CRITICAL: >20 failed logins from same IP in 1 minute
⚠️ WARNING: Admin action from new IP address
🚨 CRITICAL: Database error rate >1% sustained 5 minutes
\`\`\`

## Incident Response Integration

Logs enable:
1. **Detection** - Identify attack in progress
2. **Investigation** - Trace attacker's actions
3. **Containment** - Understand scope of compromise
4. **Evidence** - Support legal/forensic analysis
5. **Prevention** - Learn and improve defenses`,
    },
    {
      id: "logging-quiz-1",
      title: "Quiz: What to Log",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "Which of the following should you log for security monitoring?",
        options: [
          "Successful user passwords for verification",
          "Failed authentication attempts with IP and timestamp",
          "Full credit card numbers for payment tracking",
          "Session tokens for debugging",
        ],
        correctAnswer: 1,
        explanation:
          "Failed authentication attempts with contextual information (IP, timestamp, user agent) are essential for detecting brute force attacks. Passwords, credit cards, and tokens should NEVER be logged.",
      },
    },
    {
      id: "logging-quiz-2",
      title: "Quiz: Log Injection",
      type: "quiz",
      content: "",
      quiz: {
        question: "What is log injection and why is it dangerous?",
        options: [
          "A technique to improve log performance",
          "Attackers inserting fake log entries to hide malicious activity or frame others",
          "A method of compressing log files",
          "A way to encrypt sensitive log data",
        ],
        correctAnswer: 1,
        explanation:
          "Log injection occurs when attackers include special characters (like newlines) in input that ends up in logs, allowing them to create fake log entries, hide evidence of attacks, or even inject malicious content into log analysis tools.",
      },
    },
    {
      id: "logging-quiz-3",
      title: "Quiz: Sensitive Data",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "A developer logs the full request body for debugging. What is the security risk?",
        options: [
          "Log files will become too large",
          "Performance will degrade",
          "Sensitive data like passwords and tokens may be exposed in logs",
          "There is no security risk",
        ],
        correctAnswer: 2,
        explanation:
          "Logging full request bodies can inadvertently capture passwords, API keys, tokens, and personal data. Logs are often stored with less protection than databases and may be accessed by more people, creating a significant data exposure risk.",
      },
    },
    {
      id: "logging-quiz-4",
      title: "Quiz: Detection Time",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "According to industry reports, what is the average time to detect a data breach without proper monitoring?",
        options: ["1-2 hours", "1-2 days", "1-2 weeks", "6+ months"],
        correctAnswer: 3,
        explanation:
          "Industry reports consistently show that breaches take an average of 200+ days to detect without proper monitoring. With effective logging and monitoring, this can be reduced to hours or days.",
      },
    },
    {
      id: "logging-lab",
      title: "Lab: Implement Secure Logging",
      type: "lab",
      content: "",
      lab: {
        instructions:
          "The code below has multiple logging security issues. Fix them by: 1) Removing sensitive data from logs, 2) Adding sanitization to prevent log injection, 3) Using structured logging format.",
        initialCode: `function handleLogin(req, res) {
  const { email, password } = req.body;

  // Log the login attempt with all details
  console.log(\`Login attempt: email=\${email}, password=\${password}, ip=\${req.ip}\`);

  const user = authenticate(email, password);

  if (user) {
    const token = generateToken(user);
    // Log success with token for debugging
    console.log(\`Login success: user=\${email}, token=\${token}\`);
    res.json({ token });
  } else {
    console.log(\`Login failed for \${email}\`);
    res.status(401).json({ error: 'Invalid credentials' });
  }
}`,
        solutionCode: `function handleLogin(req, res) {
  const { email, password } = req.body;

  // Sanitize input for logging (prevent log injection)
  const sanitizedEmail = email.replace(/[\\r\\n]/g, '');

  const user = authenticate(email, password);

  if (user) {
    // Log success WITHOUT sensitive data
    logger.info('auth.login.success', {
      userId: user.id,
      email: sanitizedEmail,
      ip: req.ip
    });

    const token = generateToken(user);
    res.json({ token });
  } else {
    // Log failure for security monitoring
    logger.warn('auth.login.failure', {
      email: sanitizedEmail,
      ip: req.ip,
      reason: 'invalid_credentials'
    });
    res.status(401).json({ error: 'Invalid credentials' });
  }
}`,
      },
    },
  ],
};
