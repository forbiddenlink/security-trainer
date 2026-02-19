import type { Module } from "../../types";

export const apiSecurity: Module = {
  id: "api-security",
  title: "API Security",
  description:
    "Learn to secure REST APIs against common attacks including broken authentication, excessive data exposure, rate limiting bypasses, and mass assignment vulnerabilities.",
  difficulty: "Intermediate",
  xpReward: 400,
  locked: false,
  lessons: [
    {
      id: "api-security-intro",
      title: "API Security Fundamentals",
      type: "theory",
      content: `# API Security Fundamentals

APIs (Application Programming Interfaces) are the backbone of modern applications. They enable communication between services, mobile apps, and web frontends. However, APIs are prime targets for attackers.

## Why API Security Matters

- **APIs expose business logic directly** - Unlike web pages, APIs provide direct access to data and functionality
- **APIs are increasingly targeted** - The OWASP API Security Top 10 exists specifically for API vulnerabilities
- **Mobile and SPA apps rely on APIs** - Every mobile app and single-page application uses APIs

## Common API Security Risks

### 1. Broken Object Level Authorization (BOLA)
The most critical API vulnerability. Occurs when an API doesn't properly verify that the user has permission to access a specific resource.

\`\`\`
// Vulnerable: No authorization check
GET /api/users/12345/orders

// An attacker changes the user ID
GET /api/users/99999/orders  // Access to another user's data!
\`\`\`

### 2. Broken Authentication
Weak or missing authentication mechanisms:
- No rate limiting on login attempts
- Weak password requirements
- Tokens that never expire
- Credentials in URLs

### 3. Excessive Data Exposure
APIs that return more data than necessary:

\`\`\`json
// Bad: Returns everything including sensitive fields
{
  "id": 123,
  "name": "John",
  "email": "john@example.com",
  "password_hash": "...",  // Shouldn't be exposed!
  "ssn": "123-45-6789",    // Shouldn't be exposed!
  "internal_notes": "..."   // Shouldn't be exposed!
}
\`\`\`

### 4. Lack of Rate Limiting
Without rate limiting, attackers can:
- Brute force credentials
- Scrape data at scale
- Cause denial of service
- Enumerate resources

## Security Best Practices

1. **Always validate authorization** - Check permissions on every request
2. **Use strong authentication** - Implement OAuth 2.0 / JWT properly
3. **Return only needed data** - Use DTOs to control what's exposed
4. **Implement rate limiting** - Protect against abuse
5. **Validate all input** - Never trust client data
6. **Use HTTPS** - Encrypt all API traffic
7. **Version your APIs** - Allow security updates without breaking clients`,
    },
    {
      id: "api-security-quiz",
      title: "API Security Knowledge Check",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "An API endpoint /api/invoices/{id} returns invoice data. A user with ID 5 can access /api/invoices/100 which belongs to user ID 8. What vulnerability is this?",
        options: [
          "SQL Injection",
          "Broken Object Level Authorization (BOLA)",
          "Cross-Site Scripting (XSS)",
          "Server-Side Request Forgery (SSRF)",
        ],
        correctAnswer: 1,
        explanation:
          "This is Broken Object Level Authorization (BOLA), also known as Insecure Direct Object Reference (IDOR). The API fails to verify that the requesting user has permission to access the specific invoice. Just because a user is authenticated doesn't mean they should access any resource - each request must verify authorization for that specific object.",
      },
    },
    {
      id: "api-rate-limiting",
      title: "Rate Limiting & Throttling",
      type: "theory",
      content: `# Rate Limiting & Throttling

Rate limiting is essential for API security. It prevents abuse, protects resources, and ensures fair usage.

## Why Rate Limiting Matters

Without rate limiting, attackers can:
- **Brute force attacks** - Try millions of passwords
- **Data scraping** - Download your entire database
- **Denial of Service** - Overwhelm your servers
- **Enumeration attacks** - Find all valid usernames/emails

## Rate Limiting Strategies

### 1. Fixed Window
Count requests in fixed time periods (e.g., 100 requests per minute).

**Pros:** Simple to implement
**Cons:** Burst traffic at window boundaries

### 2. Sliding Window
Track requests over a rolling time period.

**Pros:** Smoother rate limiting
**Cons:** More memory usage

### 3. Token Bucket
Users have a "bucket" of tokens that refills over time.

**Pros:** Allows bursts while maintaining average rate
**Cons:** More complex to implement

### 4. Leaky Bucket
Requests are processed at a constant rate, excess requests are queued or dropped.

**Pros:** Consistent processing rate
**Cons:** May drop legitimate traffic

## Implementation Headers

Standard headers to communicate rate limits:

\`\`\`
HTTP/1.1 200 OK
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1609459200
\`\`\`

## When Rate Limited (429 Too Many Requests)

\`\`\`
HTTP/1.1 429 Too Many Requests
Retry-After: 60
Content-Type: application/json

{
  "error": "rate_limit_exceeded",
  "message": "Too many requests. Please retry after 60 seconds.",
  "retry_after": 60
}
\`\`\`

## Best Practices

1. **Different limits for different endpoints** - Login endpoints need stricter limits
2. **Identify users properly** - Use API keys, not just IP addresses
3. **Return helpful headers** - Let clients know their limit status
4. **Log rate limit events** - For security monitoring
5. **Consider costs** - Some endpoints are more expensive than others`,
    },
    {
      id: "api-auth-patterns",
      title: "API Authentication Patterns",
      type: "theory",
      content: `# API Authentication Patterns

Choosing the right authentication pattern is crucial for API security.

## Common Authentication Methods

### 1. API Keys

Simple but limited. Best for server-to-server communication.

\`\`\`
GET /api/data HTTP/1.1
X-API-Key: sk_live_abc123def456
\`\`\`

**Pros:** Simple, no expiration management
**Cons:** Can't revoke easily, no user context, easily leaked

### 2. JWT (JSON Web Tokens)

Self-contained tokens with embedded claims.

\`\`\`javascript
// JWT Structure: header.payload.signature
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
              "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ." +
              "signature";

// Usage
GET /api/data HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
\`\`\`

**Pros:** Stateless, scalable, contains user info
**Cons:** Can't revoke easily, size can grow

### 3. OAuth 2.0

Industry standard for delegated authorization.

\`\`\`
┌──────────┐                              ┌──────────┐
│   User   │──1. Authorization Request──▶│  Auth    │
│          │◀──2. Authorization Grant────│  Server  │
│          │                              └──────────┘
│          │                                    │
└──────────┘                                    │
                                                │
┌──────────┐                                    │
│  Client  │──3. Access Token Request──────────┤
│   App    │◀──4. Access Token─────────────────┘
│          │
│          │──5. API Request + Token───▶ ┌──────────┐
│          │◀──6. Protected Resource──── │ Resource │
└──────────┘                             │  Server  │
                                         └──────────┘
\`\`\`

## JWT Security Best Practices

### Do:
- Use short expiration times (15 minutes for access tokens)
- Implement refresh token rotation
- Store tokens securely (httpOnly cookies for web)
- Validate all claims (iss, aud, exp)
- Use strong signing algorithms (RS256, ES256)

### Don't:
- Store sensitive data in JWT payload
- Use symmetric keys (HS256) for public clients
- Send tokens in URL parameters
- Use JWTs for session management without refresh tokens

## Token Storage

| Platform | Recommended Storage |
|----------|---------------------|
| Web SPA | httpOnly cookie |
| Mobile | Secure enclave / Keychain |
| Server | Environment variables |

## Refresh Token Flow

\`\`\`
1. User logs in
2. Server returns access_token (15 min) + refresh_token (7 days)
3. Access token expires
4. Client sends refresh_token to get new access_token
5. Old refresh_token is invalidated (rotation)
\`\`\``,
    },
    {
      id: "api-security-lab",
      title: "Lab: Secure API Endpoint",
      type: "lab",
      content: `# Lab: Secure an API Endpoint

In this lab, you'll fix a vulnerable API endpoint that has multiple security issues.

## The Vulnerable Code

The following Express.js endpoint has several security problems:

\`\`\`javascript
// VULNERABLE CODE - DO NOT USE
app.get('/api/users/:id', (req, res) => {
  const user = db.query(
    'SELECT * FROM users WHERE id = ' + req.params.id
  );
  res.json(user);
});
\`\`\`

## Your Task

Write a secure version of this endpoint that:
1. Uses parameterized queries to prevent SQL injection
2. Validates that the authenticated user can access this resource
3. Returns only necessary fields (no password hash)

## Requirements

Your solution must include:
- A parameterized query using \`?\` placeholder
- An authorization check comparing \`req.user.id\` with the requested user ID
- A response object that excludes the \`password_hash\` field
- Proper status codes for unauthorized (403) and not found (404) cases`,
    },
    {
      id: "api-mass-assignment",
      title: "Mass Assignment Vulnerabilities",
      type: "theory",
      content: `# Mass Assignment Vulnerabilities

Mass assignment occurs when an API automatically binds request data to model fields without proper filtering.

## The Vulnerability

Consider this user update endpoint:

\`\`\`javascript
// Vulnerable: Accepts any field from request body
app.put('/api/users/:id', (req, res) => {
  const user = User.findById(req.params.id);
  Object.assign(user, req.body);  // Dangerous!
  user.save();
  res.json(user);
});
\`\`\`

An attacker sends:
\`\`\`json
{
  "name": "John",
  "isAdmin": true,        // Privilege escalation!
  "accountBalance": 999999 // Financial manipulation!
}
\`\`\`

## Real-World Example

In 2012, a security researcher exploited GitHub's mass assignment vulnerability to gain commit access to the Rails repository by modifying the \`public_key\` association.

## Prevention Strategies

### 1. Explicit Field Whitelisting

\`\`\`javascript
// Only allow specific fields to be updated
const allowedFields = ['name', 'email', 'bio'];
const updates = {};

for (const field of allowedFields) {
  if (req.body[field] !== undefined) {
    updates[field] = req.body[field];
  }
}

await User.update(updates, { where: { id: req.params.id } });
\`\`\`

### 2. Data Transfer Objects (DTOs)

\`\`\`typescript
// Define exactly what can be updated
interface UpdateUserDTO {
  name?: string;
  email?: string;
  bio?: string;
}

function validateUpdateUserDTO(data: unknown): UpdateUserDTO {
  // Validation logic that strips unknown fields
}
\`\`\`

### 3. Schema Validation

\`\`\`javascript
const updateSchema = Joi.object({
  name: Joi.string().max(100),
  email: Joi.string().email(),
  bio: Joi.string().max(500)
}).unknown(false);  // Reject unknown fields
\`\`\`

## Dangerous Fields to Protect

Always protect these fields from mass assignment:
- \`isAdmin\`, \`role\`, \`permissions\` - Authorization
- \`password\`, \`password_hash\` - Credentials
- \`email_verified\`, \`account_status\` - Account state
- \`balance\`, \`credits\` - Financial data
- \`created_at\`, \`updated_at\` - Timestamps
- \`id\`, \`user_id\` - Identifiers`,
    },
    {
      id: "api-security-final-quiz",
      title: "API Security Final Assessment",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "An API endpoint accepts a JSON body and directly assigns all fields to the database model using Object.assign(). An attacker adds an 'isAdmin: true' field to become an administrator. What is this vulnerability called?",
        options: [
          "SQL Injection",
          "Mass Assignment",
          "Broken Object Level Authorization",
          "Insecure Deserialization",
        ],
        correctAnswer: 1,
        explanation:
          "This is a Mass Assignment vulnerability. It occurs when an API blindly binds request data to internal objects without filtering which fields are allowed. The fix is to explicitly whitelist allowed fields or use DTOs (Data Transfer Objects) that only accept specific properties.",
      },
    },
  ],
};
