import type { Module } from "../../types";

export const jwtVulnerabilities: Module = {
  id: "jwt-vulnerabilities",
  title: "JWT Security Vulnerabilities",
  description:
    "Understand JWT attacks including algorithm confusion, weak secrets, and token tampering.",
  difficulty: "Intermediate",
  xpReward: 400,
  locked: false,
  lessons: [
    {
      id: "jwt-theory",
      title: "Understanding JWT Security",
      type: "theory",
      content: `
# JWT Security Vulnerabilities

JSON Web Tokens (JWTs) are widely used for authentication, but improper implementation creates serious security holes. Understanding these vulnerabilities is essential for secure API development.

## JWT Structure Refresher

A JWT has three parts separated by dots:
\`\`\`
eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiam9obiJ9.xyz123signature
   HEADER              PAYLOAD              SIGNATURE
\`\`\`

- **Header**: Algorithm and token type
- **Payload**: Claims (user data, expiration, etc.)
- **Signature**: Cryptographic verification

## Critical Vulnerabilities

### 1. Algorithm Confusion (Critical)
The most dangerous JWT attack. If a server accepts tokens signed with different algorithms, attackers can:

\`\`\`mermaid
sequenceDiagram
    participant Attacker
    participant Server

    Note over Attacker: Valid token signed with RS256
    Attacker->>Attacker: Change alg header to HS256
    Attacker->>Attacker: Sign with server's PUBLIC key
    Attacker->>Server: Send forged token
    Server->>Server: Uses public key as HMAC secret
    Server->>Attacker: Token accepted - auth bypass!
\`\`\`

\`\`\`javascript
// Attacker changes header from RS256 to HS256
// Then signs with the PUBLIC key (which everyone has)
{ "alg": "HS256" }  // Changed from RS256!
\`\`\`

If the server's public key is used as the HMAC secret, the attacker's signature will verify!

::video[https://www.youtube.com/watch?v=I-vjt5dU7wQ]{title="JWT Algorithm Confusion" caption="How one header field bypasses authentication"}

### 2. "none" Algorithm Attack
Some libraries accept \`"alg": "none"\` which means NO signature required:

\`\`\`javascript
{ "alg": "none" }  // No signature needed!
{ "user": "admin", "role": "superuser" }
// No signature at all - just remove it
\`\`\`

### 3. Weak Secrets
HMAC-signed JWTs can be brute-forced if the secret is weak:
\`\`\`bash
# Tools like jwt_tool can crack weak secrets in seconds
jwt_tool eyJ... -C -d /usr/share/wordlists/rockyou.txt
\`\`\`

## Real-World Intel

**Case File: Auth0 (2015)** - Algorithm confusion vulnerability allowed attackers to forge tokens and impersonate any user.

**Case File: Multiple Node.js Libraries** - The "none" algorithm was enabled by default, allowing complete auth bypass.

## Defense Checklist

1. **Whitelist algorithms** - Never let the token dictate which algorithm to use
2. **Use strong secrets** - At least 256 bits of entropy for HMAC
3. **Validate all claims** - Check exp, iss, aud, not just signature
4. **Reject "none" algorithm** - Explicitly disable it
            `,
    },
    {
      id: "jwt-quiz-1",
      title: "Algorithm Confusion Attack",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "In an algorithm confusion attack, how does an attacker exploit a server that supports both RS256 and HS256?",
        options: [
          "They decrypt the JWT using a rainbow table",
          "They change the algorithm to HS256 and sign with the server's public RS256 key",
          "They overflow the signature buffer to bypass validation",
          "They replay an old token from a different session",
        ],
        correctAnswer: 1,
        explanation:
          "In algorithm confusion, the attacker switches from RS256 (asymmetric) to HS256 (symmetric). If the server uses its public key for HMAC verification (because it's the only 'key' it has for that token), the attacker can sign with that same public key and the signature will verify.",
      },
    },
    {
      id: "jwt-quiz-2",
      title: "None Algorithm Defense",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "What is the correct way to prevent 'none' algorithm attacks?",
        options: [
          "Check if the signature is empty before processing",
          "Explicitly whitelist allowed algorithms and reject all others",
          "Require tokens to be at least 100 characters long",
          "Only use JWTs over HTTPS connections",
        ],
        correctAnswer: 1,
        explanation:
          "The safest approach is to explicitly whitelist the algorithms your server accepts (e.g., only HS256 or only RS256) and reject any token that specifies a different algorithm, including 'none'. Never trust the algorithm specified in the token header.",
      },
    },
    {
      id: "jwt-quiz-3",
      title: "Secret Strength",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "For HMAC-SHA256 signed JWTs, what is the minimum recommended secret length?",
        options: [
          "8 characters (like a typical password)",
          "16 characters (128 bits)",
          "32 characters (256 bits) or more",
          "Secret length doesn't matter if you use HTTPS",
        ],
        correctAnswer: 2,
        explanation:
          "HMAC-SHA256 produces a 256-bit hash, so your secret should have at least 256 bits of entropy to prevent brute-force attacks. This means at least 32 random bytes, not a human-readable password. Weak secrets can be cracked in minutes with tools like hashcat.",
      },
    },
    {
      id: "jwt-quiz-4",
      title: "Claim Validation",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "Besides verifying the signature, which JWT claims should ALWAYS be validated?",
        options: [
          "Only the 'sub' (subject) claim",
          "Only the 'iat' (issued at) claim",
          "exp (expiration), iss (issuer), and aud (audience) claims",
          "Claims don't need validation if the signature is valid",
        ],
        correctAnswer: 2,
        explanation:
          "A valid signature only proves the token wasn't tampered with—it doesn't mean the token should be accepted. You must check: exp (not expired), iss (from trusted issuer), aud (intended for your service). Otherwise, tokens from other services or expired tokens could be accepted.",
      },
    },
    {
      id: "jwt-lab",
      title: "Secure JWT Verification",
      type: "lab",
      content:
        'The JWT verification code below is vulnerable to algorithm confusion and accepts the "none" algorithm. Your mission: Implement secure verification with algorithm whitelisting.',
      lab: {
        initialCode: `
function verifyToken(token, publicKey) {
  // VULNERABLE: Trusts algorithm from token header!
  const decoded = jwt.decode(token, { complete: true });
  const algorithm = decoded.header.alg;

  // VULNERABLE: No algorithm whitelist!
  const payload = jwt.verify(token, publicKey, {
    algorithms: [algorithm]  // Uses whatever the token says!
  });

  return payload;
}
                `,
        solutionCode: `
function verifyToken(token, publicKey) {
  // SECURE: Define allowed algorithms (whitelist)
  const allowedAlgorithms = ['RS256'];

  // SECURE: Verify with explicit algorithm whitelist
  const payload = jwt.verify(token, publicKey, {
    algorithms: allowedAlgorithms,
    issuer: 'https://auth.example.com',
    audience: 'api.example.com'
  });

  return payload;
}
                `,
        instructions:
          "Fix the JWT verification: 1) Create an allowedAlgorithms array with only 'RS256', 2) Use this whitelist in jwt.verify options, 3) Add issuer and audience validation.",
      },
    },
  ],
};
