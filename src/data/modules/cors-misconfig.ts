import type { Module } from "../../types";

export const corsMisconfig: Module = {
  id: "cors-misconfig",
  title: "CORS Misconfiguration",
  description:
    "Learn how Cross-Origin Resource Sharing misconfigurations can expose sensitive data and how to configure CORS securely.",
  difficulty: "Intermediate",
  xpReward: 350,
  locked: false,
  lessons: [
    {
      id: "cors-theory",
      title: "Understanding CORS",
      type: "theory",
      content: `
# Cross-Origin Resource Sharing (CORS)

CORS is a security mechanism that allows servers to specify which origins can access their resources. Misconfigured CORS can expose your API to unauthorized access from malicious websites.

## Mission Briefing: The Same-Origin Policy

Browsers enforce the Same-Origin Policy (SOP) by default: scripts on one origin cannot read responses from another origin. CORS is a controlled way to relax this restriction.

\`\`\`
Origin = protocol + host + port
https://api.example.com:443 ≠ https://app.example.com:443
\`\`\`

## How CORS Works

When a browser makes a cross-origin request, the server responds with Access-Control headers:

\`\`\`
Access-Control-Allow-Origin: https://trusted-app.com
Access-Control-Allow-Methods: GET, POST
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Allow-Credentials: true
\`\`\`

## Real-World Intel

**Case File #1: Uber (2016)**
A CORS misconfiguration allowed attackers to read trip history, credit card details, and personal information from any website a user visited.

**Case File #2: BitBucket (2018)**
Wildcard CORS configuration exposed private repository contents to malicious websites.

## The Danger: Wildcard + Credentials

The most critical misconfiguration:
\`\`\`javascript
// VULNERABLE: Never do this!
res.setHeader('Access-Control-Allow-Origin', '*');
res.setHeader('Access-Control-Allow-Credentials', 'true');
\`\`\`

While browsers block this specific combination, many developers work around it by reflecting the Origin header—equally dangerous.

## Preflight Requests

For "complex" requests (PUT, DELETE, custom headers), browsers send a preflight OPTIONS request first. The server must respond with appropriate CORS headers before the actual request proceeds.
            `,
    },
    {
      id: "cors-quiz-1",
      title: "CORS Fundamentals",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "What is the purpose of the Access-Control-Allow-Origin header?",
        options: [
          "To encrypt data sent between origins",
          "To specify which origins are permitted to read the response",
          "To block all cross-origin requests",
          "To authenticate the requesting client",
        ],
        correctAnswer: 1,
        explanation:
          "Access-Control-Allow-Origin specifies which origins are allowed to read the response from a cross-origin request. The browser enforces this—if the response doesn't include the requesting origin, the browser blocks JavaScript from reading the response.",
      },
    },
    {
      id: "cors-quiz-2",
      title: "Credentials Mode",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "Why is 'Access-Control-Allow-Origin: *' combined with 'Access-Control-Allow-Credentials: true' dangerous?",
        options: [
          "It causes the server to crash",
          "It would allow any website to make authenticated requests and read responses with the user's credentials",
          "It disables HTTPS encryption",
          "It exposes the server's source code",
        ],
        correctAnswer: 1,
        explanation:
          "This combination would allow any malicious website to make requests with the user's cookies/credentials and read the response. Browsers actually block this specific combination, but developers often work around it by reflecting the Origin header, which is equally dangerous.",
      },
    },
    {
      id: "cors-quiz-3",
      title: "Preflight Requests",
      type: "quiz",
      content: "",
      quiz: {
        question: "When does a browser send a preflight OPTIONS request?",
        options: [
          "For every cross-origin request",
          "Only for GET requests",
          "For requests with custom headers, non-simple methods (PUT, DELETE), or non-simple content types",
          "Only when the server requires authentication",
        ],
        correctAnswer: 2,
        explanation:
          "Preflight requests are sent for 'complex' requests: those using methods like PUT/DELETE, custom headers like Authorization, or content types other than form data. Simple GET/POST requests with standard headers don't trigger preflight.",
      },
    },
    {
      id: "cors-quiz-4",
      title: "Origin Reflection Attack",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "A server reflects the Origin header in Access-Control-Allow-Origin without validation. What's the security impact?",
        options: [
          "No impact—this is the recommended approach",
          "Any origin can make cross-origin requests and read responses, bypassing CORS protection entirely",
          "It only affects GET requests",
          "The browser will automatically block this",
        ],
        correctAnswer: 1,
        explanation:
          "Reflecting the Origin header without validation is equivalent to using a wildcard but works with credentials. Any malicious site can make authenticated requests to your API and read the response, potentially stealing sensitive user data.",
      },
    },
    {
      id: "cors-lab",
      title: "Secure CORS Configuration",
      type: "lab",
      content:
        "The API endpoint below has a dangerous CORS configuration that reflects any origin. Your mission: Implement a secure allowlist-based CORS policy.",
      lab: {
        initialCode: `
function setCorsHeaders(req, res) {
  // VULNERABLE: Reflects any origin!
  const origin = req.headers.origin;
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

// Handle the request
app.get('/api/user', (req, res) => {
  setCorsHeaders(req, res);
  res.json(getUserData(req.user));
});
                `,
        solutionCode: `
const ALLOWED_ORIGINS = [
  'https://app.example.com',
  'https://admin.example.com'
];

function setCorsHeaders(req, res) {
  const origin = req.headers.origin;

  // SECURE: Only allow origins from the allowlist
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }
}

// Handle the request
app.get('/api/user', (req, res) => {
  setCorsHeaders(req, res);
  res.json(getUserData(req.user));
});
                `,
        instructions:
          "Fix the CORS vulnerability: 1) Create an ALLOWED_ORIGINS array with trusted domains, 2) Check if the request origin is in the allowlist before setting Access-Control-Allow-Origin, 3) Only set CORS headers for allowed origins.",
      },
    },
  ],
};
