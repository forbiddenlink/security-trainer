import type { Module } from '../../types';

export const ssrfAttacks: Module = {
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

In a typical SSRF attack, the attacker abuses functionality on the server to read or update internal resources. Unlike client-side attacks (like XSS), SSRF exploits the **trust** that internal networks and cloud services place in requests originating from an application server.

## Critical Target: Cloud Metadata Endpoints

Modern cloud infrastructure exposes metadata services at well-known IP addresses:

### AWS Instance Metadata Service
\`\`\`
http://169.254.169.254/latest/meta-data/iam/security-credentials/[role-name]
\`\`\`

These endpoints can expose IAM credentials, API tokens, and secrets.

## Case File: Capital One Breach (2019)
**Impact:** 100+ million customer records exposed

A former AWS employee exploited an SSRF vulnerability to query the AWS metadata service and retrieve IAM role credentials, which were then used to access S3 buckets containing customer data.

## Defense Strategies

1. **Allowlist Validation**: Only permit requests to known, trusted domains
2. **Block Internal IP Ranges**: Deny requests to localhost, private ranges, and cloud metadata IPs
3. **Disable Unnecessary Protocols**: Only allow http:// and https://
4. **Use Network Segmentation**: Deploy applications in segments that cannot reach sensitive services
5. **AWS IMDSv2**: Use token-based metadata service
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
                explanation: "Cloud metadata services are accessible from any application running on the instance. SSRF allows attackers to make requests to these endpoints and steal IAM credentials. This was the core of the Capital One breach."
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
                explanation: "The IP 169.254.169.254 is the AWS metadata endpoint. An attacker requesting this URL is attempting SSRF to steal cloud credentials."
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
                explanation: "A combination of domain allowlisting AND blocking internal IP ranges provides defense in depth. Blocking only the metadata IP misses other internal services."
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
                explanation: "SSRF filters are often bypassed using: case variations (LOCALHOST), alternative representations (0.0.0.0), or IPv6 (::1). Robust protection requires blocking ALL private/internal ranges."
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
                explanation: "The attacker used SSRF to query the AWS metadata service and obtained temporary AWS credentials assigned to the server's IAM role."
            }
        },
        {
            id: 'ssrf-lab',
            title: 'Implement SSRF Protection',
            type: 'lab',
            content: 'The function below fetches content from a user-provided URL without any validation. Your mission: Implement URL validation to prevent SSRF attacks.',
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
  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    return true;
  }
  if (hostname === '169.254.169.254') {
    return true;
  }
  if (hostname.startsWith('10.') || hostname.startsWith('192.168.')) {
    return true;
  }
  return false;
}
                `,
                instructions: "Implement SSRF protection: 1) Parse URL, 2) Check protocol is 'https:', 3) Validate hostname against allowedDomains, 4) Block private IPs with isPrivateIP() function."
            }
        }
    ]
};
