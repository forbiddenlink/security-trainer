import type { Module } from '../../types';

export const subdomainTakeover: Module = {
    id: 'subdomain-takeover',
    title: 'Subdomain Takeover',
    description: 'Learn how dangling DNS records create opportunities for attackers to hijack your subdomains and impersonate your organization.',
    difficulty: 'Advanced',
    xpReward: 400,
    locked: false,
    lessons: [
        {
            id: 'subdomain-theory-how',
            title: 'How Subdomain Takeover Works',
            type: 'theory',
            content: `
# How Subdomain Takeover Works

A subdomain takeover occurs when a DNS record points to a service that has been deprovisioned, allowing an attacker to claim that service and serve content under your domain.

## The Mechanics

1. Your organization creates \`staging.example.com\` with a CNAME pointing to \`example-staging.herokuapp.com\`
2. The project ends. The Heroku app is deleted. **But the DNS record remains.**
3. An attacker creates a new Heroku app named \`example-staging\` on their own account
4. \`staging.example.com\` now resolves to the attacker's content

\`\`\`
staging.example.com  CNAME  example-staging.herokuapp.com
                               ↓
                       [Heroku App Deleted]
                               ↓
                       Attacker claims "example-staging"
                               ↓
                       staging.example.com → Attacker's content
\`\`\`

## Dangling DNS Records

A **dangling DNS** record is any record (CNAME, A, AAAA) that points to a resource that no longer exists. This is the root cause of all subdomain takeovers.

Common scenarios:
- CNAME to a deleted cloud service (Heroku, GitHub Pages, AWS S3)
- A record to a released Elastic IP or decommissioned server
- NS delegation to nameservers you no longer control

## Vulnerable Services

Not all services are equally vulnerable. Takeover is possible when a service allows anyone to claim an arbitrary hostname:

| Service | Vulnerable? | Mechanism |
|---------|------------|-----------|
| **GitHub Pages** | Yes | Custom domain CNAME claim |
| **AWS S3** | Yes | Bucket name matches subdomain |
| **Heroku** | Yes | App name claim |
| **Azure** | Yes | Multiple services (CDN, Traffic Manager, App Service) |
| **Shopify** | Yes | Custom domain binding |
| **Fastly** | Yes | CDN hostname claim |
| **Pantheon** | Yes | Custom domain claim |
| **Surge.sh** | Yes | Project claim |
| **AWS CloudFront** | Partial | Distribution must be deleted |
| **Google Cloud** | Low | Requires domain verification |

## Real-World Cases

### Starbucks Subdomain Takeover (2018)
A researcher discovered that \`svcgatewayus.starbucks.com\` had a CNAME pointing to an unclaimed Azure Traffic Manager endpoint. They claimed it and demonstrated they could serve arbitrary content — including credential-harvesting phishing pages — under the trusted starbucks.com domain. Bounty: $2,000.

### Microsoft Subdomain Takeovers (2019-2020)
Security researchers found over 670 subdomains across microsoft.com, skype.com, and other Microsoft properties with dangling DNS records. Attackers could have used these for phishing, cookie theft (same-origin for the parent domain), and OAuth token interception.

### Tesla Subdomain Takeover (2017)
A researcher found \`ciso.tesla.com\` pointing to an unclaimed CloudFront distribution. They claimed it and reported it through Tesla's bug bounty program.

## Why It's Dangerous

- **Phishing:** Victims trust content served from your domain
- **Cookie theft:** Subdomain can read cookies scoped to the parent domain
- **OAuth hijacking:** Can intercept redirect URIs if they match the subdomain
- **Email spoofing:** SPF/DKIM may authorize the subdomain for sending
- **SEO poisoning:** Attacker content indexed under your domain authority
            `
        },
        {
            id: 'subdomain-quiz-risk',
            title: 'DNS & Subdomain Risk Assessment',
            type: 'quiz',
            content: '',
            quiz: {
                question: "Your organization has `blog.example.com` with a CNAME record pointing to `example.ghost.io`. The Ghost blog was cancelled six months ago. What is the immediate risk?",
                options: [
                    "No risk — the CNAME will simply fail to resolve and visitors will see a browser error",
                    "An attacker could create a Ghost blog at example.ghost.io and serve malicious content under blog.example.com",
                    "The DNS record will automatically expire after 30 days of the target being unreachable",
                    "Only internal employees could be affected since external DNS wouldn't propagate"
                ],
                correctAnswer: 1,
                explanation: "The dangling CNAME creates a direct takeover opportunity. An attacker can register a Ghost blog at example.ghost.io, and blog.example.com will serve their content. DNS records do not auto-expire — they persist until manually removed, regardless of whether the target exists."
            }
        },
        {
            id: 'subdomain-theory-prevention',
            title: 'Detection & Prevention',
            type: 'theory',
            content: `
# Detection & Prevention

Subdomain takeover prevention requires both proactive detection and disciplined operational processes.

## Subdomain Enumeration

Before you can protect your subdomains, you need to know what exists. These tools discover subdomains through various techniques:

### Passive Enumeration
- **subfinder** — Aggregates results from 40+ sources (Certificate Transparency logs, DNS datasets, search engines)
- **amass** — OWASP project for comprehensive subdomain mapping via passive and active techniques
- **crt.sh** — Free Certificate Transparency log search

\`\`\`bash
# Discover subdomains passively
subfinder -d example.com -o subdomains.txt

# Comprehensive enumeration with amass
amass enum -passive -d example.com -o amass-results.txt
\`\`\`

### Active Detection
- **subjack** — Tests CNAME records against known vulnerable service fingerprints
- **nuclei** — Template-based scanner with subdomain takeover detection templates
- **can-i-take-over-xyz** — Community-maintained list of vulnerable services and their fingerprints

\`\`\`bash
# Check for takeover vulnerabilities
subjack -w subdomains.txt -t 100 -v

# Use nuclei with takeover templates
nuclei -l subdomains.txt -t takeovers/
\`\`\`

## Monitoring DNS Records

Set up continuous monitoring, not just one-time audits:

- **DNS record diffing:** Snapshot your zone files weekly, alert on changes
- **Certificate Transparency monitoring:** Watch for unexpected certificates issued for your subdomains
- **Automated scanning:** Run subjack/nuclei in CI on a schedule

\`\`\`yaml
# Example GitHub Actions workflow for DNS monitoring
name: DNS Takeover Scan
on:
  schedule:
    - cron: '0 6 * * 1'  # Weekly on Monday
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - run: subfinder -d example.com -o subs.txt
      - run: subjack -w subs.txt -v -o results.json
      - name: Alert on findings
        if: steps.scan.outputs.findings != ''
        run: curl -X POST $SLACK_WEBHOOK -d @results.json
\`\`\`

## Service Deprovisioning Checklist

When removing any external service:

1. **Delete the DNS record FIRST** — before deprovisioning the service
2. **Verify removal** — confirm the record no longer resolves (\`dig\` / \`nslookup\`)
3. **Check for wildcard records** — \`*.example.com\` can create invisible exposure
4. **Document the change** — log who removed what and when
5. **Scan post-removal** — run a takeover check 24 hours after deprovisioning

## Cloud Resource Lifecycle Management

- **Tag all cloud resources** with the DNS records that point to them
- **Automate cleanup:** Terraform/Pulumi can manage DNS + service lifecycle together
- **Require DNS review** in service decommission runbooks
- **Use infrastructure-as-code:** DNS changes go through code review, not manual portal edits

\`\`\`hcl
# Terraform: DNS and service lifecycle are coupled
resource "aws_s3_bucket" "marketing_site" {
  bucket = "marketing.example.com"
}

resource "aws_route53_record" "marketing" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "marketing.example.com"
  type    = "CNAME"
  records = [aws_s3_bucket.marketing_site.bucket_regional_domain_name]
}
# When the bucket is destroyed, the DNS record is destroyed too
\`\`\`

## Domain Verification

Where possible, use services that require domain ownership verification (TXT record) before accepting custom domains. Google Cloud and some CDN providers do this — it prevents third parties from claiming your subdomains.
            `
        },
        {
            id: 'subdomain-quiz-prevention',
            title: 'Prevention Strategy',
            type: 'quiz',
            content: '',
            quiz: {
                question: "Your team is decommissioning a staging environment hosted on Heroku. The subdomain `staging.example.com` has a CNAME pointing to `example-staging.herokuapp.com`. What is the correct order of operations?",
                options: [
                    "Delete the Heroku app first, then remove the DNS record within the next sprint",
                    "Remove the DNS CNAME record first, verify it no longer resolves, then delete the Heroku app",
                    "Leave the DNS record in place as documentation of the old environment, and delete the Heroku app",
                    "Rename the Heroku app to a random string, then remove both the app and DNS record whenever convenient"
                ],
                correctAnswer: 1,
                explanation: "Always remove the DNS record before (or simultaneously with) deprovisioning the service. The window between service deletion and DNS cleanup is exactly when takeover is possible. Removing DNS first ensures no resolution to a non-existent (and claimable) service."
            }
        },
        {
            id: 'subdomain-lab',
            title: 'DNS Configuration Audit',
            type: 'lab',
            content: 'You have been given a list of DNS records for an organization along with the current status of their target services. Your mission: write an audit function that identifies which subdomains are vulnerable to takeover.',
            lab: {
                initialCode: `
// Each DNS record has a subdomain, type, target, and service status
const dnsRecords = [
  { subdomain: "blog.example.com", type: "CNAME", target: "example.ghost.io", serviceActive: true },
  { subdomain: "docs.example.com", type: "CNAME", target: "example-docs.herokuapp.com", serviceActive: false },
  { subdomain: "shop.example.com", type: "CNAME", target: "example.myshopify.com", serviceActive: true },
  { subdomain: "staging.example.com", type: "CNAME", target: "example-staging.s3.amazonaws.com", serviceActive: false },
  { subdomain: "api.example.com", type: "A", target: "203.0.113.10", serviceActive: true },
  { subdomain: "old-campaign.example.com", type: "CNAME", target: "example-campaign.azurewebsites.net", serviceActive: false },
  { subdomain: "mail.example.com", type: "MX", target: "mx.example.com", serviceActive: true },
  { subdomain: "beta.example.com", type: "CNAME", target: "example-beta.netlify.app", serviceActive: false },
];

// Services known to be vulnerable to subdomain takeover
const vulnerableServices = [
  "herokuapp.com",
  "s3.amazonaws.com",
  "azurewebsites.net",
  "ghost.io",
  "myshopify.com",
  "netlify.app",
  "github.io",
];

function auditDnsRecords(records, vulnerableServices) {
  const vulnerableSubdomains = [];
  // TODO: Check each record and identify vulnerable subdomains
  // A subdomain is vulnerable if:
  // 1. It has a CNAME record
  // 2. The target service is NOT active (serviceActive === false)
  // 3. The target matches a known vulnerable service
  return vulnerableSubdomains;
}

const results = auditDnsRecords(dnsRecords, vulnerableServices);
console.log("Vulnerable subdomains:", results);
                `,
                solutionCode: `
const dnsRecords = [
  { subdomain: "blog.example.com", type: "CNAME", target: "example.ghost.io", serviceActive: true },
  { subdomain: "docs.example.com", type: "CNAME", target: "example-docs.herokuapp.com", serviceActive: false },
  { subdomain: "shop.example.com", type: "CNAME", target: "example.myshopify.com", serviceActive: true },
  { subdomain: "staging.example.com", type: "CNAME", target: "example-staging.s3.amazonaws.com", serviceActive: false },
  { subdomain: "api.example.com", type: "A", target: "203.0.113.10", serviceActive: true },
  { subdomain: "old-campaign.example.com", type: "CNAME", target: "example-campaign.azurewebsites.net", serviceActive: false },
  { subdomain: "mail.example.com", type: "MX", target: "mx.example.com", serviceActive: true },
  { subdomain: "beta.example.com", type: "CNAME", target: "example-beta.netlify.app", serviceActive: false },
];

const vulnerableServices = [
  "herokuapp.com",
  "s3.amazonaws.com",
  "azurewebsites.net",
  "ghost.io",
  "myshopify.com",
  "netlify.app",
  "github.io",
];

function auditDnsRecords(records, vulnerableServices) {
  const vulnerableSubdomains = [];

  for (const record of records) {
    if (record.type !== "CNAME") continue;
    if (record.serviceActive) continue;

    const isVulnerableService = vulnerableServices.some(
      (service) => record.target.endsWith(service)
    );

    if (isVulnerableService) {
      vulnerableSubdomains.push({
        subdomain: record.subdomain,
        target: record.target,
        risk: "Subdomain takeover — CNAME points to deprovisioned vulnerable service",
      });
    }
  }

  return vulnerableSubdomains;
}

const results = auditDnsRecords(dnsRecords, vulnerableServices);
console.log("Vulnerable subdomains:", results);
                `,
                instructions: "Implement the auditDnsRecords function: 1) Loop through each record, 2) Skip records that are not CNAME type, 3) Skip records where serviceActive is true, 4) Check if the target matches a vulnerable service using .some() and .endsWith(), 5) Push vulnerable subdomains to the results array with subdomain, target, and risk description."
            }
        }
    ]
};
