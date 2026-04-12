import type { Module } from "../../types";

export const cloudSecurity: Module = {
  id: "cloud-security",
  title: "Cloud Security Fundamentals",
  description:
    "Navigate the cloud threat landscape — from shared responsibility to IAM, storage, and network security.",
  difficulty: "Intermediate",
  xpReward: 400,
  locked: false,
  lessons: [
    {
      id: "cloud-shared-responsibility-theory",
      title: "Cloud Security Shared Responsibility",
      type: "theory",
      content: `# Cloud Security & the Shared Responsibility Model

## The Cloud Paradox

Cloud providers invest billions in security — and yet cloud breaches keep happening. Why?

Because the cloud is secure. Your configuration of it probably isn't.

> The shared responsibility model means the provider secures the **infrastructure**. You secure everything you put **on** it.

## Shared Responsibility by Service Model

### IaaS (Infrastructure as a Service)
**Examples**: AWS EC2, Google Compute Engine, Azure VMs

| Provider Secures | You Secure |
|-----------------|-----------|
| Physical data centers | Operating system patches |
| Hypervisor / host OS | Application security |
| Network infrastructure | Data encryption |
| Hardware | Firewall/security group rules |
| | Identity & access management |
| | Logging & monitoring |

**You own the most.** It's essentially "renting hardware" — everything above the hypervisor is your responsibility.

### PaaS (Platform as a Service)
**Examples**: AWS Elastic Beanstalk, Google App Engine, Azure App Service, Heroku

| Provider Secures | You Secure |
|-----------------|-----------|
| Everything in IaaS + | Application code |
| Operating system | Data |
| Runtime environment | User access management |
| Middleware | Application-level security |
| | API security |

**You own less**, but application security and data protection are still entirely on you.

### SaaS (Software as a Service)
**Examples**: Salesforce, Microsoft 365, Google Workspace, Slack

| Provider Secures | You Secure |
|-----------------|-----------|
| Everything in PaaS + | User accounts & access |
| Application code | Data classification |
| Data storage | Sharing permissions |
| | Compliance configuration |
| | Third-party integrations |

**You own the least**, but misconfigurations in user access and sharing settings cause most SaaS breaches.

## Multi-Tenancy Risks

Cloud providers run multiple customers on shared infrastructure. This creates unique risks:

- **Noisy neighbor**: Other tenants consuming shared resources (DoS by proximity)
- **Side-channel attacks**: Theoretical extraction of data from co-located VMs (Spectre/Meltdown)
- **Data remnants**: Deleted data may persist on shared storage until overwritten
- **Metadata leakage**: Instance metadata services can expose credentials (SSRF → IMDS)

### The Instance Metadata Problem

\`\`\`bash
# This URL is reachable from inside any EC2 instance
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name

# Returns temporary AWS credentials!
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "FwoGZXIvYXdzEBY...",
  "Expiration": "2024-01-15T12:00:00Z"
}
\`\`\`

**IMDSv2** (token-required) mitigates this, but many instances still run IMDSv1.

## Data Residency & Sovereignty

- **GDPR**: EU personal data may need to stay in EU regions
- **Data residency laws**: Russia (data localization), China (PIPL), Brazil (LGPD)
- **Government clouds**: AWS GovCloud, Azure Government for regulated workloads
- **Provider subprocessors**: Know where your data flows through SaaS vendor chains

## Real-World Case: Capital One S3 Breach (2019)

### What Happened
- A former AWS employee exploited a misconfigured WAF to perform SSRF
- SSRF accessed EC2 instance metadata, retrieving IAM role credentials
- Those credentials had overly permissive access to S3 buckets
- **100 million** credit card applications and personal records stolen

### Root Causes
1. **WAF misconfiguration** allowed SSRF to metadata endpoint
2. **Overly permissive IAM role** on the WAF server (could list and read all S3 buckets)
3. **No alerts** on mass S3 data access
4. **IMDSv1** enabled (no token protection)

### Shared Responsibility Breakdown
- **AWS responsibility**: Infrastructure was secure (it was)
- **Capital One responsibility**: IAM policies, WAF configuration, monitoring — all failed

## Real-World Case: Microsoft Power Apps Data Exposure (2021)

### What Happened
- Researchers discovered 38 million records exposed across 47 organizations
- Power Apps portals had **table permissions set to public by default**
- Exposed data included: COVID-19 vaccination records, Social Security numbers, employee records

### Root Cause
- **Default configuration was insecure**: Table permissions were open unless explicitly restricted
- Organizations assumed "private" meant "not accessible" — it didn't
- Microsoft later changed the default to private

### Lesson
SaaS doesn't mean secure. Default configurations must be audited. The shared responsibility model applies even when you're "just using an app."`,
    },
    {
      id: "cloud-shared-responsibility-quiz",
      title: "Quiz: Shared Responsibility Model",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "Your company runs a web application on AWS EC2 instances. An attacker exploits an unpatched vulnerability in your application's dependency (Log4Shell). AWS says it's not their responsibility. Are they correct?",
        options: [
          "No — AWS is responsible for patching all software running on their infrastructure",
          "Yes — in IaaS, the customer is responsible for application dependencies and patching",
          "Partially — AWS should have blocked the exploit at the network level",
          "No — AWS provides the OS and runtime, so they must patch application dependencies",
        ],
        correctAnswer: 1,
        explanation:
          "In the IaaS model (EC2), AWS is responsible for the hardware and hypervisor. Everything above that — the OS, runtime, application code, and dependencies — is the customer's responsibility. Patching Log4j in your application is squarely in your domain. AWS Managed Services (like Lambda or RDS) might have patched it on their end for their managed components, but EC2 is your machine to manage.",
      },
    },
    {
      id: "cloud-iam-theory",
      title: "Identity & Access Management",
      type: "theory",
      content: `# Identity & Access Management (IAM)

## IAM: The Perimeter Is Dead, Long Live Identity

In cloud, there are no physical firewalls to hide behind. Identity IS the perimeter. If an attacker gets valid credentials, they're "inside" — no matter where they are in the world.

## Principle of Least Privilege

Every identity (user, service, application) should have only the minimum permissions required to perform its function.

### AWS IAM Policy — Bad vs Good

\`\`\`json
// ❌ Overly permissive (the "Capital One" pattern)
{
  "Effect": "Allow",
  "Action": "s3:*",
  "Resource": "*"
}

// ✅ Least privilege
{
  "Effect": "Allow",
  "Action": [
    "s3:GetObject",
    "s3:PutObject"
  ],
  "Resource": "arn:aws:s3:::my-app-uploads/*"
}
\`\`\`

### GCP IAM — Bad vs Good

\`\`\`yaml
# ❌ Overly permissive
- role: roles/owner
  members:
    - serviceAccount:my-app@project.iam.gserviceaccount.com

# ✅ Least privilege
- role: roles/storage.objectViewer
  members:
    - serviceAccount:my-app@project.iam.gserviceaccount.com
  condition:
    expression: resource.name.startsWith("projects/_/buckets/my-app-data")
\`\`\`

### Azure RBAC — Bad vs Good

\`\`\`json
// ❌ Overly permissive
{
  "roleDefinitionId": "Owner",
  "scope": "/subscriptions/sub-id"
}

// ✅ Least privilege
{
  "roleDefinitionId": "Storage Blob Data Reader",
  "scope": "/subscriptions/sub-id/resourceGroups/my-rg/providers/Microsoft.Storage/storageAccounts/myaccount"
}
\`\`\`

## Role-Based Access Control (RBAC)

Map permissions to roles, assign roles to identities:

\`\`\`
Role: "AppDeployer"
  → Permissions: ECR push, ECS update, CloudWatch read
  → Assigned to: CI/CD service account, senior engineers

Role: "DataAnalyst"
  → Permissions: S3 read (analytics bucket), Athena query, QuickSight access
  → Assigned to: Analytics team members

Role: "IncidentResponder"
  → Permissions: EC2 describe/stop, VPC modify, CloudTrail read, GuardDuty read
  → Assigned to: Security team (activated during incidents via break-glass)
\`\`\`

## Service Accounts & Machine Identity

Service accounts are the most dangerous identities in cloud — they often have broad permissions and no MFA.

### Best Practices
- **No long-lived keys**: Use IAM roles (AWS), workload identity (GCP), managed identity (Azure)
- **Scope narrowly**: One service account per workload, not shared across applications
- **Rotate if keys are required**: Automate rotation, alert on key age > 90 days
- **Monitor usage**: Alert on service account logins from unexpected sources
- **Disable unused**: Audit service accounts quarterly, disable inactive ones

### Temporary Credentials

\`\`\`typescript
// AWS: Use STS AssumeRole for temporary credentials
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';

const sts = new STSClient({});
const { Credentials } = await sts.send(new AssumeRoleCommand({
  RoleArn: 'arn:aws:iam::123456789012:role/AppDeployer',
  RoleSessionName: 'deploy-pipeline-run-42',
  DurationSeconds: 900, // 15 minutes — minimum viable duration
}));

// Credentials auto-expire — no cleanup needed
\`\`\`

## MFA Enforcement

MFA should be enforced for:
- All human users (no exceptions for executives)
- Root/admin account access
- Sensitive operations (deleting resources, changing IAM policies)
- Console access (even if CLI uses SSO)

### AWS MFA Policy

\`\`\`json
{
  "Effect": "Deny",
  "NotAction": [
    "iam:CreateVirtualMFADevice",
    "iam:EnableMFADevice",
    "iam:ListMFADevices",
    "sts:GetSessionToken"
  ],
  "Resource": "*",
  "Condition": {
    "BoolIfExists": { "aws:MultiFactorAuthPresent": "false" }
  }
}
\`\`\`

## Federation & SSO

Centralizing identity reduces attack surface:

- **SAML 2.0 / OIDC federation**: Use corporate IdP (Okta, Azure AD, Google Workspace) as the source of truth
- **No local cloud accounts**: All access through federated identity
- **Just-in-time access**: Temporary privilege elevation (AWS SSO permission sets, PIM in Azure)
- **Audit trail**: All authentication flows through one system = one place to monitor`,
    },
    {
      id: "cloud-iam-quiz",
      title: "Quiz: IAM Best Practices",
      type: "quiz",
      content: "",
      quiz: {
        question:
          'A developer creates an IAM user with programmatic access and attaches the "AdministratorAccess" policy because "it\'s easier than figuring out which permissions I actually need." The access keys are stored in the application\'s .env file committed to a private GitHub repository. How many security violations are present?',
        options: [
          "One — the overly permissive policy is the only real issue",
          "Two — overly permissive policy and credentials in source control",
          "Three — overly permissive policy, credentials in source control, and using long-lived access keys instead of IAM roles",
          "Four — all of the above plus the .env file should be encrypted at rest",
        ],
        correctAnswer: 2,
        explanation:
          'Three violations: (1) AdministratorAccess violates least privilege — the developer should identify the specific permissions needed. (2) Access keys in a Git repository (even private) risk exposure through repo cloning, collaborator access, or future public exposure. (3) Long-lived access keys should be replaced with IAM roles or temporary credentials via STS AssumeRole. "Private" GitHub repos are not a secrets management solution.',
      },
    },
    {
      id: "cloud-storage-secrets-theory",
      title: "Cloud Storage & Secrets",
      type: "theory",
      content: `# Cloud Storage & Secrets Management

## Storage Misconfigurations: The #1 Cloud Breach Cause

More data has been exposed through misconfigured cloud storage than any other cloud vulnerability. The pattern is almost always the same: a bucket or blob that should be private is accidentally public.

## S3 / GCS / Azure Blob — Access Control

### AWS S3 Bucket Policies

\`\`\`json
// ❌ PUBLIC BUCKET — anyone on the internet can read
{
  "Effect": "Allow",
  "Principal": "*",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::my-bucket/*"
}

// ✅ PRIVATE — only specific role can access
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::123456789012:role/AppServer"
  },
  "Action": ["s3:GetObject", "s3:PutObject"],
  "Resource": "arn:aws:s3:::my-bucket/uploads/*"
}
\`\`\`

### S3 Public Access Block (Account-Level)

\`\`\`json
// ✅ Enable ALL four settings at the account level
{
  "BlockPublicAcls": true,
  "IgnorePublicAcls": true,
  "BlockPublicPolicy": true,
  "RestrictPublicBuckets": true
}
\`\`\`

This is the single most impactful S3 security setting. Apply it at the AWS account level, then grant exceptions only where absolutely needed (e.g., a static website bucket).

### Google Cloud Storage — IAM vs ACLs

\`\`\`bash
# ❌ Legacy ACL — grants public read to all objects
gsutil acl ch -u AllUsers:R gs://my-bucket

# ✅ Uniform bucket-level access (recommended)
gsutil uniformbucketlevelaccess set on gs://my-bucket

# ✅ IAM-based access
gcloud storage buckets add-iam-policy-binding gs://my-bucket \\
  --member="serviceAccount:my-app@project.iam.gserviceaccount.com" \\
  --role="roles/storage.objectViewer"
\`\`\`

### Azure Blob Storage

\`\`\`bash
# ❌ Container with public access
az storage container set-permission --name uploads --public-access blob

# ✅ Private container (default)
az storage container set-permission --name uploads --public-access off
\`\`\`

## Secrets Management

### The Hierarchy of Secrets Storage (Worst to Best)

1. **Hardcoded in source code** — Worst. Committed forever in git history.
2. **Environment variables in .env files** — Bad if committed or logged.
3. **Environment variables set in deployment config** — Okay. Better than files.
4. **Cloud secrets managers** — Good. Encrypted, audited, access-controlled.
5. **Hardware Security Modules (HSM)** — Best. Keys never leave the hardware.

### Cloud Secrets Managers

\`\`\`typescript
// AWS Secrets Manager
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';

const client = new SecretsManagerClient({});
const { SecretString } = await client.send(new GetSecretValueCommand({
  SecretId: 'prod/myapp/database',
}));
const dbCredentials = JSON.parse(SecretString);

// Benefits: automatic rotation, audit trail, encryption at rest,
// fine-grained IAM access control
\`\`\`

\`\`\`typescript
// HashiCorp Vault
const response = await fetch('https://vault.internal:8200/v1/secret/data/database', {
  headers: { 'X-Vault-Token': process.env.VAULT_TOKEN },
});
const { data } = await response.json();
const dbPassword = data.data.password;

// Benefits: dynamic secrets (generated on demand, auto-expire),
// multi-cloud, lease-based access
\`\`\`

### Environment Variables Done Wrong

\`\`\`bash
# ❌ .env committed to git (this happens ALL THE TIME)
DATABASE_URL=postgres://admin:SuperSecret123@db.example.com:5432/prod
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_live_51ABC123...

# ❌ Visible in process listing
ps aux | grep node
# node server.js DATABASE_URL=postgres://admin:SuperSecret123@...

# ❌ Logged by debugging middleware
app.use((req, res, next) => {
  console.log('ENV:', process.env); // LOGS ALL SECRETS
  next();
});
\`\`\`

## Encryption

### Encryption at Rest

| Approach | Who Manages Keys | Use When |
|----------|-----------------|----------|
| **SSE-S3** (S3-managed) | AWS | Default, lowest effort |
| **SSE-KMS** (CMK) | You (via KMS) | Regulatory requirements, key rotation control |
| **SSE-C** (Customer-provided) | You (entirely) | Maximum control, you supply key per request |
| **Client-side encryption** | You (before upload) | Zero-trust of provider, data never decrypted in cloud |

### Encryption in Transit
- **Enforce HTTPS**: S3 bucket policy with \`aws:SecureTransport\` condition
- **TLS 1.2+**: Deprecate TLS 1.0/1.1 everywhere
- **Certificate pinning**: For high-security applications communicating with specific endpoints

\`\`\`json
// ✅ Deny unencrypted S3 access
{
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:*",
  "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"],
  "Condition": {
    "Bool": { "aws:SecureTransport": "false" }
  }
}
\`\`\`

## Real-World Case: Twitch Leak (2021)

- **125GB** of data leaked including: entire source code, creator payment history, internal tools
- Root cause: Server misconfiguration allowed unauthorized access
- Twitch described it as a "server configuration change that allowed improper access"
- Creator payout data (2019-2021) exposed, damaging trust

## Real-World Case: Uber S3 Credentials in GitHub (2016)

- Uber engineers stored AWS credentials in a **private** GitHub repository
- Attackers who gained access to the GitHub account used the credentials to access S3
- **57 million** rider and driver records stolen
- Uber paid $100,000 to the attackers to delete the data (later disclosed, resulting in further legal action)
- **Lesson**: Private repos are not secrets vaults. Use secrets managers.`,
    },
    {
      id: "cloud-network-security-theory",
      title: "Cloud Network Security",
      type: "theory",
      content: `# Cloud Network Security

## Virtual Private Clouds (VPCs)

A VPC is your isolated network within the cloud provider's infrastructure. Think of it as your own private data center — but software-defined.

### VPC Architecture Best Practices

\`\`\`
┌─────────────────────── VPC (10.0.0.0/16) ───────────────────────┐
│                                                                   │
│  ┌─── Public Subnet (10.0.1.0/24) ───┐                          │
│  │  Internet Gateway ←→ ALB           │                          │
│  │  NAT Gateway                       │                          │
│  │  Bastion Host (if needed)          │                          │
│  └────────────────────────────────────┘                          │
│                       │                                           │
│  ┌─── Private Subnet (10.0.10.0/24) ──┐                         │
│  │  Application Servers (EC2/ECS)      │                         │
│  │  → Can reach internet via NAT GW    │                         │
│  │  → NOT directly accessible from     │                         │
│  │    internet                         │                         │
│  └─────────────────────────────────────┘                         │
│                       │                                           │
│  ┌─── Private Subnet (10.0.20.0/24) ──┐                         │
│  │  Database (RDS/ElastiCache)         │                         │
│  │  → No internet access at all        │                         │
│  │  → Only accessible from app subnet  │                         │
│  └─────────────────────────────────────┘                         │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
\`\`\`

**Key principles:**
- **Public subnets**: Only load balancers and NAT gateways
- **Private subnets**: Application servers (outbound via NAT only)
- **Isolated subnets**: Databases (no internet, inbound from app tier only)

## Security Groups (Stateful Firewalls)

Security groups are instance-level firewalls. They're **stateful** — if you allow inbound, the response is automatically allowed outbound.

\`\`\`json
// ❌ Security Group from hell
{
  "IpPermissions": [{
    "IpProtocol": "-1",
    "IpRanges": [{ "CidrIp": "0.0.0.0/0" }]
  }]
}
// Translation: Allow ALL traffic from ANYWHERE. Please hack me.

// ✅ Properly scoped security group
{
  "GroupName": "web-server-sg",
  "IpPermissions": [
    {
      "IpProtocol": "tcp",
      "FromPort": 443,
      "ToPort": 443,
      "IpRanges": [{ "CidrIp": "0.0.0.0/0", "Description": "HTTPS from internet" }]
    },
    {
      "IpProtocol": "tcp",
      "FromPort": 22,
      "ToPort": 22,
      "UserIdGroupPairs": [{ "GroupId": "sg-bastion", "Description": "SSH from bastion only" }]
    }
  ]
}
\`\`\`

## Network ACLs (Stateless Firewalls)

NACLs are subnet-level firewalls. They're **stateless** — you must explicitly allow both inbound AND outbound traffic.

| Feature | Security Group | NACL |
|---------|---------------|------|
| Level | Instance | Subnet |
| Stateful | Yes | No |
| Rules | Allow only | Allow + Deny |
| Evaluation | All rules | Rules in order (first match) |
| Default | Deny all inbound | Allow all |

**Use NACLs for**: Subnet-level deny rules (block known bad IPs), defense-in-depth alongside security groups.

## NAT Gateways

NAT Gateways allow private subnet instances to reach the internet (for updates, API calls) without being directly accessible:

- **Outbound only**: Instances initiate connections, internet cannot initiate inbound
- **No public IP needed**: Instances stay private
- **High availability**: Deploy NAT GW in each AZ

## VPN & Direct Connect

For hybrid cloud (on-prem + cloud):

- **Site-to-Site VPN**: Encrypted tunnel over internet (IPsec). Good for most use cases.
- **AWS Direct Connect / Azure ExpressRoute / GCP Interconnect**: Dedicated physical connection. Lower latency, more bandwidth, doesn't traverse public internet.
- **Client VPN**: Individual users accessing cloud resources securely.

## Web Application Firewall (WAF)

WAF sits in front of your application and filters HTTP/HTTPS traffic:

\`\`\`
Internet → CloudFront/ALB → WAF → Application
                              ↓
                         Rules Engine:
                         - Block SQL injection patterns
                         - Block XSS patterns
                         - Rate limiting (100 req/5min per IP)
                         - Geo-blocking (block countries)
                         - IP reputation lists
                         - Bot detection
                         - Custom rules (your app logic)
\`\`\`

### AWS WAF Managed Rule Groups
- **AWSManagedRulesCommonRuleSet**: OWASP Top 10 protection
- **AWSManagedRulesSQLiRuleSet**: SQL injection patterns
- **AWSManagedRulesKnownBadInputsRuleSet**: Log4Shell, path traversal
- **AWSManagedRulesBotControlRuleSet**: Bot traffic management

## DDoS Protection

| Layer | Attack Type | Protection |
|-------|------------|------------|
| L3/L4 | SYN flood, UDP flood, amplification | AWS Shield Standard (free), Azure DDoS Protection |
| L7 | HTTP flood, slowloris, application-layer | WAF rate limiting, Shield Advanced, CloudFlare |

**AWS Shield Advanced** provides: DDoS cost protection, 24/7 DDoS Response Team, real-time attack visibility.

## Zero-Trust Networking

Traditional: "Trust everything inside the network perimeter."
Zero-Trust: "Never trust, always verify. Every request, every time."

### Zero-Trust Principles in Cloud
1. **Verify explicitly**: Authenticate and authorize every request based on all available data
2. **Least privilege access**: Just-in-time, just-enough-access (JIT/JEA)
3. **Assume breach**: Minimize blast radius, segment access, verify end-to-end encryption

### Implementation
- **BeyondCorp (Google)**: Access based on device trust + user identity, not network location
- **AWS Verified Access**: Application-level access without VPN
- **Azure Private Link**: Access cloud services over private endpoints (no public internet)
- **Service mesh (Istio/Linkerd)**: mTLS between all microservices, policy enforcement at the network layer`,
    },
    {
      id: "cloud-config-audit-lab",
      title: "Lab: Cloud Configuration Audit",
      type: "lab",
      content: "",
      lab: {
        instructions:
          "You are auditing a cloud environment. The configuration below has multiple security misconfigurations across S3, IAM, and Security Groups. Find and fix ALL issues. Add comments explaining each fix. There are at least 7 misconfigurations to find.",
        initialCode: `// CLOUD CONFIGURATION AUDIT
// Review and fix all security misconfigurations

const s3BucketPolicy = {
  bucketName: "acme-customer-data",
  publicAccessBlock: {
    blockPublicAcls: false,
    ignorePublicAcls: false,
    blockPublicPolicy: false,
    restrictPublicBuckets: false,
  },
  policy: {
    Statement: [{
      Effect: "Allow",
      Principal: "*",
      Action: "s3:*",
      Resource: "arn:aws:s3:::acme-customer-data/*",
    }],
  },
  encryption: {
    enabled: false,
  },
  versioning: false,
  logging: false,
};

const iamPolicy = {
  policyName: "AppServerPolicy",
  statement: [
    {
      Effect: "Allow",
      Action: "*",
      Resource: "*",
    },
  ],
  attachedTo: "app-server-role",
  mfaRequired: false,
};

const securityGroup = {
  groupName: "app-server-sg",
  inboundRules: [
    { protocol: "tcp", port: 22, source: "0.0.0.0/0", description: "SSH" },
    { protocol: "tcp", port: 3306, source: "0.0.0.0/0", description: "MySQL" },
    { protocol: "tcp", port: 443, source: "0.0.0.0/0", description: "HTTPS" },
    { protocol: "-1", port: "all", source: "0.0.0.0/0", description: "" },
  ],
  outboundRules: [
    { protocol: "-1", port: "all", destination: "0.0.0.0/0" },
  ],
};`,
        solutionCode: `// CLOUD CONFIGURATION AUDIT — FIXED
// All misconfigurations identified and remediated

const s3BucketPolicy = {
  bucketName: "acme-customer-data",
  // FIX 1: Enable ALL public access blocks at the bucket level
  publicAccessBlock: {
    blockPublicAcls: true,
    ignorePublicAcls: true,
    blockPublicPolicy: true,
    restrictPublicBuckets: true,
  },
  policy: {
    Statement: [{
      // FIX 2: Restrict Principal to specific IAM role (was "*" = public)
      Effect: "Allow",
      Principal: { AWS: "arn:aws:iam::123456789012:role/app-server-role" },
      // FIX 3: Scope actions to only what's needed (was "s3:*")
      Action: ["s3:GetObject", "s3:PutObject"],
      Resource: "arn:aws:s3:::acme-customer-data/*",
      // FIX 4: Enforce encrypted transport only
      Condition: { Bool: { "aws:SecureTransport": "true" } },
    }],
  },
  // FIX 5: Enable server-side encryption with KMS
  encryption: {
    enabled: true,
    type: "aws:kms",
    keyId: "arn:aws:kms:us-east-1:123456789012:key/mrk-example",
  },
  // FIX 6: Enable versioning for data recovery
  versioning: true,
  // FIX 7: Enable access logging for audit trail
  logging: true,
  loggingBucket: "acme-access-logs",
};

const iamPolicy = {
  policyName: "AppServerPolicy",
  statement: [
    {
      // FIX 8: Replace wildcard with specific permissions
      Effect: "Allow",
      Action: [
        "s3:GetObject",
        "s3:PutObject",
        "sqs:SendMessage",
        "sqs:ReceiveMessage",
        "logs:PutLogEvents",
        "logs:CreateLogStream",
      ],
      // FIX 9: Restrict to specific resources
      Resource: [
        "arn:aws:s3:::acme-customer-data/*",
        "arn:aws:sqs:us-east-1:123456789012:app-queue",
        "arn:aws:logs:us-east-1:123456789012:log-group:/app/*",
      ],
    },
  ],
  attachedTo: "app-server-role",
  // FIX 10: Require MFA for sensitive operations
  mfaRequired: true,
};

const securityGroup = {
  groupName: "app-server-sg",
  inboundRules: [
    // FIX 11: Restrict SSH to bastion security group only (was 0.0.0.0/0)
    { protocol: "tcp", port: 22, source: "sg-bastion-host", description: "SSH from bastion only" },
    // FIX 12: Restrict MySQL to app subnet only (was 0.0.0.0/0 — database port open to internet!)
    { protocol: "tcp", port: 3306, source: "10.0.10.0/24", description: "MySQL from app subnet" },
    // HTTPS from anywhere is acceptable for a web server
    { protocol: "tcp", port: 443, source: "0.0.0.0/0", description: "HTTPS from internet" },
    // FIX 13: REMOVED the allow-all rule (protocol -1, all ports, 0.0.0.0/0)
  ],
  // FIX 14: Restrict outbound to only necessary destinations
  outboundRules: [
    { protocol: "tcp", port: 443, destination: "0.0.0.0/0", description: "HTTPS outbound" },
    { protocol: "tcp", port: 3306, destination: "10.0.20.0/24", description: "MySQL to DB subnet" },
    { protocol: "tcp", port: 53, destination: "10.0.0.2/32", description: "DNS to VPC resolver" },
    { protocol: "udp", port: 53, destination: "10.0.0.2/32", description: "DNS to VPC resolver" },
  ],
};`,
      },
    },
  ],
};
