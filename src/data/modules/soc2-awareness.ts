import type { Module } from '../../types';

export const soc2Awareness: Module = {
    id: 'soc2-awareness',
    title: 'SOC 2 Awareness',
    description: 'Understand SOC 2 audits, the five Trust Service Criteria, and how to prepare your organization for compliance. Essential knowledge for SaaS companies and their vendors.',
    difficulty: 'Intermediate',
    xpReward: 300,
    locked: false,
    lessons: [
        {
            id: 'soc2-overview',
            title: 'SOC 2 Overview',
            type: 'theory',
            content: `
# Mission Briefing: SOC 2

SOC 2 (System and Organization Controls 2) is an auditing framework developed by the American Institute of Certified Public Accountants (AICPA). It evaluates how well an organization safeguards customer data based on five Trust Service Criteria.

Unlike GDPR or HIPAA, SOC 2 is **not a law** -- it's a voluntary audit framework. But in practice, it's become a **de facto requirement** for SaaS companies, cloud providers, and any business that handles customer data. Enterprise customers and procurement teams routinely require a SOC 2 report before signing a contract.

## Type I vs Type II

### SOC 2 Type I
- Evaluates the **design** of controls at a **single point in time**
- "Do you have the right controls in place?"
- Faster and cheaper to obtain (4-8 weeks of prep)
- Good as a first step, but limited value long-term

### SOC 2 Type II
- Evaluates the **design AND operating effectiveness** of controls over a **period of time** (typically 6-12 months)
- "Do your controls actually work, consistently, over time?"
- Much more rigorous -- requires sustained evidence of compliance
- This is what enterprise customers want to see

Think of it like the difference between showing someone your gym membership card (Type I) versus showing them your workout logs for the past year (Type II).

## The 5 Trust Service Criteria (TSC)

### 1. Security (Common Criteria) -- REQUIRED
The foundational criterion -- always included in every SOC 2 audit. Covers protection against unauthorized access, both physical and logical.

**Key controls:**
- Firewalls and intrusion detection
- Multi-factor authentication
- Encryption (at rest and in transit)
- Access control and least privilege
- Vulnerability management
- Incident response procedures

### 2. Availability
Systems are available for operation and use as agreed upon. Not about 100% uptime -- about meeting your SLA commitments.

**Key controls:**
- Disaster recovery and business continuity plans
- Redundancy and failover mechanisms
- Performance monitoring and capacity planning
- Backup procedures and testing
- Incident communication procedures

### 3. Processing Integrity
System processing is complete, valid, accurate, timely, and authorized. Critical for companies that process transactions or perform calculations.

**Key controls:**
- Input validation and data quality checks
- Error handling and correction procedures
- Transaction reconciliation
- Audit trails for data processing
- Change management for processing logic

### 4. Confidentiality
Information designated as confidential is protected as agreed. Applies to any data the organization has committed to keeping confidential (trade secrets, business plans, source code, etc.).

**Key controls:**
- Data classification policies
- Encryption for confidential data
- Non-disclosure agreements
- Secure data disposal
- Access restrictions based on classification

### 5. Privacy
Personal information is collected, used, retained, disclosed, and disposed of in accordance with the organization's privacy notice. Overlaps with GDPR concepts but focused on the organization's own privacy commitments.

**Key controls:**
- Privacy notice and consent management
- Data subject access requests
- Data retention and disposal schedules
- Privacy impact assessments
- Third-party data sharing controls

## Who Needs SOC 2?

SOC 2 is especially important for:

- **SaaS companies** selling to enterprises
- **Cloud service providers** (hosting, infrastructure)
- **Managed service providers** (IT, security, HR)
- **Data processors** (analytics, marketing platforms)
- **Any company** whose customers ask "How do you protect our data?"

## The Audit Process

1. **Readiness Assessment** (2-4 weeks): Gap analysis against TSC criteria
2. **Remediation** (1-6 months): Fix gaps, implement missing controls, gather evidence
3. **Type I Audit** (4-8 weeks): Point-in-time assessment of control design
4. **Observation Period** (6-12 months): Controls operate and evidence accumulates
5. **Type II Audit** (4-8 weeks): Auditor reviews evidence from the observation period
6. **Report Issuance**: CPA firm issues the SOC 2 report
7. **Continuous Compliance**: Maintain controls and prepare for annual re-audit

The report is issued by a licensed CPA firm, not the organization itself. It includes the auditor's opinion, a description of the system, the controls tested, and the results.
            `
        },
        {
            id: 'soc2-quiz-tsc',
            title: 'Trust Service Criteria',
            type: 'quiz',
            content: '',
            quiz: {
                question: "Your SaaS platform processes financial transactions for clients. During a code deployment, a bug causes some transactions to be processed twice, resulting in duplicate charges. Which Trust Service Criterion is MOST directly relevant to this failure?",
                options: [
                    "Security -- because the system allowed unauthorized duplicate transactions",
                    "Availability -- because the system was not functioning correctly during deployment",
                    "Processing Integrity -- because system processing was not complete, valid, and accurate",
                    "Confidentiality -- because transaction data may have been exposed during the error"
                ],
                correctAnswer: 2,
                explanation: "Processing Integrity covers whether system processing is complete, valid, accurate, timely, and authorized. Duplicate transactions are a classic processing integrity failure -- the system processed data inaccurately. While the bug may raise availability concerns, the core issue is that processing produced incorrect results."
            }
        },
        {
            id: 'soc2-practice-theory',
            title: 'SOC 2 in Practice',
            type: 'theory',
            content: `
# Intel Report: SOC 2 in the Real World

## Evidence Collection

SOC 2 audits run on evidence. Auditors don't take your word for it -- they want proof. Here's what you'll need to produce:

### Access Reviews
- **Quarterly access reviews**: Screenshots or exports showing who has access to what, and manager sign-off confirming each person's access is appropriate
- **Onboarding/offboarding logs**: Evidence that access is granted on hire and revoked on departure
- **Privileged access inventory**: List of all admin accounts with justification

### Change Management
- **Pull request history**: PRs with code reviews, approvals, and merge records
- **Deployment logs**: Automated CI/CD pipeline records showing what was deployed, when, and by whom
- **Change approval records**: Evidence that changes were reviewed before production deployment

\`\`\`typescript
// Your CI/CD pipeline IS your change management evidence
// A good pipeline produces SOC 2 evidence automatically:
const deploymentRecord = {
  commitHash: 'a1b2c3d',
  author: 'dev@company.com',
  reviewer: 'lead@company.com',       // PR approval
  approvedAt: '2024-03-15T10:30:00Z',
  deployedAt: '2024-03-15T11:00:00Z',
  environment: 'production',
  pipelineId: 'deploy-12345',          // CI/CD run link
  testsPasseed: true,                   // Automated test evidence
  securityScanPassed: true              // SAST/DAST evidence
};
\`\`\`

### Incident Response
- **Incident tickets**: Documentation of security incidents with timeline, impact, root cause, and remediation
- **Postmortem reports**: Evidence of lessons learned and preventive measures
- **Incident response plan**: Documented procedures, tested at least annually

### Continuous Monitoring
- **Vulnerability scan reports**: Regular scans with evidence of remediation
- **Uptime monitoring dashboards**: SLA compliance evidence (for Availability criterion)
- **Alert configuration**: Evidence that alerts exist for security events

## Vendor Management

Your SOC 2 compliance extends to your vendors. If you use AWS, Stripe, or Datadog, auditors want to see:

- **Vendor inventory**: List of all third-party services that access or process customer data
- **Vendor SOC 2 reports**: Proof your vendors are also SOC 2 compliant (or equivalent)
- **Vendor risk assessments**: Annual reviews of vendor security posture
- **Data processing agreements**: Contracts defining how vendors handle your data

\`\`\`typescript
// Maintain a vendor inventory for audit readiness
const vendorRegistry = [
  {
    name: 'AWS',
    dataAccessed: ['customer data', 'application logs'],
    soc2ReportDate: '2024-01-15',
    soc2Type: 'Type II',
    riskLevel: 'high',           // Hosts core infrastructure
    lastReviewDate: '2024-06-01',
    dpaInPlace: true
  },
  {
    name: 'Stripe',
    dataAccessed: ['payment data'],
    soc2ReportDate: '2024-03-01',
    soc2Type: 'Type II',
    pciDssCompliant: true,
    riskLevel: 'high',
    lastReviewDate: '2024-06-01',
    dpaInPlace: true
  },
  {
    name: 'SendGrid',
    dataAccessed: ['email addresses'],
    soc2ReportDate: '2024-02-15',
    soc2Type: 'Type II',
    riskLevel: 'medium',
    lastReviewDate: '2024-06-01',
    dpaInPlace: true
  }
];
\`\`\`

## Common Controls by Category

### Administrative Controls
- Information security policy (reviewed annually)
- Security awareness training (at hire + annually)
- Background checks for employees
- Risk assessment process (annual)
- Board/management oversight of security

### Technical Controls
- Encryption at rest (AES-256) and in transit (TLS 1.2+)
- Multi-factor authentication for all internal systems
- Centralized logging and SIEM
- Automated vulnerability scanning
- Intrusion detection / prevention systems
- Endpoint detection and response (EDR)

### Operational Controls
- Incident response plan (tested annually via tabletop exercise)
- Business continuity / disaster recovery plan (tested annually)
- Change management process (PR reviews, staging, rollback plans)
- Backup and restoration testing (at least annually)
- Penetration testing (annual, by independent third party)

## Tools That Help

Many companies use compliance automation platforms to streamline SOC 2:

- **Vanta**, **Drata**, **Secureframe**: Continuously monitor controls, collect evidence automatically, and manage the audit process
- These tools integrate with AWS, GitHub, Okta, Jira, etc. to pull evidence automatically
- They don't replace the audit -- they make preparation dramatically easier

## Common Pitfalls

1. **Treating SOC 2 as a one-time project** -- It's an ongoing program. Controls must work every day, not just during audit season.
2. **Starting too late** -- Type II requires 6-12 months of evidence. Start collecting early.
3. **Ignoring vendor risk** -- Your subprocessors are part of your scope.
4. **Documentation gaps** -- If it's not documented, it didn't happen. Auditors need written evidence.
5. **No formal incident response** -- Even if you've never had an incident, you need a documented and tested plan.
            `
        },
        {
            id: 'soc2-quiz-audit',
            title: 'Audit Readiness',
            type: 'quiz',
            content: '',
            quiz: {
                question: "During a SOC 2 Type II audit, the auditor asks for evidence that your access review process is working effectively. Which of the following would be the STRONGEST evidence?",
                options: [
                    "A written access review policy document approved by the CISO",
                    "Screenshots of your IAM dashboard showing current user permissions",
                    "Quarterly access review reports from the past 12 months showing manager approvals, identified issues, and remediation actions taken",
                    "An email from the IT director confirming that access reviews happen regularly"
                ],
                correctAnswer: 2,
                explanation: "SOC 2 Type II evaluates operating effectiveness over time. Quarterly reports spanning the observation period show that the control was consistently applied. A policy (option A) shows design only (Type I). A current screenshot (B) is a point-in-time view. An email assertion (D) is not verifiable evidence. The auditor wants proof of repeated, consistent execution."
            }
        },
        {
            id: 'soc2-lab-gap-assessment',
            title: 'Control Gap Assessment',
            type: 'lab',
            content: 'A startup is preparing for their first SOC 2 audit. Below is their current set of security controls. Your mission: Identify which Trust Service Criteria have gaps by reviewing what controls exist and marking categories as having gaps where critical controls are missing.',
            lab: {
                initialCode: `
// Company: CloudWidget Inc.
// Current security controls inventory
// Review and identify TSC gaps

const currentControls = {
  // What they HAVE implemented:
  encryption: "AES-256 at rest, TLS 1.3 in transit",
  authentication: "SSO via Okta with MFA for all employees",
  codeReview: "All PRs require 1 approval before merge",
  cicd: "GitHub Actions with automated tests",
  monitoring: "Datadog for application performance monitoring",
  logging: "Application logs sent to CloudWatch, retained 30 days",
  firewall: "AWS Security Groups and WAF configured",
  antimalware: "CrowdStrike EDR on all endpoints"
};

// What they are MISSING (not yet implemented):
// - No documented incident response plan
// - No disaster recovery or business continuity plan
// - No backup restoration testing
// - No vendor risk assessment process
// - No formal access review process (quarterly)
// - No security awareness training program
// - No penetration testing performed
// - No data classification policy
// - No privacy notice or consent management
// - No data retention/disposal schedule

// Assess each TSC category:
const gapAssessment = {
  security: {
    hasGap: false,
    existingControls: "",
    missingControls: "",
    riskLevel: ""
  },
  availability: {
    hasGap: false,
    existingControls: "",
    missingControls: "",
    riskLevel: ""
  },
  processingIntegrity: {
    hasGap: false,
    existingControls: "",
    missingControls: "",
    riskLevel: ""
  },
  confidentiality: {
    hasGap: false,
    existingControls: "",
    missingControls: "",
    riskLevel: ""
  },
  privacy: {
    hasGap: false,
    existingControls: "",
    missingControls: "",
    riskLevel: ""
  }
};
`,
                solutionCode: `
const currentControls = {
  encryption: "AES-256 at rest, TLS 1.3 in transit",
  authentication: "SSO via Okta with MFA for all employees",
  codeReview: "All PRs require 1 approval before merge",
  cicd: "GitHub Actions with automated tests",
  monitoring: "Datadog for application performance monitoring",
  logging: "Application logs sent to CloudWatch, retained 30 days",
  firewall: "AWS Security Groups and WAF configured",
  antimalware: "CrowdStrike EDR on all endpoints"
};

const gapAssessment = {
  security: {
    hasGap: true,
    existingControls: "Encryption, MFA/SSO, firewall/WAF, EDR, code review, CI/CD with tests, logging",
    missingControls: "No incident response plan, no penetration testing, no formal access review process, no security awareness training, no vulnerability scanning program",
    riskLevel: "high"
  },
  availability: {
    hasGap: true,
    existingControls: "Application performance monitoring (Datadog), firewall/WAF for DDoS protection",
    missingControls: "No disaster recovery plan, no business continuity plan, no backup restoration testing, no documented SLAs or uptime commitments",
    riskLevel: "critical"
  },
  processingIntegrity: {
    hasGap: true,
    existingControls: "CI/CD with automated tests, code review process",
    missingControls: "No formal change management documentation, no transaction reconciliation, no input validation standards, log retention only 30 days (should be 12 months)",
    riskLevel: "medium"
  },
  confidentiality: {
    hasGap: true,
    existingControls: "Encryption at rest and in transit, access control via Okta SSO",
    missingControls: "No data classification policy, no vendor risk assessment process, no formal access review process, no secure data disposal procedures",
    riskLevel: "high"
  },
  privacy: {
    hasGap: true,
    existingControls: "Encryption protects personal data in transit and at rest",
    missingControls: "No privacy notice or consent management, no data retention/disposal schedule, no data subject access request process, no privacy impact assessments, no vendor data processing agreements",
    riskLevel: "critical"
  }
};
`,
                instructions: "For each of the 5 Trust Service Criteria: 1) Set hasGap to true or false, 2) List which existing controls from the inventory apply to that category, 3) Identify which missing controls are relevant to that category, 4) Assign a riskLevel of 'low', 'medium', 'high', or 'critical'. All 5 categories have gaps given the missing controls listed above."
            }
        }
    ]
};
