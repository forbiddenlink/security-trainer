import type { Module } from "../../types";

export const incidentResponse: Module = {
  id: "incident-response",
  title: "Incident Response",
  description:
    "Master the art of responding to security incidents — from detection through recovery and lessons learned.",
  difficulty: "Advanced",
  xpReward: 450,
  locked: false,
  lessons: [
    {
      id: "ir-framework-theory",
      title: "Incident Response Framework",
      type: "theory",
      content: `# Incident Response Framework

## Why Incident Response Matters

Every organization will face a security incident. The difference between a contained breach and a catastrophe comes down to preparation. An IR framework turns chaos into a repeatable, measurable process.

> "Everyone has a plan until they get punched in the mouth." — Mike Tyson
>
> In IR, the plan IS the punch back.

## NIST SP 800-61: The Gold Standard

The NIST Computer Security Incident Handling Guide defines four phases:

### Phase 1: Preparation
- **IR Team**: Assemble a cross-functional team (security, engineering, legal, communications, executive sponsor)
- **IR Plan**: Document roles, communication channels, escalation paths, and authority to act
- **Tooling**: Deploy SIEM, EDR, forensic workstations, isolated analysis networks
- **Playbooks**: Pre-written response procedures for common scenarios (ransomware, data breach, insider threat, DDoS)
- **Tabletop Exercises**: Regular simulated incidents to test readiness
- **Contact Lists**: Legal counsel, law enforcement (FBI IC3, CISA), cyber insurance carrier, PR firm

### Phase 2: Detection & Analysis
- Monitor alerts from SIEM, IDS/IPS, EDR, and user reports
- Correlate indicators of compromise (IoCs) across data sources
- Classify severity (P1-P4) and determine scope
- Document everything in an incident ticket from minute one

### Phase 3: Containment, Eradication & Recovery
- **Short-term containment**: Isolate affected systems immediately (network segmentation, disable accounts)
- **Evidence preservation**: Forensic images before any remediation
- **Long-term containment**: Patch vulnerabilities, rotate credentials
- **Eradication**: Remove malware, close backdoors, eliminate root cause
- **Recovery**: Restore from clean backups, validate system integrity, monitor for re-infection

### Phase 4: Post-Incident Activity
- Blameless retrospective within 72 hours
- Update playbooks and detection rules
- Document timeline, decisions made, and outcomes
- Report to regulators if required

## SANS 6-Step Framework

SANS breaks IR into six discrete steps:

1. **Preparation** — Same as NIST: people, processes, tools
2. **Identification** — Determine if an event is actually an incident
3. **Containment** — Stop the bleeding (short-term and long-term)
4. **Eradication** — Remove the threat actor's presence entirely
5. **Recovery** — Return to normal operations with confidence
6. **Lessons Learned** — What happened, why, and how do we improve?

The key difference: SANS separates Identification from Detection/Analysis, emphasizing the triage decision of "is this real?"

## Building an IR Team

| Role | Responsibility |
|------|---------------|
| **Incident Commander** | Owns the response, makes decisions, coordinates |
| **Technical Lead** | Directs investigation and remediation |
| **Communications Lead** | Internal/external messaging, media, regulators |
| **Legal Counsel** | Privilege, regulatory obligations, law enforcement |
| **Executive Sponsor** | Authority to approve budget, downtime, disclosure |
| **Scribe** | Documents every action, decision, and timestamp |

## IR Plan Essentials

A usable IR plan must include:
- **Incident classification matrix** (what qualifies as P1 vs P4)
- **Communication tree** with backup contacts
- **Authority matrix** (who can isolate production, notify customers, engage law enforcement)
- **Evidence handling procedures** (chain of custody)
- **Regulatory notification requirements** by jurisdiction
- **Vendor contact info** (cloud providers, CDN, DNS, cyber insurance)

## Real-World Case: Equifax Breach (2017)

### Timeline
- **March 7**: Apache Struts vulnerability (CVE-2017-5638) disclosed
- **March 8**: US-CERT alert issued
- **March 9**: Equifax security team notified — **patch not applied**
- **May 13**: Attackers begin exploiting the vulnerability
- **July 29**: Equifax discovers the breach (76 days later)
- **July 30**: CEO notified
- **September 7**: Public disclosure (143 million people affected)

### What Went Wrong
- Known vulnerability left unpatched for 145 days
- SSL certificate for inspection tool had expired — exfiltration went undetected
- No network segmentation between web-facing and database systems
- Dispute portal stored data unencrypted

### IR Failures
- Delayed detection (76 days of active exploitation)
- Delayed public notification (40 days after discovery)
- Response website was itself vulnerable and nearly phished by a parody site

## Real-World Case: SolarWinds (2020)

### Timeline
- **September 2019**: Attackers gain access to SolarWinds build environment
- **February 2020**: Trojanized Orion update (SUNBURST) deployed to ~18,000 customers
- **December 8, 2020**: FireEye discloses theft of red team tools, begins investigation
- **December 13, 2020**: SolarWinds discloses supply chain compromise

### What Made This Exceptional
- **Supply chain attack**: Malicious code inserted into legitimate software updates
- **Sophistication**: SUNBURST checked for analysis environments, delayed execution by 2 weeks
- **Scope**: US Treasury, Commerce, Homeland Security, and Fortune 500 companies compromised
- **Attribution**: Russian SVR (APT29/Cozy Bear)

### IR Lessons
- Detection came from a secondary indicator (FireEye red team tool theft)
- Build pipeline integrity is critical
- Software Bill of Materials (SBOM) became a national security priority
- Executive Order 14028 mandated federal cybersecurity improvements`,
    },
    {
      id: "ir-phase-quiz",
      title: "Quiz: IR Phase Identification",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "Your SOC detects unusual outbound traffic from a database server at 2 AM. After confirming it's not a scheduled backup, you isolate the server from the network and take a forensic image of the disk. Which IR phase are you currently in?",
        options: [
          "Preparation — you're testing your incident response plan",
          "Detection & Analysis — you're still investigating the alert",
          "Containment — you've isolated the system and preserved evidence",
          "Recovery — you're restoring the server from backup",
        ],
        correctAnswer: 2,
        explanation:
          "Isolating the affected system from the network is short-term containment, and taking a forensic image is evidence preservation — both are Containment phase activities. Detection & Analysis concluded when you confirmed the traffic was not legitimate. You haven't begun eradication or recovery yet.",
      },
    },
    {
      id: "ir-detection-theory",
      title: "Detection & Triage",
      type: "theory",
      content: `# Detection & Triage

## Indicators of Compromise (IoCs)

IoCs are forensic evidence that a security incident may have occurred. They're the breadcrumbs attackers leave behind.

### Network-Based IoCs
- Unusual outbound traffic (especially to known C2 servers)
- DNS queries to suspicious domains (DGA-generated names)
- Beaconing patterns (regular intervals of small outbound requests)
- Large data transfers outside business hours
- Traffic to countries with no business relationship
- Unexpected protocol usage (DNS tunneling, ICMP exfiltration)

### Host-Based IoCs
- Unknown processes or services running
- Modified system binaries or configuration files
- Unexpected scheduled tasks or cron jobs
- Registry modifications (Windows persistence mechanisms)
- Unusual file system changes (encrypted files, new executables)
- Anti-forensic artifacts (cleared event logs, timestomping)

### Account-Based IoCs
- Login from impossible geographies ("impossible travel")
- Privilege escalation or new admin accounts
- Service account interactive logins
- Mass password resets or credential changes
- Access to resources outside normal role

### Application-Based IoCs
- SQL injection patterns in web logs
- Unusual API call patterns or volumes
- Application errors indicating exploitation attempts
- Unexpected configuration changes

## SIEM Alert Correlation

A single alert rarely tells the full story. SIEM correlation connects the dots:

\`\`\`
Alert 1: Failed SSH login (5x in 1 min) → IP 203.0.113.50
Alert 2: Successful SSH login              → IP 203.0.113.50 → user: admin
Alert 3: New cron job created              → user: admin
Alert 4: Outbound connection to 198.51.100.77 (known C2)

Correlated: Brute force → Compromise → Persistence → C2 Communication
Severity: CRITICAL (P1)
\`\`\`

Without correlation, Alert 1 alone is low-priority. Together, they paint a clear attack narrative.

## Log Sources for Detection

| Source | What It Reveals |
|--------|----------------|
| **Firewall/IDS** | Network attacks, C2 communication, lateral movement |
| **Web Application Firewall** | SQLi, XSS, path traversal, bot activity |
| **Authentication Logs** | Brute force, credential stuffing, impossible travel |
| **DNS Logs** | C2 domains, DGA, data exfiltration via DNS |
| **Endpoint Detection (EDR)** | Malware execution, file changes, process injection |
| **Cloud Audit Logs** | API abuse, IAM changes, resource exfiltration |
| **Email Gateway** | Phishing, malicious attachments, BEC |

## Threat Classification (P1-P4)

### P1 — Critical
- Active data exfiltration in progress
- Ransomware spreading across network
- Compromise of authentication infrastructure (Active Directory, SSO)
- Production system integrity compromised

**Response**: All hands on deck. Incident Commander activated. 15-minute status updates.

### P2 — High
- Confirmed unauthorized access to sensitive systems
- Successful phishing with credential compromise
- Malware detected on multiple endpoints
- Vulnerability actively being exploited

**Response**: IR team assembled. 30-minute status updates. Business leadership notified.

### P3 — Medium
- Single endpoint malware (contained)
- Unauthorized access attempt (unsuccessful)
- Suspicious but unconfirmed activity
- Policy violation with security implications

**Response**: Assigned to security analyst. 4-hour SLA for initial assessment.

### P4 — Low
- Informational alerts (port scans, vulnerability scan noise)
- Minor policy violations
- False positive investigation

**Response**: Queued for review. 24-hour SLA.

## Escalation Criteria

Escalate immediately when:
- Scope expands beyond initial assessment
- Sensitive data (PII, financial, health) is confirmed involved
- Attacker shows signs of persistence (backdoors, new accounts)
- Multiple systems or business units affected
- Legal or regulatory notification may be required
- Media attention is likely

## False Positive Management

False positives are the bane of SOC analysts. Reducing them requires:

1. **Tuning**: Adjust alert thresholds based on baseline behavior
2. **Whitelisting**: Exclude known-good activity (scheduled scans, automated deployments)
3. **Enrichment**: Automatically add context (threat intel, asset criticality, user role)
4. **Feedback loops**: Analysts mark false positives, ML models learn
5. **Tiered review**: Low-confidence alerts go to automated triage first`,
    },
    {
      id: "ir-threat-classification-quiz",
      title: "Quiz: Threat Classification",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "An analyst receives three alerts: (1) A new admin account was created at 3 AM, (2) the account accessed the customer database, (3) a 2GB file was uploaded to an external cloud storage service. How should this be classified?",
        options: [
          "P4 — Informational, could be a developer working late",
          "P3 — Medium, assign to an analyst for review within 4 hours",
          "P2 — High, likely unauthorized access requiring IR team assembly",
          "P1 — Critical, active data exfiltration requiring immediate all-hands response",
        ],
        correctAnswer: 3,
        explanation:
          "The combination of unauthorized admin account creation, database access, and large outbound data transfer strongly indicates active data exfiltration — a P1 Critical incident. Each alert alone might be lower severity, but correlated they indicate a breach in progress. Waiting 4 hours (P3) or treating this as informational (P4) could allow the attacker to exfiltrate the entire database.",
      },
    },
    {
      id: "ir-containment-theory",
      title: "Containment & Eradication",
      type: "theory",
      content: `# Containment & Eradication

## The Containment Dilemma

You've confirmed a breach. Now you face a critical decision:

> **Act too fast**: You alert the attacker, who destroys evidence or detonates ransomware.
> **Act too slow**: The attacker exfiltrates more data or expands their foothold.

The answer is **planned containment** — decisive action based on evidence, not panic.

## Short-Term Containment

Goal: Stop the immediate threat while preserving evidence.

### Actions (minutes to hours)
- **Network isolation**: Remove compromised systems from the network (disable switch ports, modify firewall rules, move to quarantine VLAN)
- **Account lockout**: Disable compromised accounts, force password resets for affected scope
- **Block IoCs**: Add malicious IPs, domains, and file hashes to blocklists
- **Disable remote access**: Revoke VPN tokens, disable RDP if lateral movement suspected
- **DNS sinkhole**: Redirect C2 domains to internal sinkhole

\`\`\`bash
# Example: Immediate network isolation
# Firewall rule to quarantine compromised host
iptables -I FORWARD -s 10.0.5.42 -j DROP
iptables -I FORWARD -d 10.0.5.42 -j DROP

# Allow only forensic workstation access
iptables -I FORWARD -s 10.0.100.10 -d 10.0.5.42 -j ACCEPT
\`\`\`

### What NOT to do during short-term containment
- Don't power off systems (volatile memory evidence lost)
- Don't reimage immediately (need forensic image first)
- Don't confront the suspected insider (legal and HR first)
- Don't communicate on compromised channels (assume email may be monitored)

## Evidence Preservation

Evidence must be collected in order of volatility (most volatile first):

1. **CPU registers and cache** (nanoseconds)
2. **RAM / running processes** (lost on power-off)
3. **Network connections** (active sessions, routing tables)
4. **Disk** (files, logs, swap space)
5. **Backup media** (tape, cloud snapshots)

### Chain of Custody

Every piece of evidence requires documentation:

\`\`\`
Evidence ID: EV-2024-001
Description: Forensic image of web server (prod-web-03)
Collected by: J. Smith, Senior Analyst
Date/Time: 2024-01-15 14:32 UTC
Method: dd if=/dev/sda | sha256sum > image.hash
Hash (SHA-256): a3f2b8c9d1e4...
Storage: Evidence locker B, shelf 3
Transfer log:
  - 2024-01-15 14:32 → J. Smith (collection)
  - 2024-01-15 16:00 → Evidence locker (storage)
  - 2024-01-17 09:00 → M. Garcia (analysis)
\`\`\`

Breaking chain of custody can render evidence inadmissible in legal proceedings.

## Long-Term Containment

Goal: Allow business operations to continue while fully remediating the threat.

### Actions (hours to days)
- Stand up parallel clean systems if production must continue
- Apply patches that address the exploited vulnerability
- Implement additional monitoring on contained systems
- Rotate ALL credentials in the affected environment (not just confirmed compromised ones)
- Review and restrict service account permissions
- Enable enhanced logging on high-value targets

## Eradication

Goal: Remove every trace of the attacker's presence.

### Common Eradication Actions
- Remove malware, backdoors, and webshells
- Delete unauthorized accounts and SSH keys
- Rebuild compromised systems from known-clean images
- Patch all instances of the exploited vulnerability
- Revoke and re-issue certificates if CA was compromised
- Clean or rebuild Active Directory if domain compromise occurred

### Root Cause Analysis

Eradication is incomplete without understanding HOW the attacker got in:

\`\`\`
Root Cause Analysis — Incident INC-2024-042

Initial Access: Spear-phishing email with malicious Excel macro
  → Targeted: Finance department (3 recipients)
  → Clicked by: 1 user (accounts payable)

Exploitation: Macro executed PowerShell downloader
  → Downloaded Cobalt Strike beacon
  → Established C2 to 198.51.100.77

Persistence: Scheduled task + registry run key
  → HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdateSvc

Lateral Movement: Pass-the-hash using cached domain admin creds
  → Domain controller accessed within 4 hours

Root Cause: Lack of macro execution policies + cached privileged credentials on workstations
\`\`\`

## Common Mistakes in Containment & Eradication

1. **Partial eradication**: Removing malware from 9 of 10 infected hosts
2. **Tipping off the attacker**: Blocking one C2 domain when they have five
3. **Credential rotation gaps**: Resetting user passwords but not service accounts
4. **Rebuilding without patching**: Reimaging from a backup that has the same vulnerability
5. **Premature all-clear**: Declaring the incident over before confirming eradication`,
    },
    {
      id: "ir-recovery-theory",
      title: "Recovery & Post-Incident",
      type: "theory",
      content: `# Recovery & Post-Incident Activity

## System Restoration

Recovery is not just "turn it back on." It requires validation and monitoring.

### Recovery Steps

1. **Validate clean state**: Confirm rebuilt/restored systems are free of compromise
2. **Staged reconnection**: Bring systems back online in phases, not all at once
3. **Enhanced monitoring**: Increase logging verbosity and alert sensitivity for 30-90 days
4. **User validation**: Confirm legitimate users can access systems (credential resets may cause lockouts)
5. **Business validation**: Verify application functionality, data integrity, and integrations

### Monitoring for Re-infection

The attacker may have additional access vectors you haven't found. Watch for:
- Same IoCs reappearing (C2 domains, file hashes, behavioral patterns)
- New IoCs that match the attacker's TTPs (Tactics, Techniques, Procedures)
- Anomalous activity from previously compromised accounts
- Unexpected changes to systems that were remediated

\`\`\`typescript
// Post-incident enhanced monitoring rule
const enhancedMonitoring = {
  duration: '90_days',
  targets: ['prod-web-*', 'prod-db-*', 'corp-dc-*'],
  rules: [
    { name: 'known_c2', type: 'network', iocs: ['198.51.100.77', '*.evil.example'] },
    { name: 'new_admin', type: 'account', pattern: 'admin account created' },
    { name: 'large_transfer', type: 'network', threshold: '500MB outbound' },
    { name: 'off_hours', type: 'access', pattern: 'login between 00:00-05:00' },
  ],
  alertLevel: 'P2', // Elevated from normal P3
};
\`\`\`

## Post-Incident Retrospective

### Blameless Retrospective

The goal is to improve systems and processes, not assign blame. Blame creates silence; silence creates repeat incidents.

**Format:**
1. **Timeline reconstruction** (what happened, when, in sequence)
2. **What went well** (what worked in the response)
3. **What could be improved** (gaps in detection, process, tooling)
4. **Action items** with owners and deadlines
5. **Metrics** (time to detect, time to contain, time to recover)

### Key IR Metrics

| Metric | Definition | Target |
|--------|-----------|--------|
| **MTTD** (Mean Time to Detect) | Time from compromise to detection | < 24 hours |
| **MTTC** (Mean Time to Contain) | Time from detection to containment | < 4 hours |
| **MTTR** (Mean Time to Recover) | Time from containment to full recovery | < 48 hours |
| **MTTI** (Mean Time to Investigate) | Time spent in analysis phase | Minimize |

### Updating Playbooks

Every incident should result in at least one playbook update:

- New detection rules for observed IoCs and TTPs
- Updated escalation criteria based on what was missed
- Revised communication templates
- New or modified automation for common containment actions
- Training gaps identified and addressed

## Legal & Regulatory Notification Requirements

### GDPR (European Union)
- **Timeline**: 72 hours from discovery to supervisory authority
- **Scope**: Any breach involving personal data of EU residents
- **Penalties**: Up to 4% of annual global revenue or EUR 20 million
- **Individual Notification**: Required when breach likely results in high risk to individuals

### HIPAA (United States — Healthcare)
- **Timeline**: 60 days from discovery to HHS and affected individuals
- **Scope**: Unsecured protected health information (PHI)
- **Penalties**: $100 to $50,000 per violation, up to $1.5M per year per category
- **Breach of 500+**: Must notify media in affected state(s)

### State Breach Notification Laws (United States)
- **All 50 states** have breach notification laws (varying requirements)
- **Timeline**: Ranges from "most expedient time possible" to specific day counts (30-90 days)
- **California (CCPA/CPRA)**: Private right of action for data breaches, statutory damages $100-$750 per consumer
- **New York (SHIELD Act)**: Expanded definition of private information, requires "reasonable security"

### PCI DSS (Payment Card Industry)
- **Timeline**: Immediately notify acquiring bank and card brands
- **Scope**: Any breach involving cardholder data
- **Consequence**: Fines, increased transaction fees, loss of ability to process cards
- **Forensic Investigation**: Must use PCI Forensic Investigator (PFI)

### SEC Requirements (United States — Public Companies)
- **Timeline**: Material cybersecurity incidents must be disclosed on Form 8-K within 4 business days
- **Scope**: Incidents that are material to investors
- **Annual Reporting**: Describe cybersecurity risk management in annual 10-K

## Documentation Requirements

Every incident file should contain:
1. Incident ticket with complete timeline
2. Evidence inventory with chain of custody
3. Communication logs (internal and external)
4. Forensic analysis reports
5. Remediation actions taken
6. Post-incident retrospective document
7. Regulatory notifications sent (with receipts)
8. Legal hold notices if applicable`,
    },
    {
      id: "ir-simulation-lab",
      title: "Lab: Incident Response Simulation",
      type: "lab",
      content: "",
      lab: {
        instructions:
          "You are the Incident Commander. Review the breach timeline below and complete the incident response plan by filling in the containment, eradication, and recovery steps. Each step should be a specific, actionable instruction — not vague guidance. Think about evidence preservation, scope of compromise, and regulatory requirements.",
        initialCode: `// BREACH TIMELINE — Operation Midnight Falcon
// Your organization's SOC has detected a security incident.
// Review the events and complete the response plan below.

const breachTimeline = [
  { time: "2024-01-15 02:14 UTC", event: "Failed SSH logins (47x) from IP 203.0.113.50 targeting admin accounts" },
  { time: "2024-01-15 02:31 UTC", event: "Successful SSH login as 'deploy-svc' from IP 203.0.113.50" },
  { time: "2024-01-15 02:45 UTC", event: "New cron job created: reverse shell to 198.51.100.77 every 5 min" },
  { time: "2024-01-15 03:12 UTC", event: "Database export initiated: customers table (2.3M records with PII)" },
  { time: "2024-01-15 03:18 UTC", event: "Outbound transfer of 1.8GB to external cloud storage (198.51.100.77)" },
  { time: "2024-01-15 08:00 UTC", event: "SOC analyst notices anomalous outbound traffic alert from overnight" },
  { time: "2024-01-15 08:15 UTC", event: "Incident declared — you are the Incident Commander" },
];

// YOUR TASK: Complete the incident response plan
const incidentResponsePlan = {

  // Classification: What severity level is this incident?
  classification: "", // Fill in: P1, P2, P3, or P4 and why

  // PHASE 1: Containment (immediate actions to stop the bleeding)
  shortTermContainment: [
    // Add specific containment steps
    // Think: network, accounts, attacker C2, evidence
  ],

  // PHASE 2: Eradication (remove attacker's presence)
  eradication: [
    // Add specific eradication steps
    // Think: backdoors, credentials, root cause
  ],

  // PHASE 3: Recovery (restore normal operations)
  recovery: [
    // Add specific recovery steps
    // Think: restoration, validation, monitoring
  ],

  // PHASE 4: Notifications (who must be told and by when?)
  notifications: [
    // Add specific notification requirements
    // Think: 2.3M customer PII records were exfiltrated
  ],
};`,
        solutionCode: `// BREACH TIMELINE — Operation Midnight Falcon
const breachTimeline = [
  { time: "2024-01-15 02:14 UTC", event: "Failed SSH logins (47x) from IP 203.0.113.50 targeting admin accounts" },
  { time: "2024-01-15 02:31 UTC", event: "Successful SSH login as 'deploy-svc' from IP 203.0.113.50" },
  { time: "2024-01-15 02:45 UTC", event: "New cron job created: reverse shell to 198.51.100.77 every 5 min" },
  { time: "2024-01-15 03:12 UTC", event: "Database export initiated: customers table (2.3M records with PII)" },
  { time: "2024-01-15 03:18 UTC", event: "Outbound transfer of 1.8GB to external cloud storage (198.51.100.77)" },
  { time: "2024-01-15 08:00 UTC", event: "SOC analyst notices anomalous outbound traffic alert from overnight" },
  { time: "2024-01-15 08:15 UTC", event: "Incident declared — you are the Incident Commander" },
];

const incidentResponsePlan = {

  classification: "P1 — Critical: Active data exfiltration confirmed. 2.3M customer PII records stolen. Attacker has persistent access via cron-based reverse shell.",

  shortTermContainment: [
    "Isolate the compromised server from the network immediately (quarantine VLAN or firewall deny-all)",
    "Block outbound traffic to 198.51.100.77 and 203.0.113.50 at the perimeter firewall",
    "Disable the 'deploy-svc' account across all systems",
    "Take forensic memory dump of the compromised server before any changes",
    "Create forensic disk image with SHA-256 hash for chain of custody",
    "Kill the active reverse shell process and remove the malicious cron job",
    "Block the attacker's IP ranges at DNS and network level",
    "Preserve all SSH, database, and network logs from the past 30 days",
  ],

  eradication: [
    "Rotate ALL service account credentials, not just deploy-svc",
    "Audit all cron jobs and scheduled tasks across the server fleet",
    "Check for additional backdoors: SSH authorized_keys, web shells, startup scripts",
    "Scan all servers for IoCs: connections to 198.51.100.77, files modified after 02:30 UTC",
    "Patch or reconfigure SSH: disable password auth, enforce key-based with MFA",
    "Rebuild the compromised server from a known-clean image",
    "Review and restrict network segmentation between app and database tiers",
    "Conduct root cause analysis: how did deploy-svc have SSH access with weak credentials?",
  ],

  recovery: [
    "Restore the server from a verified clean backup predating the compromise",
    "Validate database integrity — confirm no records were modified or deleted",
    "Deploy enhanced monitoring: alert on any connection to known attacker IPs",
    "Implement 90-day enhanced monitoring with P2 alert escalation",
    "Conduct staged reconnection: database first, then application tier",
    "Verify all legitimate users can access systems after credential rotation",
    "Run vulnerability scan on all systems in the affected network segment",
    "Schedule tabletop exercise within 30 days to review lessons learned",
  ],

  notifications: [
    "Legal team: Engage immediately for breach counsel and privilege",
    "GDPR: Notify supervisory authority within 72 hours if EU residents affected",
    "State breach notification: Notify affected individuals per applicable state laws (30-90 days)",
    "Affected customers: Prepare notification with credit monitoring offer",
    "Cyber insurance carrier: Notify per policy requirements",
    "Board/executives: Brief within 4 hours of incident declaration",
    "Law enforcement: File report with FBI IC3 for potential prosecution",
    "SEC (if public company): Assess materiality for 8-K filing within 4 business days",
  ],
};`,
      },
    },
  ],
};
