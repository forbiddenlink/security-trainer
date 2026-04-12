import type { Module } from '../../types';

export const hipaaBasics: Module = {
    id: 'hipaa-basics',
    title: 'HIPAA Basics',
    description: 'Learn the Health Insurance Portability and Accountability Act -- the US law protecting health information. Understand PHI, covered entities, safeguards, and what HIPAA compliance means for developers building healthcare applications.',
    difficulty: 'Intermediate',
    xpReward: 350,
    locked: false,
    lessons: [
        {
            id: 'hipaa-overview',
            title: 'HIPAA Overview',
            type: 'theory',
            content: `
# Mission Briefing: HIPAA

The Health Insurance Portability and Accountability Act (HIPAA) is a US federal law enacted in 1996 that establishes national standards for protecting sensitive health information. If your software touches health data in any way, HIPAA likely applies to you.

## Who Must Comply?

### Covered Entities
Organizations that directly handle health information:
- **Health plans** (insurance companies, HMOs, Medicare, Medicaid)
- **Healthcare providers** (hospitals, clinics, doctors, pharmacies, dentists) who transmit health information electronically
- **Healthcare clearinghouses** (entities that process nonstandard health information into standard formats)

### Business Associates
Any organization that performs services for a covered entity and has access to Protected Health Information (PHI):
- Cloud hosting providers storing health data
- Software companies building healthcare applications
- IT consultants with access to health systems
- Billing companies, law firms, accountants
- Analytics platforms processing health data

**If you're a developer building a healthcare app, you are almost certainly a Business Associate.**

## What is Protected Health Information (PHI)?

PHI is any individually identifiable health information that is created, received, maintained, or transmitted by a covered entity or business associate. It includes:

### The 18 HIPAA Identifiers

Any health information combined with any of these identifiers is PHI:

1. **Names**
2. **Geographic data** (anything smaller than a state)
3. **Dates** (except year) related to an individual -- birth date, admission date, discharge date, date of death
4. **Phone numbers**
5. **Fax numbers**
6. **Email addresses**
7. **Social Security numbers**
8. **Medical record numbers**
9. **Health plan beneficiary numbers**
10. **Account numbers**
11. **Certificate/license numbers**
12. **Vehicle identifiers** (VIN, license plate)
13. **Device identifiers and serial numbers**
14. **Web URLs**
15. **IP addresses**
16. **Biometric identifiers** (fingerprints, voiceprints)
17. **Full-face photographs**
18. **Any other unique identifying number or code**

### ePHI (Electronic PHI)
PHI that is created, stored, maintained, or transmitted electronically. This is the primary concern for developers and is governed by the HIPAA Security Rule.

## The Minimum Necessary Rule

One of HIPAA's core principles: covered entities and business associates must make reasonable efforts to limit PHI access and disclosure to the **minimum necessary** to accomplish the intended purpose.

\`\`\`typescript
// BAD: Returning full patient record when only name is needed
app.get('/api/appointment/:id', (req, res) => {
  const patient = db.patients.findById(req.params.id);
  res.json(patient); // Returns SSN, full medical history, insurance, etc.
});

// GOOD: Return only what's needed for the appointment view
app.get('/api/appointment/:id', (req, res) => {
  const patient = db.patients.findById(req.params.id);
  res.json({
    name: patient.name,
    appointmentDate: patient.nextAppointment,
    provider: patient.assignedProvider
    // No SSN, no diagnosis, no insurance details
  });
});
\`\`\`

## Case Files: HIPAA Enforcement Actions

**Anthem Inc. (2015) -- $16 million settlement (largest HIPAA settlement ever):**
A cyberattack exposed the ePHI of nearly 79 million people -- names, dates of birth, Social Security numbers, healthcare IDs, addresses, and employment information. The HHS investigation found that Anthem failed to conduct an enterprise-wide risk analysis, had insufficient access controls, and lacked adequate security monitoring. The attackers gained access through a spear-phishing email.

**UCLA Health System (2015) -- $865,000 settlement:**
Unauthorized employees repeatedly accessed celebrity medical records out of curiosity. UCLA failed to implement adequate access controls and audit mechanisms. This case established that HIPAA violations don't require external hackers -- insider threats from authorized users accessing records without a legitimate purpose are equally serious.

**Premera Blue Cross (2019) -- $6.85 million settlement:**
A breach affecting 10.4 million individuals went undetected for 9 months. Attackers gained access through a phishing email and installed malware. HHS found that Premera failed to conduct a thorough risk analysis and failed to implement sufficient security measures to reduce risks and vulnerabilities.

**Banner Health (2023) -- $1.25 million settlement:**
A 2016 breach affecting 2.81 million individuals. Attackers gained access to food and beverage point-of-sale systems, then pivoted to health data systems. HHS cited failure to conduct an accurate and thorough risk analysis and failure to implement adequate audit controls.

**Montefiore Medical Center (2024) -- $4.75 million settlement:**
An employee stole patient data over 6 months, affecting 12,517 patients. The investigation revealed inadequate monitoring and access controls -- the hospital failed to regularly review audit logs that would have detected the unauthorized access patterns.
            `
        },
        {
            id: 'hipaa-quiz-phi',
            title: 'Is This PHI?',
            type: 'quiz',
            content: '',
            quiz: {
                question: "A research database contains the following record: 'Patient diagnosed with Type 2 Diabetes, Age 45, State: California, Year of Birth: 1979.' No other identifiers are present. Is this PHI under HIPAA?",
                options: [
                    "Yes -- any health information is automatically PHI",
                    "Yes -- the combination of age, state, diagnosis, and birth year could identify someone",
                    "No -- there are no HIPAA identifiers present since state-level geography and year-only dates are permitted under Safe Harbor de-identification",
                    "No -- research data is always exempt from HIPAA"
                ],
                correctAnswer: 2,
                explanation: "Under the Safe Harbor de-identification method (45 CFR 164.514(b)), geographic data at the state level is permitted (only sub-state data is an identifier), and dates can include the year as long as the individual is not 90+ years old. With no names, no specific dates (only birth year), and no other identifiers present, this data meets Safe Harbor criteria and is not PHI. However, if the combination of age + state + diagnosis could narrow to a very small population, an Expert Determination analysis might reach a different conclusion."
            }
        },
        {
            id: 'hipaa-safeguards-theory',
            title: 'HIPAA Security & Privacy Rules',
            type: 'theory',
            content: `
# Intel Report: HIPAA Security & Privacy Rules

HIPAA has two main rules developers need to understand: the **Privacy Rule** (governs use and disclosure of PHI) and the **Security Rule** (governs protection of ePHI). The Security Rule requires three categories of safeguards.

## Administrative Safeguards (Section 164.308)

Policies and procedures to manage the selection, development, implementation, and maintenance of security measures.

### Required Specifications:
- **Risk Analysis:** Conduct an accurate and thorough assessment of potential risks to ePHI. This is the #1 thing HHS cites in enforcement actions.
- **Risk Management:** Implement security measures to reduce risks to reasonable levels
- **Sanction Policy:** Apply appropriate sanctions against employees who violate security policies
- **Information System Activity Review:** Regularly review audit logs, access reports, and security incident tracking
- **Security Officer:** Designate a security official responsible for developing and implementing policies
- **Workforce Training:** Train all employees on security policies and procedures
- **Contingency Plan:** Establish data backup, disaster recovery, and emergency operations plans

## Physical Safeguards (Section 164.310)

Physical measures to protect electronic systems and equipment from natural and environmental hazards and unauthorized intrusion.

### Required Specifications:
- **Facility Access Controls:** Limit physical access to facilities containing ePHI
- **Workstation Use:** Specify proper functions and physical attributes of workstations
- **Workstation Security:** Physical safeguards restricting access to workstations
- **Device and Media Controls:** Policies for disposal, re-use, and movement of hardware containing ePHI

\`\`\`typescript
// For cloud-hosted applications, physical safeguards are largely
// handled by your cloud provider -- but you need documentation:
const physicalSafeguards = {
  cloudProvider: 'AWS',
  baaInPlace: true,                    // BAA signed with AWS
  dataRegions: ['us-east-1', 'us-west-2'],
  physicalSecurityCertifications: [
    'SOC 2 Type II',
    'ISO 27001',
    'FedRAMP'
  ],
  mediaDisposal: 'AWS handles per BAA terms',
  localDevices: {
    fullDiskEncryption: true,          // FileVault / BitLocker
    screenLockTimeout: '5 minutes',
    remoteWipeCapability: true
  }
};
\`\`\`

## Technical Safeguards (Section 164.312)

Technology and related policies and procedures to protect ePHI and control access.

### Required Specifications:
- **Access Control:** Unique user identification, emergency access procedures, automatic logoff, encryption
- **Audit Controls:** Hardware, software, and procedural mechanisms to record and examine access to ePHI
- **Integrity Controls:** Policies to protect ePHI from improper alteration or destruction
- **Person or Entity Authentication:** Verify the identity of anyone seeking access to ePHI
- **Transmission Security:** Protect ePHI during electronic transmission (encryption)

\`\`\`typescript
// Technical safeguards checklist for a healthcare application
const technicalSafeguards = {
  accessControl: {
    uniqueUserIds: true,              // No shared accounts
    roleBasedAccess: true,            // RBAC with least privilege
    mfa: true,                        // MFA for all users
    autoLogoff: '15 minutes',         // Session timeout
    emergencyAccess: 'break-glass procedure documented'
  },
  auditControls: {
    accessLogging: true,              // Log every access to ePHI
    logRetention: '6 years',          // HIPAA requires 6 years for policies
    logTampering: 'immutable storage',// Prevent log modification
    regularReview: 'monthly'          // Review audit logs regularly
  },
  encryption: {
    atRest: 'AES-256',
    inTransit: 'TLS 1.2+',
    keyManagement: 'AWS KMS with rotation'
  },
  authentication: {
    passwordPolicy: 'NIST 800-63B compliant',
    mfaMethod: 'TOTP or FIDO2',
    sessionManagement: 'secure, HttpOnly cookies'
  }
};
\`\`\`

## Breach Notification Rule (Section 164.400-414)

### Timeline
- **To HHS:** Within **60 days** of discovery for breaches affecting 500+ individuals. For breaches under 500, you can report annually.
- **To affected individuals:** Within **60 days** of discovery. Written notice via first-class mail or email (if consented).
- **To media:** If a breach affects 500+ residents of a single state/jurisdiction, you must notify prominent media outlets.

### What Constitutes a Breach?
An impermissible use or disclosure of PHI that compromises its security or privacy. There is a **presumption of breach** unless you can demonstrate a low probability that PHI was compromised based on a four-factor risk assessment:

1. Nature and extent of PHI involved
2. Who accessed or received the PHI
3. Whether the PHI was actually acquired or viewed
4. Extent to which risk has been mitigated

### Exceptions
- Unintentional access by an authorized workforce member acting in good faith
- Inadvertent disclosure between authorized persons within the same organization
- Disclosed information could not reasonably be retained

## Business Associate Agreements (BAAs)

A BAA is a **legally binding contract** between a covered entity and a business associate that:

- Establishes permitted uses and disclosures of PHI
- Requires the business associate to implement appropriate safeguards
- Requires reporting of breaches to the covered entity
- Ensures the business associate will return or destroy PHI when the contract ends
- Makes the business associate directly liable for HIPAA violations

**No BAA = No PHI.** Never share or process PHI without a BAA in place.

## De-identification Methods

### Safe Harbor Method (Section 164.514(b)(2))
Remove all 18 identifiers listed above and confirm there is no actual knowledge that residual information could identify an individual. This is a checklist approach -- if all 18 identifiers are removed, the data is considered de-identified.

### Expert Determination Method (Section 164.514(b)(1))
A qualified statistical or scientific expert determines that the risk of identifying any individual is "very small." The expert must document their methods and results. This is more flexible but requires hiring an expert.

De-identified data is **no longer PHI** and is not subject to HIPAA restrictions.
            `
        },
        {
            id: 'hipaa-quiz-safeguards',
            title: 'Safeguard Classification',
            type: 'quiz',
            content: '',
            quiz: {
                question: "A hospital implements automatic session timeout after 10 minutes of inactivity on all systems that access patient records. Which category of HIPAA safeguard does this fall under?",
                options: [
                    "Administrative safeguard -- it's a policy decision about security management",
                    "Physical safeguard -- it protects workstations from unauthorized access",
                    "Technical safeguard -- it's an access control mechanism implemented in technology",
                    "It spans both administrative and technical safeguards equally"
                ],
                correctAnswer: 2,
                explanation: "Automatic logoff is explicitly listed under Technical Safeguards in Section 164.312(a)(2)(iii). While the policy to implement it is administrative, the mechanism itself -- a technology-based access control that automatically terminates sessions -- is a technical safeguard. The Security Rule specifically categorizes it under Access Control within Technical Safeguards."
            }
        },
        {
            id: 'hipaa-lab-violation-finder',
            title: 'HIPAA Violation Finder',
            type: 'lab',
            content: 'The following healthcare application code has multiple HIPAA violations. Your mission: Identify each violation and fix the code to be HIPAA-compliant by adding proper access controls, audit logging, encryption, and removing inappropriate data exposure.',
            lab: {
                initialCode: `
// Healthcare patient portal -- find and fix HIPAA violations

const express = require('express');
const app = express();

// VIOLATION 1: No authentication check
app.get('/api/patient/:id/records', async (req, res) => {
  const patient = await db.patients.findById(req.params.id);
  // Returns everything -- no minimum necessary principle
  res.json(patient);
});

// VIOLATION 2: Logging PHI
app.post('/api/patient/:id/diagnosis', async (req, res) => {
  const { diagnosis, notes, ssn } = req.body;
  console.log(\`New diagnosis for patient \${req.params.id}: \${diagnosis}, SSN: \${ssn}\`);

  await db.diagnoses.insert({
    patientId: req.params.id,
    diagnosis,
    notes,
    createdAt: new Date()
  });

  res.json({ success: true });
});

// VIOLATION 3: No encryption, no access control
app.get('/api/export/all-patients', async (req, res) => {
  // Bulk export with no restrictions
  const allPatients = await db.patients.findAll();
  res.json(allPatients);
});

// VIOLATION 4: No audit trail
app.put('/api/patient/:id', async (req, res) => {
  await db.patients.update(req.params.id, req.body);
  res.json({ success: true });
});

// VIOLATION 5: Sharing PHI without BAA verification
app.post('/api/share-records', async (req, res) => {
  const { patientId, thirdPartyEmail } = req.body;
  const records = await db.patients.findById(patientId);
  await emailService.send(thirdPartyEmail, 'Patient Records', JSON.stringify(records));
  res.json({ sent: true });
});
`,
                solutionCode: `
// HIPAA-compliant healthcare patient portal

const express = require('express');
const app = express();

// Middleware: Authentication + Authorization required for all PHI endpoints
const requireAuth = async (req, res, next) => {
  const user = await verifySession(req);
  if (!user) return res.status(401).json({ error: 'Authentication required' });
  req.user = user;
  next();
};

// Middleware: Audit logging for all PHI access
const auditLog = async (req, res, next) => {
  await db.auditLogs.insert({
    userId: req.user.id,
    userRole: req.user.role,
    action: req.method,
    resource: req.originalUrl,
    patientId: req.params.id || null,
    ipAddress: req.ip,
    timestamp: new Date(),
    success: true
  });
  next();
};

// FIXED: Authentication, authorization, audit logging, minimum necessary
app.get('/api/patient/:id/records', requireAuth, auditLog, async (req, res) => {
  // Check authorization -- user can only access their own records or assigned patients
  const hasAccess = await checkPatientAccess(req.user, req.params.id);
  if (!hasAccess) return res.status(403).json({ error: 'Access denied' });

  // Minimum necessary -- return only fields needed for the user's role
  const fields = getFieldsByRole(req.user.role);
  const patient = await db.patients.findById(req.params.id, { select: fields });
  res.json(patient);
});

// FIXED: No PHI in logs, proper access control
app.post('/api/patient/:id/diagnosis', requireAuth, auditLog, async (req, res) => {
  const { diagnosis, notes } = req.body;
  // Log only non-PHI metadata
  console.log(\`Diagnosis recorded for patient [REDACTED] by user \${req.user.id}\`);

  await db.diagnoses.insert({
    patientId: req.params.id,
    diagnosis: encrypt(diagnosis),
    notes: encrypt(notes),
    createdBy: req.user.id,
    createdAt: new Date()
  });

  res.json({ success: true });
});

// FIXED: Bulk export restricted to authorized roles with audit trail
app.get('/api/export/patients', requireAuth, auditLog, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'compliance_officer') {
    return res.status(403).json({ error: 'Insufficient privileges for bulk export' });
  }
  // Export de-identified data only unless specific authorization exists
  const patients = await db.patients.findAll({ deidentified: true });
  res.json(patients);
});

// FIXED: All changes audited with before/after state
app.put('/api/patient/:id', requireAuth, auditLog, async (req, res) => {
  const before = await db.patients.findById(req.params.id);
  await db.patients.update(req.params.id, req.body);
  await db.auditLogs.insert({
    userId: req.user.id,
    action: 'UPDATE',
    resource: \`patient/\${req.params.id}\`,
    changeDetails: { before: '[encrypted]', after: '[encrypted]' },
    timestamp: new Date()
  });
  res.json({ success: true });
});

// FIXED: Verify BAA, use secure transmission, minimum necessary
app.post('/api/share-records', requireAuth, auditLog, async (req, res) => {
  const { patientId, recipientOrgId, purpose } = req.body;
  // Verify BAA exists with recipient organization
  const baa = await db.businessAssociateAgreements.findByOrg(recipientOrgId);
  if (!baa || baa.status !== 'active') {
    return res.status(403).json({ error: 'No active BAA with recipient organization' });
  }
  // Share minimum necessary via secure, encrypted channel -- not email
  const records = await db.patients.findById(patientId, {
    select: getFieldsForPurpose(purpose)
  });
  await secureTransfer.send(recipientOrgId, encrypt(records));
  res.json({ shared: true, recipientOrg: recipientOrgId });
});
`,
                instructions: "Fix all HIPAA violations: 1) Add authentication middleware to verify user identity before any PHI access, 2) Remove all PHI from console.log statements -- use redacted placeholders, 3) Implement the minimum necessary principle -- don't return full patient records when only specific fields are needed, 4) Add audit logging for every PHI access (who, what, when, where), 5) Restrict bulk export to authorized roles and use de-identified data, 6) Verify BAA exists before sharing records with third parties, and use encrypted channels instead of email."
            }
        }
    ]
};
