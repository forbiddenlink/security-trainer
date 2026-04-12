import type { Module } from '../../types';

export const gdprFundamentals: Module = {
    id: 'gdpr-fundamentals',
    title: 'GDPR Fundamentals',
    description: 'Master the General Data Protection Regulation -- the gold standard of privacy law. Learn the 7 principles, data subject rights, lawful bases, and what GDPR compliance looks like in code.',
    difficulty: 'Intermediate',
    xpReward: 350,
    locked: false,
    lessons: [
        {
            id: 'gdpr-overview',
            title: 'GDPR Overview & Key Principles',
            type: 'theory',
            content: `
# Mission Briefing: The GDPR

The General Data Protection Regulation (GDPR) is the European Union's landmark privacy law, effective since May 25, 2018. It governs how organizations collect, store, process, and share personal data of individuals in the EU/EEA -- regardless of where the organization is based.

## Who Does GDPR Apply To?

GDPR has **extraterritorial reach**. It applies to:

- **Any organization in the EU** that processes personal data
- **Any organization worldwide** that offers goods/services to EU residents
- **Any organization worldwide** that monitors the behavior of EU residents

If your website uses cookies to track a visitor from Berlin, GDPR applies to you -- even if your company is in San Francisco.

## The 7 Key Principles (Article 5)

Every data processing activity must comply with these principles:

### 1. Lawfulness, Fairness, and Transparency
You must have a legal basis to process data, do so fairly, and be transparent about what you're doing with it.

### 2. Purpose Limitation
Data must be collected for specified, explicit, and legitimate purposes. You can't collect email addresses for a newsletter and then sell them to advertisers.

### 3. Data Minimization
Collect only the data you actually need. If your app only needs an email to function, don't also ask for date of birth, phone number, and home address.

### 4. Accuracy
Personal data must be accurate and kept up to date. You must take reasonable steps to erase or rectify inaccurate data.

### 5. Storage Limitation
Don't keep data longer than necessary. If a user deletes their account, their data should be purged -- not archived indefinitely "just in case."

### 6. Integrity and Confidentiality
Data must be processed securely. This means encryption at rest, encryption in transit, access controls, and protection against unauthorized access or accidental loss.

### 7. Accountability
The data controller must be able to **demonstrate** compliance. It's not enough to be compliant -- you must prove it through documentation, audits, and records of processing activities.

## Fines Structure

GDPR has a two-tier penalty system:

- **Lower tier:** Up to **EUR 10 million** or **2% of global annual turnover** (whichever is higher) -- for violations of technical/organizational requirements
- **Upper tier:** Up to **EUR 20 million** or **4% of global annual turnover** (whichever is higher) -- for violations of core principles, data subject rights, or cross-border transfer rules

## Case Files: Real Enforcement Actions

**Google (2019) -- EUR 50 million fine (CNIL, France):**
Google was fined for lack of transparency and valid consent for ad personalization. Users weren't given clear information about how their data was being used, and consent was bundled rather than granular.

**H&M (2020) -- EUR 35.3 million fine (Hamburg DPA, Germany):**
H&M's service center in Nuremberg maintained extensive records on employees' private lives -- health issues, family problems, religious beliefs -- gathered through "welcome back" chats after sick leave. A configuration error exposed the database to the entire company.

**British Airways (2020) -- GBP 20 million fine (ICO, UK):**
A cyberattack compromised the personal and payment data of approximately 400,000 customers. The ICO found BA had poor security measures, including lack of multi-factor authentication, inadequate testing, and insufficient logging and monitoring.

**Amazon (2021) -- EUR 746 million fine (CNPD, Luxembourg):**
The largest GDPR fine to date. Amazon's advertising targeting system processed personal data without proper consent. The fine was later reduced on appeal but remains a landmark case.

**Meta/Instagram (2022) -- EUR 405 million fine (DPC, Ireland):**
Instagram was fined for mishandling children's data, including making teenagers' phone numbers and email addresses public by default through business accounts.
            `
        },
        {
            id: 'gdpr-quiz-applicability',
            title: 'GDPR Applicability',
            type: 'quiz',
            content: '',
            quiz: {
                question: "A US-based SaaS company has no offices in Europe but serves customers in France and Germany through its website. A French user signs up and enters personal data. Does GDPR apply to this company?",
                options: [
                    "No -- GDPR only applies to companies physically located in the EU",
                    "Yes -- GDPR applies because the company offers services to EU residents, regardless of its location",
                    "Only if the company processes more than 10,000 EU records per year",
                    "Only if the company has explicitly agreed to GDPR compliance in its terms of service"
                ],
                correctAnswer: 1,
                explanation: "GDPR has extraterritorial reach (Article 3). It applies to any organization that offers goods or services to individuals in the EU, regardless of where the organization is based. The key factor is whether the company targets EU residents, not its physical location."
            }
        },
        {
            id: 'gdpr-rights-theory',
            title: 'Data Subject Rights & Lawful Bases',
            type: 'theory',
            content: `
# Intel Report: Data Subject Rights & Lawful Bases

## The 8 Data Subject Rights

GDPR grants individuals powerful rights over their personal data. As a developer or product owner, you must build systems that can honor these rights.

### 1. Right of Access (Article 15)
Individuals can request a copy of all personal data you hold about them, along with information about how it's being processed. You must respond within **30 days**.

\`\`\`
// Your system needs an endpoint like:
GET /api/user/data-export
// Returns: All personal data in a structured, machine-readable format
\`\`\`

### 2. Right to Rectification (Article 16)
Individuals can request corrections to inaccurate personal data. Your UI should allow users to update their own data where possible.

### 3. Right to Erasure / "Right to Be Forgotten" (Article 17)
Individuals can request deletion of their personal data when it's no longer necessary, consent is withdrawn, or it was unlawfully processed. This includes backups and third-party systems.

### 4. Right to Restrict Processing (Article 18)
Individuals can request that you stop processing their data while a dispute is resolved, without deleting it entirely.

### 5. Right to Data Portability (Article 20)
Individuals can request their data in a **structured, commonly used, machine-readable format** (like JSON or CSV) and have it transferred to another controller.

### 6. Right to Object (Article 21)
Individuals can object to processing based on legitimate interests or for direct marketing. For direct marketing, the objection is absolute -- you must stop immediately.

### 7. Rights Related to Automated Decision-Making (Article 22)
Individuals have the right not to be subject to purely automated decisions that produce legal or significant effects. They can request human intervention.

### 8. Right to Be Informed (Articles 13-14)
Organizations must proactively tell individuals what data they collect, why, how long they'll keep it, and who they share it with -- typically via a privacy policy.

## The 6 Lawful Bases for Processing (Article 6)

You **must** have at least one lawful basis before processing any personal data:

### 1. Consent
The individual has given clear, affirmative consent for a specific purpose. Must be freely given, specific, informed, and unambiguous. Pre-ticked boxes don't count.

### 2. Contract
Processing is necessary to fulfill a contract with the individual. Example: you need their shipping address to deliver a product they purchased.

### 3. Legal Obligation
Processing is necessary to comply with the law. Example: retaining tax records for the required period.

### 4. Vital Interests
Processing is necessary to protect someone's life. Rarely applies in software -- think emergency medical situations.

### 5. Public Task
Processing is necessary for a task in the public interest or official authority. Mainly applies to government bodies.

### 6. Legitimate Interests
Processing is necessary for your legitimate interests, provided they don't override the individual's rights. Requires a **Legitimate Interest Assessment (LIA)**. Example: fraud prevention, network security.

## Consent Requirements

When relying on consent as your lawful basis, GDPR sets a high bar:

- **Freely given:** No bundling consent with terms of service. No "consent or you can't use the service" (unless the data is strictly necessary for the service).
- **Specific:** Separate consent for separate purposes. One checkbox per purpose.
- **Informed:** Clear, plain language about what they're consenting to.
- **Unambiguous:** Requires a clear affirmative action (opt-in, not opt-out).
- **Withdrawable:** Must be as easy to withdraw consent as it was to give it.
            `
        },
        {
            id: 'gdpr-quiz-rights',
            title: 'Rights & Responsibilities',
            type: 'quiz',
            content: '',
            quiz: {
                question: "A user requests deletion of their account data under the Right to Erasure. Your system deletes the user record from the production database but their data still exists in database backups, analytics logs, and a third-party CRM. Is this compliant?",
                options: [
                    "Yes -- deleting from the production database is sufficient",
                    "Yes -- backups and third-party systems are exempt from erasure requests",
                    "No -- you must make reasonable efforts to erase data from all systems, including backups and third parties you've shared data with",
                    "No -- but only if the user specifically mentions backups in their request"
                ],
                correctAnswer: 2,
                explanation: "The Right to Erasure requires you to erase personal data from all systems where it's stored and to inform third parties who received the data. While backup deletion can be technically challenging, you must have processes to handle it -- such as excluding restored records from deleted users or using crypto-shredding."
            }
        },
        {
            id: 'gdpr-developers-theory',
            title: 'GDPR for Developers',
            type: 'theory',
            content: `
# Case File: GDPR in the Codebase

## Privacy by Design (Article 25)

GDPR requires that data protection is built into systems from the start -- not bolted on afterward. This is legally mandated, not optional.

### What This Means in Practice

\`\`\`typescript
// BAD: Collect everything, figure out privacy later
const userData = {
  name, email, phone, dob, location, browserFingerprint,
  ipAddress, deviceId, socialMediaProfiles, browsingHistory
};

// GOOD: Collect only what's needed for the specific purpose
const userData = {
  email,  // Needed for account login
  name,   // Needed for personalization (optional field)
};
\`\`\`

### Privacy by Default
The strictest privacy settings should apply by default. Users shouldn't have to dig through settings to protect their privacy.

\`\`\`typescript
// User preferences should default to most private
const defaultSettings = {
  profileVisibility: 'private',     // Not 'public'
  marketingEmails: false,           // Not true
  dataSharing: false,               // Not true
  activityTracking: false,          // Not true
};
\`\`\`

## Data Protection Impact Assessments (DPIA)

A DPIA is required when processing is likely to result in **high risk** to individuals. This includes:

- Large-scale processing of sensitive data (health, biometrics, political opinions)
- Systematic monitoring of public areas
- Automated decision-making with legal effects (credit scoring, hiring algorithms)
- New technologies whose privacy impact is unknown

A DPIA documents:
1. The nature and purpose of processing
2. Necessity and proportionality assessment
3. Risks to individuals
4. Measures to mitigate those risks

## Data Breach Notification (Articles 33-34)

### To the Supervisory Authority: 72 Hours
If a personal data breach occurs, you must notify the relevant Data Protection Authority (DPA) within **72 hours** of becoming aware of it. The notification must include:

- Nature of the breach (what data, how many individuals)
- Contact details of the DPO
- Likely consequences
- Measures taken to address the breach

### To Affected Individuals: Without Undue Delay
If the breach is likely to result in **high risk** to individuals, you must also notify them directly. You can skip this if:

- The data was encrypted/pseudonymized
- You've taken measures that eliminate the high risk
- Individual notification would involve disproportionate effort (use public communication instead)

\`\`\`typescript
// Every application should have a breach response function
async function handleDataBreach(breach: BreachDetails) {
  // 1. Log the breach with timestamp (starts the 72-hour clock)
  const discoveryTime = new Date();
  await logBreach({ ...breach, discoveredAt: discoveryTime });

  // 2. Assess severity and affected individuals
  const assessment = await assessBreachSeverity(breach);

  // 3. Notify DPO immediately
  await notifyDPO(breach, assessment);

  // 4. If high risk, prepare individual notifications
  if (assessment.riskLevel === 'high') {
    await prepareIndividualNotifications(breach.affectedUsers);
  }

  // 5. Document everything for the supervisory authority
  await generateBreachReport(breach, assessment, discoveryTime);
}
\`\`\`

## Data Protection Officer (DPO)

A DPO is mandatory if you:
- Are a public authority
- Carry out large-scale systematic monitoring
- Process sensitive data on a large scale

The DPO must be independent, report to the highest level of management, and cannot be penalized for performing their duties.

## International Data Transfers (Chapter V)

Transferring personal data outside the EU/EEA requires safeguards:

- **Adequacy Decision:** The EU Commission has deemed the destination country adequate (e.g., Japan, UK, South Korea, and the US under the EU-US Data Privacy Framework)
- **Standard Contractual Clauses (SCCs):** Pre-approved contractual terms between sender and receiver
- **Binding Corporate Rules (BCRs):** Approved internal policies for multinational companies

### Post-Schrems II Reality
The 2020 Schrems II ruling invalidated the EU-US Privacy Shield. Companies must now conduct **Transfer Impact Assessments** and implement supplementary measures when relying on SCCs for transfers to countries without adequate protections.

\`\`\`typescript
// Before sending data to any third-party service, check:
const transferChecklist = {
  serviceLocation: 'us-east-1',              // Where is data stored?
  adequacyDecision: true,                      // EU-US DPF certified?
  sccsInPlace: true,                           // Standard Contractual Clauses signed?
  transferImpactAssessment: true,              // Risk assessment completed?
  encryptionInTransit: true,                   // TLS 1.2+?
  encryptionAtRest: true,                      // AES-256?
  dataProcessingAgreement: true,               // DPA signed with vendor?
};
\`\`\`
            `
        },
        {
            id: 'gdpr-lab-privacy-audit',
            title: 'Privacy Policy Audit',
            type: 'lab',
            content: 'The following privacy policy object has multiple GDPR violations. Your mission: Review each field and mark non-compliant sections by setting their `compliant` property to `false` and adding a `violation` description explaining the GDPR principle or article being violated.',
            lab: {
                initialCode: `
// This company's privacy policy has several GDPR violations.
// Review each section and mark non-compliant ones:
//   - Set compliant: false
//   - Add a violation: string explaining the issue
//
// Hint: Check against the 7 principles and consent requirements.

const privacyPolicyAudit = {
  dataCollection: {
    description: "We collect your name, email, phone number, home address, date of birth, social media profiles, browsing history, device fingerprint, and location data when you sign up for our newsletter.",
    compliant: true,
    violation: ""
  },
  consent: {
    description: "By using our website, you agree to all data processing activities described in this policy.",
    compliant: true,
    violation: ""
  },
  dataRetention: {
    description: "We retain all user data indefinitely to improve our services and for potential future use.",
    compliant: true,
    violation: ""
  },
  thirdPartySharing: {
    description: "We share your personal data with our trusted partners for marketing purposes. A list of partners is available upon request.",
    compliant: true,
    violation: ""
  },
  userRights: {
    description: "To request data deletion, please send a letter by certified mail to our headquarters. Please allow 6-8 months for processing.",
    compliant: true,
    violation: ""
  },
  consentWithdrawal: {
    description: "To withdraw consent, please contact our legal department during business hours and complete a notarized withdrawal form.",
    compliant: true,
    violation: ""
  }
};
`,
                solutionCode: `
const privacyPolicyAudit = {
  dataCollection: {
    description: "We collect your name, email, phone number, home address, date of birth, social media profiles, browsing history, device fingerprint, and location data when you sign up for our newsletter.",
    compliant: false,
    violation: "Violates Data Minimization (Article 5(1)(c)). A newsletter only requires an email address. Collecting home address, DOB, social media profiles, browsing history, device fingerprint, and location is excessive and not necessary for the stated purpose."
  },
  consent: {
    description: "By using our website, you agree to all data processing activities described in this policy.",
    compliant: false,
    violation: "Violates Consent requirements (Article 7, Recital 32). Consent must be freely given, specific, informed, and unambiguous via a clear affirmative action. Implied consent through website usage is not valid. Bundling all processing under one blanket agreement violates the 'specific' requirement."
  },
  dataRetention: {
    description: "We retain all user data indefinitely to improve our services and for potential future use.",
    compliant: false,
    violation: "Violates Storage Limitation (Article 5(1)(e)). Data must be kept only as long as necessary for the specified purpose. Indefinite retention with vague justification ('potential future use') is not a legitimate purpose."
  },
  thirdPartySharing: {
    description: "We share your personal data with our trusted partners for marketing purposes. A list of partners is available upon request.",
    compliant: false,
    violation: "Violates Transparency (Article 5(1)(a)) and Right to Be Informed (Articles 13-14). Third parties must be named, not described vaguely as 'trusted partners.' The purposes must be specific, and separate consent is required for marketing by third parties."
  },
  userRights: {
    description: "To request data deletion, please send a letter by certified mail to our headquarters. Please allow 6-8 months for processing.",
    compliant: false,
    violation: "Violates Right to Erasure (Article 17) and response timeline (Article 12(3)). Erasure requests must be fulfilled within 30 days (extendable by 2 months for complex cases). Requiring certified mail creates an unreasonable barrier. The process must be as easy as the original data collection."
  },
  consentWithdrawal: {
    description: "To withdraw consent, please contact our legal department during business hours and complete a notarized withdrawal form.",
    compliant: false,
    violation: "Violates Article 7(3): Withdrawal of consent must be as easy as giving it. If consent was given with a click, withdrawal cannot require notarized forms and phone calls during business hours. This creates an unreasonable barrier."
  }
};
`,
                instructions: "Review each section of the privacy policy. For each GDPR violation: 1) Set compliant to false, 2) Add a violation string explaining which GDPR principle or article is being violated and why. All 6 sections contain violations related to data minimization, consent, storage limitation, transparency, user rights, and consent withdrawal."
            }
        }
    ]
};
