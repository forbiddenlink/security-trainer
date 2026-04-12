import type { Module } from '../../types';

export const passwordDataHygiene: Module = {
    id: 'password-data-hygiene',
    title: 'Password & Data Hygiene',
    description: 'Master the fundamentals of strong passwords, multi-factor authentication, and proper data handling to protect yourself and your organization.',
    difficulty: 'Beginner',
    xpReward: 200,
    locked: false,
    lessons: [
        {
            id: 'password-fundamentals',
            title: 'Password Security Fundamentals',
            type: 'theory',
            content: `# Password Security Fundamentals

## Mission Briefing

Agent, passwords are the front door to every digital system. And right now, that door is wide open for most people. In this briefing, you'll learn why passwords fail, how attackers crack them, and what you can do to lock things down for good.

## Why Passwords Get Cracked

Most people think their password is strong enough. Most people are wrong. Here's why:

### The Scale of the Problem

- The average person has **100+ online accounts**
- **65%** of people reuse the same password across multiple sites
- **23 million** accounts still use "123456" as their password
- A modern GPU can test **100 billion password guesses per second**

### How Attackers Crack Passwords

**1. Dictionary Attacks**
Attackers start with lists of common passwords and known words:

\`\`\`
Attempt 1: password
Attempt 2: 123456
Attempt 3: qwerty
Attempt 4: letmein
Attempt 5: dragon
...
(Top 10,000 passwords crack ~30% of accounts)
\`\`\`

**2. Credential Stuffing**
When a website is breached, attackers take those leaked email/password combinations and try them on every other site:

\`\`\`
LinkedIn breach (2012):
  sarah@email.com : SunnyDay2012!

Attackers try same credentials on:
  → Gmail        ✓ Same password!
  → Amazon       ✓ Same password!
  → Banking app  ✓ Same password!
  → Work email   ✓ Same password!
\`\`\`

**One breach becomes access to everything** when you reuse passwords.

**3. Brute Force with Smart Rules**
Attackers know the patterns people use to "make passwords complex":

\`\`\`
Base word:     summer
Common rules:  Summer1! → Summer2023! → $ummer2023!

Attackers apply these same rules automatically:
  - Capitalize first letter
  - Add numbers at end
  - Replace 's' with '$', 'a' with '@', etc.
  - Append ! or # at the end
\`\`\`

**4. Phishing and Social Engineering**
Why crack a password when you can just ask for it? (See our Phishing module.)

## Real-World Intel

**Case File #1: RockYou Breach (2009)**

The RockYou social media platform stored 32 million passwords in plain text (no encryption). When hackers breached their database, every single password was exposed. Analysis revealed the most common password was "123456" (used by 290,000+ accounts), followed by "12345", "123456789", and "password". This breach became the foundation for password cracking dictionaries that are still used today -- over 15 years later.

**Case File #2: Collection #1 Breach (2019)**

In January 2019, security researcher Troy Hunt discovered "Collection #1" -- a massive database of 773 million email addresses and 21 million unique passwords compiled from thousands of different data breaches. This wasn't a single hack -- it was an aggregation of years of breaches assembled into one package and shared openly on hacking forums. It demonstrated how credential stuffing works at industrial scale: attackers combine breaches to build comprehensive profiles of reused passwords.

## Building Strong Passwords

### The Passphrase Method

Instead of a complex, hard-to-remember password, use a passphrase -- a string of random, unrelated words:

\`\`\`
Weak:     P@ssw0rd123!        (looks complex but easily cracked)
Strong:   correct-horse-battery-staple  (easy to remember, very hard to crack)
Stronger: purple-trumpet-glacier-bicycle-17
\`\`\`

Why passphrases work:
- "P@ssw0rd" has ~30 bits of entropy -- cracked in seconds
- "correct-horse-battery-staple" has ~66 bits -- takes centuries to crack
- Length beats complexity every time

### Password Managers: The Real Solution

A password manager generates, stores, and auto-fills unique, strong passwords for every account. You only need to remember one master password.

**Why you need one:**
- Generates truly random passwords (e.g., \`kJ#9mP2$xL7nQ4&vR\`)
- Unique password for every site (no reuse)
- Auto-fills passwords (immune to phishing -- won't fill on fake sites)
- Alerts you when passwords appear in breaches

**Popular options:** 1Password, Bitwarden (free/open source), Apple Keychain, Google Password Manager

**Your master password** should be a strong passphrase you can remember but nobody could guess.

## Multi-Factor Authentication (MFA)

MFA means requiring something beyond just a password to log in. Even if your password is stolen, attackers can't get in without the second factor.

### The Three Factors

1. **Something you know** -- Password, PIN, security question
2. **Something you have** -- Phone, hardware key, authenticator app
3. **Something you are** -- Fingerprint, face scan, voice recognition

### MFA Methods (Best to Worst)

\`\`\`
Most Secure:
  🔑 Hardware security key (YubiKey, Google Titan)
     → Phishing-resistant, can't be intercepted

  📱 Authenticator app (Google Authenticator, Authy)
     → Time-based codes, works offline

Less Secure:
  📲 Push notification (Duo, Microsoft Authenticator)
     → Convenient but vulnerable to "MFA fatigue" attacks

  📨 SMS text message
     → Better than nothing, but can be intercepted via SIM swap

Avoid:
  ❓ Security questions ("What's your mother's maiden name?")
     → Answers are often publicly available on social media
\`\`\`

### MFA Fatigue: The New Attack

Attackers with your password may spam your phone with MFA approval requests at 3 AM, hoping you'll tap "Approve" just to make it stop. This is how Uber was breached in 2022.

**Defense:** Never approve an MFA request you didn't initiate. If you get unexpected prompts, change your password immediately.

## Your Security Protocol

1. **Use a password manager** -- Start today. No excuses.
2. **Enable MFA everywhere** -- Especially email, banking, and work accounts.
3. **Never reuse passwords** -- Let your password manager generate unique ones.
4. **Check haveibeenpwned.com** -- See if your accounts appear in known breaches.
5. **Use passphrases** for the few passwords you must memorize (master password, laptop login).
            `
        },
        {
            id: 'password-quiz-strength',
            title: 'Password Strength Assessment',
            type: 'quiz',
            content: '',
            quiz: {
                question: "Which of these passwords is the STRONGEST?",
                options: [
                    "P@$$w0rd!2024",
                    "correct-horse-battery-staple",
                    "Tr0ub4dor&3",
                    "qwerty123456789"
                ],
                correctAnswer: 1,
                explanation: "'correct-horse-battery-staple' is the strongest because it uses four random, unrelated words creating high entropy through length. 'P@$$w0rd!2024' looks complex but is based on a dictionary word with common substitutions that cracking tools handle easily. 'Tr0ub4dor&3' uses the same predictable substitution pattern. 'qwerty123456789' is just keyboard patterns and sequential numbers -- cracked instantly. Length and randomness beat symbol substitution every time."
            }
        },
        {
            id: 'data-handling',
            title: 'Data Handling & Classification',
            type: 'theory',
            content: `# Data Handling & Classification

## Intel Report: Protecting Sensitive Information

Agent, every piece of data your organization handles has a sensitivity level. Treating all data the same is how breaches happen. This briefing covers how to classify data, handle it properly, and avoid the common mistakes that lead to costly incidents.

## Data Classification: Know What You're Protecting

Not all data is created equal. Organizations classify data into sensitivity levels to determine how it should be stored, shared, and disposed of.

### Standard Classification Levels

\`\`\`
Level 4 - RESTRICTED / CONFIDENTIAL
  Examples: Social Security numbers, credit card data,
            medical records, passwords, encryption keys,
            trade secrets, legal documents
  Handling: Encrypted at rest and in transit, strict access
            controls, audit logging, secure disposal

Level 3 - SENSITIVE / INTERNAL ONLY
  Examples: Employee salaries, internal financial reports,
            customer contact info, strategic plans,
            performance reviews, unreleased product details
  Handling: Access on need-to-know basis, don't share
            externally, secure file sharing only

Level 2 - INTERNAL
  Examples: Company policies, org charts, meeting notes,
            internal memos, project timelines
  Handling: Keep within the organization, don't post
            publicly, basic access controls

Level 1 - PUBLIC
  Examples: Marketing materials, published press releases,
            job postings, public website content
  Handling: Can be shared freely, no restrictions
\`\`\`

### Personally Identifiable Information (PII)

PII is any data that can identify a specific person. It requires special handling under laws like GDPR, CCPA, and HIPAA:

**Direct PII** (identifies someone alone):
- Full name, Social Security number, driver's license
- Email address, phone number, home address
- Passport number, biometric data

**Indirect PII** (identifies someone when combined):
- Date of birth, ZIP code, job title
- Gender, race/ethnicity
- School name, employer name

**Sensitive PII** (causes harm if exposed):
- Financial account numbers
- Medical/health information
- Criminal records
- Religious or political affiliations

## Physical Security: The Clean Desk Policy

Digital security means nothing if someone can walk by your desk and photograph sensitive documents.

### The Clean Desk Protocol

\`\`\`
Before leaving your workspace:
  ✓ Lock your computer (Win+L or Cmd+Ctrl+Q)
  ✓ Put sensitive documents in a locked drawer
  ✓ Clear whiteboards with confidential info
  ✓ Remove sticky notes with passwords (yes, people do this)
  ✓ Turn over or shred printed documents with PII
  ✓ Lock your screen when stepping away, even briefly

At the end of the day:
  ✓ Shred documents you no longer need
  ✓ Secure portable devices (laptops, USB drives)
  ✓ Check printers for forgotten printouts
\`\`\`

### Shoulder Surfing

Attackers don't always need to hack systems -- sometimes they just need to look over your shoulder:

- **In the office:** Someone watching you type a password or reading your screen
- **On public transit:** The person behind you reading your email on your phone
- **At a coffee shop:** Someone observing your laptop screen from a nearby table

**Defense:** Use privacy screen filters, angle your screen away from foot traffic, and be aware of your surroundings.

## Secure File Sharing

### Do's and Don'ts

\`\`\`
DO:
  ✓ Use company-approved file sharing (SharePoint, Google Drive)
  ✓ Set appropriate permissions (viewer vs. editor)
  ✓ Use password-protected links for sensitive files
  ✓ Set expiration dates on shared links
  ✓ Verify the recipient before sharing sensitive data

DON'T:
  ✗ Email sensitive documents as attachments
  ✗ Use personal cloud storage for work files
  ✗ Share links with "Anyone with the link" for sensitive data
  ✗ Send passwords in the same email as the file
  ✗ Use USB drives to transfer sensitive files between systems
\`\`\`

## Public WiFi: The Silent Threat

Free WiFi at coffee shops, airports, and hotels is convenient -- and dangerous.

**Why public WiFi is risky:**
- **Evil twin attacks** -- Attackers create fake WiFi networks ("Starbucks_Free_WiFi") that intercept all your traffic
- **Packet sniffing** -- On unencrypted networks, attackers can see everything you send
- **Man-in-the-middle** -- Attackers position themselves between you and the network

**Defense:**
- Use a VPN (Virtual Private Network) on any public network
- Verify the network name with staff before connecting
- Avoid accessing banking, email, or work systems on public WiFi
- Use your phone's hotspot instead when possible
- Ensure websites show HTTPS (the padlock icon) before entering any information

## USB Risks: The Baiting Attack

Attackers leave infected USB drives in parking lots, lobbies, and common areas, hoping someone will plug one in out of curiosity.

**Real Case:** In a 2016 study by researchers at the University of Illinois, 48% of people who found USB drives in a parking lot plugged them into their computers. Some drives were picked up and inserted within 6 minutes of being dropped.

**Rule:** Never plug in a USB drive you didn't purchase yourself or receive from a verified, trusted source. If you find one, turn it in to your IT department.
            `
        },
        {
            id: 'data-quiz-classification',
            title: 'Data Classification Challenge',
            type: 'quiz',
            content: '',
            quiz: {
                question: "You're organizing files and need to classify them by sensitivity. Which of these should be classified as RESTRICTED (highest sensitivity)?",
                options: [
                    "The company's public-facing press release about a new product",
                    "An internal org chart showing team structure and reporting lines",
                    "A spreadsheet containing employee Social Security numbers and salaries",
                    "Meeting notes from a routine team standup"
                ],
                correctAnswer: 2,
                explanation: "Social Security numbers are Personally Identifiable Information (PII) and salary data is sensitive employee information -- together, this spreadsheet is RESTRICTED/CONFIDENTIAL and requires encryption, strict access controls, and secure disposal. The press release is PUBLIC. The org chart is INTERNAL. Meeting notes from routine standups are INTERNAL. When in doubt, classify higher rather than lower."
            }
        },
        {
            id: 'password-lab-policy',
            title: 'Security Policy Review',
            type: 'lab',
            content: 'Your organization\'s data handling policy has critical gaps. Review the policy below and identify all missing security protections by setting each gap to true.',
            lab: {
                initialCode: `// COMPANY DATA HANDLING POLICY (DRAFT)
// =====================================
// Review this policy and identify ALL gaps.

const companyPolicy = {
  passwordRequirements: {
    minimumLength: 6,         // characters
    requireUppercase: false,
    requireNumbers: false,
    requireSpecialChars: false,
    expiryDays: 365,          // change annually
    preventReuse: 0           // previous passwords blocked
  },
  dataHandling: {
    encryptSensitiveFiles: false,
    allowPersonalUSBDrives: true,
    allowPersonalCloudStorage: true,
    requireVPNOnPublicWifi: false,
    shredDocumentsBeforeDisposal: false
  },
  accessControls: {
    multiFactorAuth: "optional",
    screenLockTimeout: "never",
    sharePasswordsForTeamAccounts: true,
    guestWifiSeparateFromCorporate: false
  }
};

// YOUR ANALYSIS: Which policy items are security gaps?
// Set each to true if the policy item is INADEQUATE.
const policyGaps = {
  // Password length too short? (Industry standard: 12+ chars)
  passwordTooShort: false,

  // No complexity requirements?
  noComplexityRequirements: false,

  // Password change interval too long?
  passwordExpiryTooLong: false,

  // No prevention of password reuse?
  noReuseProtection: false,

  // Sensitive files not encrypted?
  sensitiveDataUnencrypted: false,

  // USB drives allowed without restrictions?
  usbDrivesUnrestricted: false,

  // Personal cloud storage for work files?
  personalCloudAllowed: false,

  // No VPN requirement on public wifi?
  noVPNRequirement: false,

  // MFA not mandatory?
  mfaNotRequired: false,

  // No automatic screen lock?
  noScreenLock: false,

  // Shared passwords for team accounts?
  sharedPasswords: false,

  // Guest and corporate wifi not separated?
  wifiNotSegmented: false,

  // No document shredding?
  noDocumentShredding: false
};

// Find ALL the gaps!`,
                solutionCode: `// COMPANY DATA HANDLING POLICY (DRAFT)
// =====================================
const companyPolicy = {
  passwordRequirements: {
    minimumLength: 6,
    requireUppercase: false,
    requireNumbers: false,
    requireSpecialChars: false,
    expiryDays: 365,
    preventReuse: 0
  },
  dataHandling: {
    encryptSensitiveFiles: false,
    allowPersonalUSBDrives: true,
    allowPersonalCloudStorage: true,
    requireVPNOnPublicWifi: false,
    shredDocumentsBeforeDisposal: false
  },
  accessControls: {
    multiFactorAuth: "optional",
    screenLockTimeout: "never",
    sharePasswordsForTeamAccounts: true,
    guestWifiSeparateFromCorporate: false
  }
};

// ANALYSIS: Every single item in this policy is a gap!
const policyGaps = {
  // 6 chars is far too short. Standard is 12-16 minimum.
  passwordTooShort: true,

  // No uppercase, numbers, or special chars required
  noComplexityRequirements: true,

  // 365 days is too long. NIST now recommends no forced
  // expiry unless breach suspected, but 365 is still risky
  // with no other protections in place.
  passwordExpiryTooLong: true,

  // Users can reuse the same password forever
  noReuseProtection: true,

  // Sensitive data MUST be encrypted at rest
  sensitiveDataUnencrypted: true,

  // Personal USB drives can introduce malware
  usbDrivesUnrestricted: true,

  // Work data on personal Dropbox/Drive is a breach risk
  personalCloudAllowed: true,

  // Public wifi without VPN exposes all traffic
  noVPNRequirement: true,

  // MFA must be mandatory, not optional
  mfaNotRequired: true,

  // "Never" lock means unattended machines are exposed
  noScreenLock: true,

  // Shared passwords destroy accountability and audit trails
  sharedPasswords: true,

  // Guest devices should never touch the corporate network
  wifiNotSegmented: true,

  // Printed documents with PII must be shredded
  noDocumentShredding: true
};`,
                instructions: "Review the company data handling policy and identify all security gaps. For each item in policyGaps, set it to true if the corresponding policy item is inadequate or insecure. Consider industry best practices: 12+ character passwords, mandatory MFA, encryption for sensitive data, no shared passwords, VPN requirements, and proper disposal procedures. HINT: This policy was written by someone who prioritized convenience over security -- every item has a gap."
            }
        }
    ]
};
