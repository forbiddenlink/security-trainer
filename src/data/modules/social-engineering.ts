import type { Module } from "../../types";

export const socialEngineering: Module = {
  id: "social-engineering",
  title: "Modern Social Engineering",
  description:
    "Learn to recognize and defend against social engineering attacks including phishing, pretexting, deepfakes, and AI-powered manipulation tactics.",
  difficulty: "Intermediate",
  xpReward: 350,
  locked: false,
  lessons: [
    {
      id: "social-intro",
      title: "The Human Attack Vector",
      type: "theory",
      content: `# The Human Attack Vector

Social engineering exploits human psychology rather than technical vulnerabilities. It's often easier to trick a person than to hack a system.

## Why Social Engineering Works

- **Trust**: Humans naturally want to be helpful
- **Authority**: We comply with perceived authority figures
- **Urgency**: Pressure reduces critical thinking
- **Fear**: Threats trigger emotional responses
- **Curiosity**: We click on interesting things

## The Attack Kill Chain

\`\`\`
1. Research        → LinkedIn, social media, company website
2. Pretext         → Create believable scenario
3. Contact         → Email, phone, in-person
4. Manipulation    → Apply psychological triggers
5. Execution       → Get credentials, access, or action
6. Persistence     → Maintain access or repeat
\`\`\`

## Modern vs Traditional Social Engineering

| Traditional | Modern (2024+) |
|-------------|----------------|
| Nigerian prince emails | Highly targeted spear phishing |
| Cold calls | AI voice cloning |
| Fake websites | Perfect domain spoofing |
| Manual research | OSINT automation tools |
| Text-only lures | Deepfake video calls |

## Attack Statistics (2024)

- **91%** of cyberattacks start with phishing
- **$50B+** lost annually to business email compromise
- **15 seconds** to judge if an email is legitimate
- **3.4 billion** phishing emails sent daily

## Key Social Engineering Categories

1. **Phishing** - Fraudulent communications
2. **Pretexting** - Fabricated scenarios
3. **Baiting** - Malicious "free" offers
4. **Quid Pro Quo** - Service in exchange for info
5. **Tailgating** - Physical access through courtesy
6. **Deepfakes** - AI-generated impersonation

Technical controls help, but awareness is the primary defense.`,
    },
    {
      id: "phishing-attacks",
      title: "Phishing Attack Techniques",
      type: "theory",
      content: `# Phishing Attack Techniques

Phishing has evolved from obvious scams to sophisticated, targeted attacks that fool even security professionals.

## Types of Phishing

### 1. Mass Phishing
Spray-and-pray approach targeting thousands:
\`\`\`
From: support@arnazon.com  ← Typosquatted domain
Subject: Your order #38291 has been delayed

Dear Customer,
Your recent order couldn't be delivered. Click here to update
your delivery address: [malicious-link]
\`\`\`

### 2. Spear Phishing
Targeted attacks using personal information:
\`\`\`
From: john.smith@partner-company.com  ← Real name, spoofed domain
Subject: Re: Q4 Partnership Agreement

Hi Sarah,

Following up on our call last Tuesday about the partnership.
Can you review the updated contract and sign?

[malicious-document.pdf]

Best,
John
\`\`\`

### 3. Whaling
Targeting executives with high-value access:
\`\`\`
From: ceo@company.com (spoofed)
To: cfo@company.com
Subject: Urgent Wire Transfer - Confidential

I need you to process an urgent wire transfer for an acquisition.
This is time-sensitive and confidential - don't discuss with anyone.
$2.4M to account ending 8291. I'll explain when I'm back.
\`\`\`

### 4. Vishing (Voice Phishing)
\`\`\`
"Hi, this is IT Security. We detected unusual login activity on
your account. I need to verify your identity - can you confirm
your password so I can check if the access was legitimate?"
\`\`\`

## Red Flags to Watch For

### Email Red Flags
- Urgency or threats ("Account suspended in 24 hours!")
- Generic greetings ("Dear Customer")
- Mismatched display name and email address
- Suspicious attachments or links
- Poor grammar (but AI has fixed this!)
- Requests for sensitive information

### URL Red Flags
\`\`\`
Legitimate:  https://www.microsoft.com/login
Phishing:    https://www.microsoft-secure.com/login
             https://www.mlcrosoft.com/login  (l→I)
             https://www.microsoft.com.login.attacker.com
             https://microsoft.attacker.com
\`\`\`

### Domain Tricks
- Typosquatting: \`arnazon.com\`, \`gogle.com\`
- Homograph: \`аpple.com\` (Cyrillic 'а')
- Subdomain: \`microsoft.com.attacker.com\`
- TLD abuse: \`microsoft.support\` vs \`microsoft.com\`

## Defense Strategies

### Technical Controls
1. Email authentication (SPF, DKIM, DMARC)
2. URL filtering and sandboxing
3. Multi-factor authentication
4. Email gateway security

### Human Controls
1. Verify sender through separate channel
2. Hover before clicking
3. When in doubt, report to security
4. Never provide credentials via email/phone`,
    },
    {
      id: "vishing-voicemail",
      title: "Vishing: Hear a Voice Scam",
      type: "theory",
      content: `# Vishing (Voice Phishing)

Vishing is phishing over a phone call or voicemail. Attackers use urgency and authority to make you act before you think.

## Hear a real example

Below is an AI-generated sample of a classic "IT Security" vishing call. Listen for the red flags.

<audio controls preload="none" src="/audio/vishing-voicemail.mp3"></audio>

> "Hi, this is Mike from IT Security. We flagged unusual login activity on your account. I need to verify it is really you. Can you read me the one-time code we just texted to your phone?"

## The red flags in that call

1. **Authority** - claims to be IT / Security
2. **Urgency** - "unusual activity", act right now
3. **The ask** - your one-time MFA code. No legitimate IT team will ever ask you to read this out.

## Common vishing scenarios

- **Fake IT support** - asks for your MFA code or password to "verify" you
- **Fake executive** - "I'm stuck in a meeting, process this urgent wire transfer"
- **Fake bank fraud alert** - robocall pressure: "press 1 to stop this charge"

## How to defend

1. Never read an MFA or one-time code to anyone who calls you
2. Hang up and call back on a number YOU look up, not the one they gave you
3. Verify any urgent money or access request through a second known channel
4. Slow down. The urgency is the attack, not the emergency.`,
    },
    {
      id: "social-quiz-1",
      title: "Spot the Phish",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "You receive an email from 'CEO@yourcompany.com' asking you to urgently wire $50,000 to a vendor. The email looks legitimate. What should you do FIRST?",
        options: [
          "Forward it to your manager for approval",
          "Call or message the CEO directly through a known channel to verify",
          "Check if the amount matches previous vendor payments",
          "Reply to the email asking for more details",
        ],
        correctAnswer: 1,
        explanation:
          "Always verify unusual requests through a separate, trusted channel (phone call, in-person, or known messaging platform). Don't reply to the email, as that reaches the attacker. Email addresses can be spoofed, and even legitimate-looking emails may be fraudulent. This is a common Business Email Compromise (BEC) scenario that has cost organizations billions.",
      },
    },
    {
      id: "pretexting-deepfakes",
      title: "Pretexting & Deepfakes",
      type: "theory",
      content: `# Pretexting & Deepfakes

Pretexting creates a fabricated scenario to manipulate victims. Deepfakes use AI to make these scenarios terrifyingly convincing.

## The Art of Pretexting

### Common Pretexts

**IT Support Scam:**
\`\`\`
"Hi, this is Mike from IT. We're doing a security audit and
noticed your machine hasn't been updated. I need to remote in
to install a critical patch. Can you give me your login?"
\`\`\`

**Authority Figure:**
\`\`\`
"This is Agent Johnson from the FBI Cyber Division. Your
company's network has been compromised. I need you to
preserve evidence by sending me the server access logs."
\`\`\`

**Vendor/Partner:**
\`\`\`
"Hi Sarah, it's Tom from Acme Corp. I can't reach my usual
contact - our invoice portal is down and we need payment
details updated to a new bank account before the wire."
\`\`\`

### Pretext Elements
- **Believable backstory** - Researched and specific
- **Authority or rapport** - Why should victim comply?
- **Urgency** - Why can't this wait?
- **Plausible request** - Fits the scenario

## AI-Powered Attacks

### Voice Cloning
\`\`\`
# Only needs ~3 seconds of audio to clone a voice
# Attackers source from: YouTube, podcasts, earnings calls

Real CEO recording from earnings call → AI model
                                           ↓
                        "CFO, wire $2.4M immediately"
\`\`\`

**2024 Case:** UK energy company lost $243,000 when attackers used AI to clone their German parent company CEO's voice.

### Deepfake Video

\`\`\`
Video Conference Attack:
1. Attacker joins Zoom as "CEO" with camera off
2. "Technical issues" - asks to call back
3. Returns with deepfake video of CEO
4. Requests urgent wire transfer "while traveling"
\`\`\`

**2024 Case:** Hong Kong multinational lost $25.6M to deepfake video call where entire finance team was impersonated.

### AI-Generated Phishing

\`\`\`
# Old phishing - obvious errors
"Dear Costumer, You're account is suspend. Click hear to verify"

# AI-generated - perfect and personalized
"Hi Sarah,

Following up on our conversation at the Chicago conference
last month. I've attached the partnership proposal we discussed.
Let me know your thoughts when you get a chance.

Best,
Michael Chen
VP Business Development, TechCorp"
\`\`\`

## Defense Against Modern Social Engineering

### Verification Protocols
\`\`\`javascript
// Implement callback verification for sensitive requests
const verifyRequest = async (request) => {
  // Never use contact info from the request itself
  const knownContact = await getVerifiedContact(request.sender);

  // Use out-of-band verification
  await sendVerificationRequest(knownContact.phone);

  // Require dual approval for financial transactions
  if (request.amount > THRESHOLD) {
    await requireDualApproval(request);
  }
};
\`\`\`

### Code Words/Phrases
Establish verbal passwords for sensitive requests:
- "What's the security word?"
- Rotating verification codes
- Pre-shared passphrases for wire transfers

### Trust But Verify Culture
- It's OK to question authority
- It's OK to delay urgent requests
- It's OK to hang up and call back
- Reward employees who catch attacks`,
    },
    {
      id: "social-quiz-2",
      title: "Deepfake Defense",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "During a video call, your 'CEO' (who you've met in person) asks you to process an urgent wire transfer. The video quality is perfect and the voice sounds right. What's the BEST defense?",
        options: [
          "Trust it because the video looks authentic",
          "Ask security questions only the real CEO would know",
          "Hang up and call back using a verified number from your contacts",
          "Check if the CEO's calendar shows they should be available",
        ],
        correctAnswer: 2,
        explanation:
          "Deepfakes can now perfectly replicate appearance and voice. Security questions can be researched through OSINT. The only reliable defense is out-of-band verification: hang up and initiate contact through a known, trusted channel. This breaks the attacker's control of the communication. Calendar checks aren't reliable as attackers can time their attacks.",
      },
    },
    {
      id: "osint-awareness",
      title: "OSINT & Attack Preparation",
      type: "theory",
      content: `# OSINT & Attack Preparation

Attackers research targets extensively before striking. Understanding what information is exposed helps you protect it.

## What Attackers Find About You

### Professional Information (LinkedIn)
\`\`\`
✓ Full name, title, company
✓ Work history and timeline
✓ Colleagues and org structure
✓ Skills and technologies used
✓ Projects and accomplishments
✓ Email format (from connections)
\`\`\`

### Personal Information (Social Media)
\`\`\`
✓ Birthdate, location, family
✓ Pets (common password material)
✓ Travel plans (when you're away)
✓ Interests and hobbies
✓ Check-ins and location history
✓ Photos with metadata
\`\`\`

### Technical Information (Passive)
\`\`\`
✓ Company tech stack (job postings)
✓ Vendor relationships (press releases)
✓ Internal tools (GitHub commits)
✓ Employee email addresses (breach databases)
✓ Subdomain enumeration
✓ Cloud storage misconfigurations
\`\`\`

## OSINT Tools Attackers Use

### Email Discovery
\`\`\`bash
# Tools like Hunter.io, Phonebook.cz
# Find email format: first.last@company.com

# theHarvester - passive reconnaissance
theHarvester -d company.com -b google,linkedin
\`\`\`

### Social Media Mining
\`\`\`bash
# LinkedIn scrapers for org charts
# Instagram/Facebook for personal details
# Twitter for real-time information
# GitHub for code and internal references
\`\`\`

### Data Breaches
\`\`\`bash
# Have I Been Pwned - check if credentials leaked
# Dehashed, LeakCheck - password breach databases
# Attackers correlate leaked passwords across services
\`\`\`

## Real Attack Scenario

\`\`\`
OSINT Phase:
1. Find target: Sarah Chen, Finance Manager
2. LinkedIn: Reports to CFO James Wilson
3. Twitter: @sarah_chen - posts about dog "Max"
4. Instagram: Vacation in Hawaii next week
5. GitHub: Company repo shows Slack, Okta used
6. Hunter.io: email format is first.last@company.com

Attack Execution:
Subject: Quick favor while James is traveling

Hi Sarah,

James asked me to reach out while he's at the board meeting.
We need to update the vendor payment details for Acme Corp
before the wire goes out Friday.

Can you update the bank routing to: [attacker account]

Max says hi! 🐕 (see you brought him to the office last week)

Thanks,
"IT Finance Support"
\`\`\`

## Protecting Your Information

### Social Media Hygiene
- Audit privacy settings quarterly
- Don't post travel plans in advance
- Avoid sharing workplace details
- Be careful with location check-ins
- Consider what photos reveal (badges, screens)

### Professional Presence
- Limit LinkedIn connection visibility
- Be vague about specific projects
- Don't list internal tools/systems
- Consider who can see your activity

### Email Protection
- Use different emails for different purposes
- Don't use work email for personal signups
- Monitor breach notifications
- Enable MFA everywhere

What's public is what attackers use. Minimize your exposure.`,
    },
    {
      id: "social-quiz-3",
      title: "OSINT Awareness",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "An attacker wants to craft a convincing spear phishing email targeting you. Which piece of public information is MOST valuable to them?",
        options: [
          "Your professional headshot photo",
          "Your current job title and company",
          "The name of a colleague you frequently interact with",
          "Your alma mater from 10 years ago",
        ],
        correctAnswer: 2,
        explanation:
          "Knowing a colleague's name allows attackers to impersonate someone you trust and work with. An email 'from' a known colleague is far more likely to be opened and acted upon than one from a stranger. Job title helps with targeting but colleague relationships enable highly convincing pretexts. This is why protecting your professional network connections is important.",
      },
    },
    {
      id: "social-engineering-lab",
      title: "Lab: Phishing Detection",
      type: "lab",
      content:
        "Implement a phishing detection function that analyzes email attributes. Check for: (1) mismatched sender display name vs email domain, (2) suspicious urgency keywords, (3) known phishing domains. Return risk level and reasons.",
      lab: {
        initialCode: `function analyzeEmail(email) {
  // email = { from: "John Smith <john@evil.com>", subject: "...", body: "..." }

  // TODO: Implement phishing detection
  // Check for:
  // 1. Display name doesn't match email domain
  // 2. Urgency keywords in subject/body
  // 3. Suspicious domain patterns

  return {
    riskLevel: "low", // "low", "medium", "high"
    reasons: []
  };
}

// Test cases
analyzeEmail({
  from: "IT Support <security@company-verify.com>",
  subject: "URGENT: Password expires in 24 hours",
  body: "Click here immediately to reset your password"
});`,
        solutionCode: `const URGENCY_KEYWORDS = [
  'urgent', 'immediately', 'expires', 'suspended',
  'verify now', 'act now', '24 hours', 'limited time'
];

const SUSPICIOUS_PATTERNS = [
  /-verify\\.com$/,
  /-secure\\.com$/,
  /-support\\.com$/,
  /\\d{5,}/  // Many numbers in domain
];

function analyzeEmail(email) {
  const reasons = [];
  let riskScore = 0;

  // Extract display name and email address
  const fromMatch = email.from.match(/^(.+?)\\s*<(.+)>$/);
  if (fromMatch) {
    const displayName = fromMatch[1].toLowerCase();
    const emailAddr = fromMatch[2].toLowerCase();
    const domain = emailAddr.split('@')[1];

    // Check for name/domain mismatch
    if (displayName.includes('support') || displayName.includes('security')) {
      if (!domain.includes('company.com')) {
        reasons.push('Display name suggests official source but domain is suspicious');
        riskScore += 3;
      }
    }
  }

  // Check for urgency keywords
  const content = (email.subject + ' ' + email.body).toLowerCase();
  for (const keyword of URGENCY_KEYWORDS) {
    if (content.includes(keyword)) {
      reasons.push(\`Contains urgency keyword: "\${keyword}"\`);
      riskScore += 2;
      break;
    }
  }

  // Check for suspicious domain patterns
  const domain = email.from.match(/@([^>]+)/)?.[1] || '';
  for (const pattern of SUSPICIOUS_PATTERNS) {
    if (pattern.test(domain)) {
      reasons.push('Domain matches suspicious pattern');
      riskScore += 3;
    }
  }

  return {
    riskLevel: riskScore >= 5 ? 'high' : riskScore >= 2 ? 'medium' : 'low',
    reasons
  };
}`,
        instructions:
          "1. Create URGENCY_KEYWORDS array with terms like 'urgent', 'immediately', 'expires'. 2. Create SUSPICIOUS_PATTERNS array with regex for fake domains. 3. Extract display name and email from the 'from' field. 4. Check if display name suggests official source but domain doesn't match. 5. Check subject and body for urgency keywords. 6. Return riskLevel based on score and list of reasons.",
      },
    },
  ],
};
