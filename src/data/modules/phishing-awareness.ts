import type { Module } from '../../types';

export const phishingAwareness: Module = {
    id: 'phishing-awareness',
    title: 'Phishing & Email Security',
    description: 'Learn to recognize and defend against phishing attacks, email fraud, and social engineering tactics that target everyday users.',
    difficulty: 'Beginner',
    xpReward: 200,
    locked: false,
    lessons: [
        {
            id: 'phishing-recognizing',
            title: 'Recognizing Phishing Attacks',
            type: 'theory',
            content: `# Recognizing Phishing Attacks

## Mission Briefing

Agent, phishing is the #1 attack vector used against organizations worldwide. Over 90% of data breaches start with a phishing email. Your mission: learn to spot these attacks before they compromise your organization.

Phishing isn't just a tech problem -- it's a human problem. Attackers don't need to hack a firewall if they can trick someone into handing over the keys.

## The Anatomy of a Phishing Email

Every phishing email exploits the same playbook. Once you know the pattern, you'll spot them instinctively.

### Red Flag #1: Suspicious Sender Address

The "From" name might say "Microsoft Support" but the actual email address tells a different story:

\`\`\`
Display Name:  Microsoft Account Team
Actual Email:  security-alert@micros0ft-verify.com
                              ^          ^
                         Zero, not O    Fake domain
\`\`\`

**Always check the actual email address, not just the display name.** On mobile, tap the sender name to reveal the full address. On desktop, hover over it.

### Red Flag #2: Urgency and Fear Tactics

Attackers want you to act before you think. Watch for language designed to create panic:

- "Your account will be suspended in 24 hours"
- "Unauthorized login detected -- verify immediately"
- "Failure to respond will result in legal action"
- "Your package could not be delivered -- confirm address NOW"

Legitimate organizations rarely use threatening language or extreme time pressure in emails.

### Red Flag #3: Suspicious Links

Hover over any link before clicking. The text might say one thing, but the URL goes somewhere else entirely:

\`\`\`
What you see:    Click here to verify your account
                 https://www.paypal.com/verify

Where it goes:   https://paypa1-verify.suspicious-site.com/login
                        ^                ^
                   "l" replaced with "1"  Attacker's domain
\`\`\`

**The domain that matters is the one right before the first slash.** Everything before it (subdomains) can be faked:
- \`paypal.com.evil.com/login\` -- This goes to evil.com, NOT paypal.com
- \`secure.login.paypal.com/account\` -- This goes to paypal.com (legitimate)

### Red Flag #4: Attachment Dangers

Be extremely cautious with email attachments, even from known contacts:

- **.exe, .scr, .bat** -- Executable files (never open from email)
- **.zip, .rar** -- Can hide malicious files inside
- **.docm, .xlsm** -- Macro-enabled Office files (can run malicious code)
- **.html** -- Can contain phishing forms that run locally

If you weren't expecting an attachment, verify with the sender through a separate channel before opening it.

### Red Flag #5: Generic Greetings and Poor Personalization

Legitimate services you have accounts with typically know your name:

\`\`\`
Suspicious:  "Dear Customer" / "Dear User" / "Dear Account Holder"
Legitimate:  "Hi Sarah" / "Dear Elizabeth Chen"
\`\`\`

However, be aware that sophisticated phishing can use your real name (harvested from LinkedIn, data breaches, or social media).

## Real-World Intel

**Case File #1: The Google Docs Phishing Attack (2017)**

In May 2017, a massive phishing campaign spread through Google accounts by disguising itself as a Google Docs sharing request. The email appeared to come from someone the victim knew and included a legitimate-looking "Open in Docs" button. Clicking it led to a fake Google authorization page that requested access to the victim's email and contacts. Once authorized, the worm automatically sent itself to everyone in the victim's contact list. It spread to over 1 million users in just one hour before Google shut it down. The attack was devastating because it used Google's own OAuth system -- the login page was real, but the app requesting access was malicious.

**Case File #2: Ubiquiti Networks CEO Fraud ($46.7 Million)**

In 2015, Ubiquiti Networks disclosed that attackers used spear phishing and CEO impersonation to trick employees in the finance department into wiring $46.7 million to overseas accounts controlled by the attackers. The emails appeared to come from executives and used convincing language about confidential acquisitions. The company only recovered $15 million. This type of attack -- Business Email Compromise (BEC) -- costs organizations over $50 billion annually according to the FBI.

## Your Defense Protocol

1. **Pause** -- Never act on urgency. Legitimate requests can wait 5 minutes.
2. **Inspect** -- Check the sender's actual email address, not just the display name.
3. **Hover** -- Preview links before clicking. Verify the domain is legitimate.
4. **Verify** -- When in doubt, contact the sender through a separate, known channel.
5. **Report** -- Forward suspicious emails to your IT/security team. You might save a colleague.
            `
        },
        {
            id: 'phishing-quiz-spot',
            title: 'Spot the Phish',
            type: 'quiz',
            content: '',
            quiz: {
                question: "You receive an email with the subject 'Your PayPal account has been limited.' The sender displays as 'PayPal Security' but the email address is service@paypal-notifications.security-center.com. What is the BIGGEST red flag?",
                options: [
                    "The subject line mentions account limitations",
                    "The email domain is not paypal.com -- it's security-center.com with PayPal as a subdomain",
                    "The sender name says 'PayPal Security' instead of just 'PayPal'",
                    "PayPal would never send security emails"
                ],
                correctAnswer: 1,
                explanation: "The actual domain is security-center.com, not paypal.com. The 'paypal-notifications' part is just a subdomain that anyone can create. Remember: the real domain is the last part before the first slash (or the end of the address). PayPal does send security emails, but always from @paypal.com or @mail.paypal.com -- never from a third-party domain."
            }
        },
        {
            id: 'phishing-advanced-social',
            title: 'Advanced Social Engineering via Email',
            type: 'theory',
            content: `# Advanced Social Engineering via Email

## Intel Report: The Evolution of Email Attacks

Agent, basic phishing is just the beginning. The most dangerous email attacks are precisely targeted, well-researched, and increasingly powered by AI. This briefing covers the advanced tactics you need to recognize.

## Spear Phishing: The Targeted Strike

Unlike mass phishing that casts a wide net, spear phishing targets specific individuals using personal information gathered from social media, company websites, and data breaches.

\`\`\`
Mass Phishing:
  "Dear Customer, your account needs verification..."
  → Sent to 100,000 random addresses
  → Success rate: ~3%

Spear Phishing:
  "Hi Sarah, following up on the Henderson project from
   Tuesday's meeting. James asked me to send the updated
   budget spreadsheet. Can you review before the board
   meeting Thursday?"
  → Sent to 1 specific person
  → Success rate: ~65%
\`\`\`

Spear phishing works because attackers research their targets. They know your name, your colleagues, your projects, and your schedule -- often just from LinkedIn and your company's website.

## Whaling: Targeting the Big Fish

Whaling attacks target executives, board members, and senior leadership -- the people with the most access and authority.

\`\`\`
Typical whaling email:
  From: "Board Chair" <chair@board-governance.com>
  To: CEO
  Subject: Confidential - Upcoming Acquisition

  The board has approved the preliminary acquisition of
  TechStart Inc. Legal needs a $2.3M escrow deposit before
  we can proceed. Please wire to the attached account by
  end of business. Keep this confidential until announced.
\`\`\`

Whaling is particularly effective because:
- Executives are busy and make quick decisions
- They have authority to approve large transactions
- They may bypass normal approval processes for "confidential" matters
- Subordinates are unlikely to question requests from leadership

## Business Email Compromise (BEC)

BEC attacks compromise or impersonate business email accounts to redirect payments, steal data, or authorize fraudulent transactions. The FBI calls it the "$50 billion scam."

Common BEC scenarios:
1. **Invoice fraud** -- "Our bank details have changed. Please update your records."
2. **CEO impersonation** -- "Process this wire transfer. I'm in a meeting and can't call."
3. **Vendor impersonation** -- "Please send payment to our new account."
4. **Payroll diversion** -- "Please update my direct deposit to this new account."

## Pretexting: The Backstory Attack

Pretexting builds an elaborate, believable backstory to manipulate victims. The attacker creates a scenario where the request seems natural:

- **IT helpdesk**: "We're migrating email servers tonight. I need your credentials to test your mailbox migration."
- **HR department**: "Annual benefits enrollment requires you to verify your SSN at this link."
- **Building security**: "We're updating access badges. Please confirm your employee ID and department."
- **Vendor**: "We're switching billing systems. Can you confirm the last four digits of the credit card on file?"

The key defense: **legitimate organizations will never ask for passwords, full SSNs, or sensitive credentials via email.**

## AI-Generated Phishing: The New Frontier

AI tools have made phishing dramatically more sophisticated:

### What AI Changes
- **Perfect grammar and spelling** -- No more "Dear Costumer" typos to spot
- **Personalized content at scale** -- AI can write unique, targeted emails for thousands of people
- **Convincing conversation** -- AI chatbots can engage in back-and-forth pretexting
- **Voice cloning** -- 3 seconds of audio is enough to clone someone's voice
- **Deepfake video** -- Real-time face swapping for video call impersonation

### Real Case: The $25.6 Million Deepfake Video Call (2024)

In early 2024, a finance worker at a Hong Kong multinational was tricked into transferring $25.6 million after attending a video call where every other participant -- including the company's CFO -- was a deepfake. The attackers used publicly available video footage to create real-time deepfakes of multiple executives, making the fraudulent authorization appear entirely legitimate.

## Your Advanced Defense Protocol

1. **Verify financial requests** through a separate channel (phone call to a known number, in-person, or company messaging platform)
2. **Question urgency** -- "This can't wait" is almost always a manipulation tactic
3. **Check for context** -- Were you expecting this? Does this match normal processes?
4. **Use code words** -- Establish verbal verification codes for sensitive transactions
5. **Trust your instincts** -- If something feels off, it probably is. Report it.
6. **Remember: AI can fake anything digital** -- Voice, video, email, and chat can all be fabricated
            `
        },
        {
            id: 'phishing-quiz-scenarios',
            title: 'What Would You Do?',
            type: 'quiz',
            content: '',
            quiz: {
                question: "You receive an urgent email from your CEO's email address asking you to purchase $2,000 in gift cards for a client appreciation event and send the codes. The CEO mentions they're in a meeting and can't talk. What should you do?",
                options: [
                    "Buy the gift cards quickly since it's from the CEO and sounds urgent",
                    "Reply to the email asking for more details about the event",
                    "Contact the CEO through a different channel (phone, Slack, in-person) to verify the request",
                    "Forward the email to a coworker to get their opinion"
                ],
                correctAnswer: 2,
                explanation: "This is a classic Business Email Compromise (BEC) scam. Gift card requests from executives are one of the most common phishing tactics because gift cards are untraceable once the codes are sent. Never reply to the suspicious email (that just reaches the attacker). Always verify through a separate, trusted channel -- call the CEO's known phone number or message them on your company's internal platform. The 'I'm in a meeting and can't talk' line is specifically designed to prevent you from calling to verify."
            }
        },
        {
            id: 'phishing-lab-triage',
            title: 'Email Triage Exercise',
            type: 'lab',
            content: 'You\'ve intercepted a suspicious email. Your mission: analyze the email headers and body to identify every red flag. Mark each suspicious element in the analysis object.',
            lab: {
                initialCode: `// INTERCEPTED EMAIL
// ==================
// Analyze this email and identify all red flags.
// Set each flag to true if you find the corresponding issue.

const suspiciousEmail = {
  from: {
    displayName: "IT Security Team",
    emailAddress: "security@your-company-ithelp.net"
  },
  replyTo: "helpdesk-update@gmail.com",
  to: "all-staff@yourcompany.com",
  subject: "URGENT: Password Expiry - Action Required Within 24 Hours",
  body: \`
    Dear Employee,

    Our security system has detected that your password will expire
    in 24 hours. To avoid being locked out of your account, you must
    reset your password immediately.

    Click here to reset: http://yourcompany-secure-login.tk/reset

    If you do not reset your password within 24 hours, your account
    will be permanently suspended and all data will be lost.

    Best regards,
    IT Security Team
    Your Company Inc.
  \`,
  attachments: ["Password_Reset_Form.html"],
  receivedDate: "Monday 9:02 AM"
};

// YOUR ANALYSIS: Set each red flag to true or false
const redFlags = {
  // Is the sender domain suspicious? (not the real company domain)
  suspiciousSenderDomain: false,

  // Does the reply-to address differ from the sender?
  mismatchedReplyTo: false,

  // Does the email use urgency/fear tactics?
  urgencyTactics: false,

  // Is the link URL suspicious?
  suspiciousLink: false,

  // Is the greeting generic rather than personalized?
  genericGreeting: false,

  // Does it threaten negative consequences?
  threatOfConsequences: false,

  // Is the attachment potentially dangerous?
  dangerousAttachment: false,

  // Is it sent to a broad distribution list?
  broadDistribution: false
};

// Set ALL red flags to true that apply!`,
                solutionCode: `// INTERCEPTED EMAIL
// ==================
const suspiciousEmail = {
  from: {
    displayName: "IT Security Team",
    emailAddress: "security@your-company-ithelp.net"
  },
  replyTo: "helpdesk-update@gmail.com",
  to: "all-staff@yourcompany.com",
  subject: "URGENT: Password Expiry - Action Required Within 24 Hours",
  body: \`
    Dear Employee,

    Our security system has detected that your password will expire
    in 24 hours. To avoid being locked out of your account, you must
    reset your password immediately.

    Click here to reset: http://yourcompany-secure-login.tk/reset

    If you do not reset your password within 24 hours, your account
    will be permanently suspended and all data will be lost.

    Best regards,
    IT Security Team
    Your Company Inc.
  \`,
  attachments: ["Password_Reset_Form.html"],
  receivedDate: "Monday 9:02 AM"
};

// ANALYSIS: ALL of these are red flags in this email!
const redFlags = {
  // "your-company-ithelp.net" is NOT the real company domain
  suspiciousSenderDomain: true,

  // Reply-to goes to a gmail address, not the sender
  mismatchedReplyTo: true,

  // "URGENT", "Action Required Within 24 Hours"
  urgencyTactics: true,

  // .tk domain, HTTP not HTTPS, fake company name in URL
  suspiciousLink: true,

  // "Dear Employee" instead of using your actual name
  genericGreeting: true,

  // "permanently suspended and all data will be lost"
  threatOfConsequences: true,

  // .html attachment can contain a local phishing form
  dangerousAttachment: true,

  // Sent to all-staff, not targeted to you specifically
  broadDistribution: true
};`,
                instructions: "Analyze the intercepted email carefully. For each item in the redFlags object, determine whether that red flag is present in this email. Set each one to true if the red flag applies. HINT: Every single red flag in this email is real -- this is a textbook phishing attempt with ALL flags present."
            }
        }
    ]
};
