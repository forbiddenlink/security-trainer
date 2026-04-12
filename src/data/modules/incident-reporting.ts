import type { Module } from '../../types';

export const incidentReporting: Module = {
    id: 'incident-reporting',
    title: 'Security Incident Reporting',
    description: 'Learn to recognize security incidents, understand why rapid reporting matters, and know exactly what to do when something goes wrong.',
    difficulty: 'Beginner',
    xpReward: 150,
    locked: false,
    lessons: [
        {
            id: 'incident-what-is',
            title: 'What Is a Security Incident?',
            type: 'theory',
            content: `# What Is a Security Incident?

## Mission Briefing

Agent, a security incident is any event that threatens the confidentiality, integrity, or availability of your organization's information or systems. Your ability to recognize and report these incidents quickly can mean the difference between a minor hiccup and a catastrophic breach.

The uncomfortable truth: most major breaches aren't caused by sophisticated hackers in dark rooms. They're caused by ordinary incidents that went unreported or were ignored until it was too late.

## Types of Security Incidents

### 1. Data Breach

Unauthorized access to or exposure of sensitive data:

\`\`\`
Examples:
  → Email sent to the wrong recipient containing PII
  → Laptop with unencrypted customer data stolen
  → Database exposed on the internet without authentication
  → Employee downloads customer list before leaving company
  → Cloud storage bucket accidentally set to public
\`\`\`

### 2. Malware Infection

Malicious software installed on a system:

\`\`\`
Examples:
  → Computer suddenly running very slowly
  → Strange pop-ups or browser redirects
  → Files encrypted with ransom demand (ransomware)
  → Antivirus detects and quarantines a threat
  → Unknown programs appearing in startup
\`\`\`

### 3. Unauthorized Access

Someone accessing systems or data they shouldn't:

\`\`\`
Examples:
  → Login alerts from a location you've never been
  → Account locked out due to failed password attempts
  → Unfamiliar devices connected to your account
  → Colleague accessing files outside their department
  → Former employee still has active system access
\`\`\`

### 4. Lost or Stolen Devices

Physical loss of devices containing organizational data:

\`\`\`
Examples:
  → Laptop left in a taxi or at a conference
  → Phone stolen from a restaurant table
  → USB drive with project files missing
  → Tablet left on an airplane
  → Company badge lost or stolen
\`\`\`

### 5. Suspicious Activity

Anything that doesn't seem right, even if you're not sure:

\`\`\`
Examples:
  → A stranger tailgating through a secure door
  → An unfamiliar person at a desk in your area
  → A phone call asking for passwords or system details
  → A coworker asking for access they shouldn't need
  → Unusual emails appearing in your "Sent" folder
\`\`\`

## Why Reporting Matters

### Speed Saves Money

The cost of a breach increases dramatically with time:

\`\`\`
Time to Identify & Contain:    Average Cost:
  Under 200 days               $3.4 million
  Over 200 days                $4.9 million
  (Source: IBM Cost of a Data Breach Report 2024)
\`\`\`

Every hour of delay gives attackers more time to:
- Spread deeper into the network
- Exfiltrate more data
- Cover their tracks
- Establish persistent access

### You See What Security Teams Can't

Security teams monitor network traffic, logs, and alerts. But they can't see:
- That you received a suspicious phone call
- That someone was looking over your shoulder
- That a USB drive appeared on your desk
- That a door was propped open in the server room
- That a colleague mentioned sharing their password

**You are the human sensor network.** Your report might be the missing piece that connects the dots.

## Real-World Intel

**Case File: Target Data Breach (2013) -- Warning Signs Ignored**

In late 2013, Target suffered a massive data breach that exposed 40 million credit card numbers and 70 million customer records. The breach cost Target over $290 million.

Here's the critical detail: Target's $1.6 million security monitoring system (FireEye) actually detected the malware and sent alerts to the security team in Bangalore, India. Those alerts were escalated to the Minneapolis headquarters. **The warnings were ignored.**

The malware had been active for nearly two weeks before an external party (the U.S. Department of Justice) notified Target of the breach. If the initial alerts had been investigated when they were first raised, the breach could have been contained before any customer data was stolen.

**The lesson:** Reporting isn't enough -- the reports must be taken seriously and acted upon. But the first step is always making the report. If you see something, say something. Let the security team decide if it's a false alarm.

## The Reporting Chain

Every organization should have a clear incident reporting chain:

\`\`\`
You notice something suspicious
        ↓
Report to your direct manager AND IT Security
        ↓
IT Security triages the incident
        ↓
Incident Response Team investigates
        ↓
Containment → Eradication → Recovery
        ↓
Lessons learned & process improvement
\`\`\`

**Key principle:** Report UP and report FAST. Don't try to investigate or fix it yourself. Don't wait until you're "sure" it's an incident. A false alarm is always better than a late report.
            `
        },
        {
            id: 'incident-quiz-identify',
            title: 'Is This an Incident?',
            type: 'quiz',
            content: '',
            quiz: {
                question: "You accidentally sent an email containing a spreadsheet with customer names and email addresses to a personal Gmail address instead of your colleague. The email has already been delivered. Is this a security incident?",
                options: [
                    "No -- it was an honest mistake, not a hack. Just delete it from the Gmail and move on.",
                    "Yes -- this is a data breach involving customer PII sent to an unauthorized destination, and must be reported immediately.",
                    "Maybe -- it depends on whether the Gmail recipient reads the email or not.",
                    "No -- email addresses aren't sensitive enough to count as a data breach."
                ],
                correctAnswer: 1,
                explanation: "This IS a security incident and a potential data breach. Customer names and email addresses are Personally Identifiable Information (PII). Sending them to an unauthorized recipient (a personal Gmail account) constitutes unauthorized data exposure, regardless of intent. Under regulations like GDPR, this could require formal notification. Report it immediately -- your security team can take steps to mitigate the impact (like requesting deletion from the recipient). Honest mistakes are the cause of many data breaches, and quick reporting limits the damage."
            }
        },
        {
            id: 'incident-how-to-report',
            title: 'How to Report & Respond',
            type: 'theory',
            content: `# How to Report & Respond

## Intel Report: Your Incident Response Playbook

Agent, knowing an incident happened is only half the battle. How you respond in the first few minutes can determine whether the incident is contained quickly or spirals into a full-scale breach. This briefing gives you the exact steps to follow.

## Step 1: Don't Panic, Don't Fix It

Your first instinct might be to try to fix the problem yourself. **Resist that urge.**

\`\`\`
DON'T:
  ✗ Try to delete malware yourself
  ✗ Turn off your computer (may destroy evidence)
  ✗ Unplug network cables (unless told to by IT)
  ✗ Try to "undo" the incident
  ✗ Delete logs or emails related to the incident
  ✗ Confront someone you suspect of wrongdoing

DO:
  ✓ Stay calm and note what you observed
  ✓ Stop using the affected system if possible
  ✓ Write down the time and what happened
  ✓ Contact your security team immediately
  ✓ Preserve everything as-is
\`\`\`

**Why not turn off the computer?** If malware is active, the computer's memory (RAM) contains evidence of what the malware is doing, where it's communicating, and how it got in. Turning off the computer destroys that evidence. Your forensics team needs it.

## Step 2: Capture the Details

When reporting, provide as much of this information as possible:

### The Incident Report Checklist

\`\`\`
WHAT happened?
  → Describe what you observed in plain language
  → "I received an email that looked like it was from our CEO
     asking me to wire money. I clicked the link but didn't
     enter any information."

WHEN did it happen?
  → Date, time, and timezone
  → "Today at 2:15 PM EST"

WHERE did it happen?
  → Physical location and/or system affected
  → "On my work laptop while connected to the office WiFi"

WHO is involved?
  → Your identity and anyone else affected
  → "The email was sent to me and possibly the entire
     finance team"

HOW did you notice it?
  → What tipped you off?
  → "The email address didn't match our CEO's real address
     and the request was unusual"

WHAT did you do?
  → Any actions you took after noticing
  → "I closed the browser tab and did not enter any
     credentials. I haven't clicked any other links."
\`\`\`

## Step 3: Know Your Channels

Report through the fastest available channel:

\`\`\`
Priority order:
  1. Company security hotline or incident email
     (e.g., security@yourcompany.com)
  2. IT helpdesk with "security incident" flagged
  3. Your direct manager (who escalates to security)
  4. In-person to the nearest IT staff member

For phishing emails specifically:
  → Use the "Report Phish" button if your email client has one
  → Forward the suspicious email as an attachment (not inline)
     to your security team
  → Do NOT forward it to colleagues asking "Is this legit?"
\`\`\`

## Step 4: Preserve Evidence

Evidence is critical for understanding what happened and preventing it from happening again.

### What to Preserve

\`\`\`
For suspicious emails:
  ✓ Don't delete the email
  ✓ Note the full sender address
  ✓ Screenshot the email headers if possible
  ✓ Don't click any links (note the URLs by hovering)

For suspected malware:
  ✓ Don't restart or shut down
  ✓ Disconnect from WiFi (turn off WiFi, don't unplug)
  ✓ Note any unusual behavior (pop-ups, slowness)
  ✓ Screenshot any error messages or ransom notes

For unauthorized access:
  ✓ Screenshot any unfamiliar login alerts
  ✓ Note the times and locations shown
  ✓ Don't change your password yet (security may want to
     monitor the unauthorized session first)
  ✓ Check and screenshot any unfamiliar account activity

For physical incidents:
  ✓ Note the person's description
  ✓ Note the time and location
  ✓ Don't confront them directly
  ✓ Contact building security
\`\`\`

## Communication Dos and Don'ts

How you communicate about an incident matters -- both legally and practically.

\`\`\`
DO:
  ✓ Report facts, not speculation
  ✓ Use secure/approved communication channels
  ✓ Follow up if you remember additional details
  ✓ Be honest about any actions you took (including mistakes)
  ✓ Cooperate fully with the investigation

DON'T:
  ✗ Post about the incident on social media
  ✗ Discuss details with people who don't need to know
  ✗ Speculate about who caused it or how bad it is
  ✗ Contact the media or external parties
  ✗ Assume it's "not a big deal" and skip reporting
  ✗ Feel ashamed -- incidents happen to everyone
\`\`\`

## Creating a Reporting Culture

The biggest barrier to incident reporting isn't lack of process -- it's fear. People worry about:

- Looking foolish for a "false alarm"
- Getting in trouble for making a mistake
- Being seen as paranoid or disruptive
- Wasting the security team's time

**The truth:** Security teams would rather investigate 100 false alarms than miss one real incident. Every unreported incident is a potential breach. Organizations that punish reporters get fewer reports -- and more breaches.

A healthy security culture celebrates reporters, treats mistakes as learning opportunities, and makes reporting as easy as possible.
            `
        },
        {
            id: 'incident-quiz-response',
            title: 'Incident Response Scenarios',
            type: 'quiz',
            content: '',
            quiz: {
                question: "You notice your computer is running unusually slowly and a program you don't recognize is running in the background. You also see brief pop-ups appearing and disappearing. What should you do FIRST?",
                options: [
                    "Open Task Manager and try to end the unknown process, then run antivirus",
                    "Immediately shut down the computer by holding the power button to stop the malware",
                    "Disconnect from the network (turn off WiFi) and report to IT Security with details of what you observed",
                    "Ignore it for now -- it might just be a Windows update running in the background"
                ],
                correctAnswer: 2,
                explanation: "Disconnect from the network first to prevent the malware from spreading or communicating with an attacker, then immediately report to IT Security. Do NOT shut down the computer -- RAM contains crucial forensic evidence. Do NOT try to kill the process yourself -- you might trigger the malware to destroy data or spread faster. And never ignore suspicious behavior -- early reporting is the single most important factor in limiting breach damage. Let the security team investigate with proper tools."
            }
        }
    ]
};
