import type { Module } from '../../types';

export const safeBrowsingRemote: Module = {
    id: 'safe-browsing-remote',
    title: 'Safe Browsing & Remote Work Security',
    description: 'Master safe browsing habits, protect your home office setup, and learn to work securely from anywhere without exposing your organization to risk.',
    difficulty: 'Beginner',
    xpReward: 200,
    locked: false,
    lessons: [
        {
            id: 'safe-browsing-practices',
            title: 'Safe Browsing Practices',
            type: 'theory',
            content: `# Safe Browsing Practices

## Mission Briefing

Agent, your web browser is one of the most powerful tools on your computer -- and one of the most exploited. Every website you visit, every extension you install, and every file you download is a potential entry point for attackers. This briefing will make you a harder target.

## HTTPS: Your First Line of Defense

### Checking for HTTPS

Every time you enter sensitive information (passwords, credit card numbers, personal data), verify the connection is encrypted:

\`\`\`
SECURE (HTTPS):
  🔒 https://www.bankofamerica.com/login
  ↑    ↑
  Lock  "s" means encrypted connection
  icon

NOT SECURE (HTTP):
  ⚠️ http://www.bankofamerica.com/login
       ↑
       No "s" = your data is sent in plain text
       Anyone on the network can read it
\`\`\`

**Important nuances:**
- HTTPS means the connection is encrypted -- it does NOT mean the website is legitimate
- A phishing site can have HTTPS (e.g., \`https://bankofamerica-secure-login.com\`)
- Always check the domain name, not just the lock icon
- If your browser shows a certificate warning, do NOT proceed

### Mixed Content Warnings

Sometimes a secure page loads some elements over HTTP. Your browser may show a warning or broken lock icon. Don't enter sensitive information on pages with mixed content warnings.

## Browser Extensions: Choose Wisely

Extensions can see everything you do in your browser. A malicious extension is essentially spyware with full access to your browsing.

### Extension Safety Rules

\`\`\`
Before installing any extension:
  ✓ Check the developer -- is it a known, trusted company?
  ✓ Check the permissions -- does a calculator really need
    access to "all your browsing data"?
  ✓ Check the reviews and install count
  ✓ Check when it was last updated

Red flags:
  ✗ Extension asks for permissions far beyond its purpose
  ✗ Few reviews or suspiciously uniform 5-star reviews
  ✗ Developer has no web presence or track record
  ✗ Copycat extensions mimicking popular ones
  ✗ Extension was recently sold to a new developer
\`\`\`

**Real Case:** In 2020, a popular Chrome extension called "The Great Suspender" (with 2 million users) was sold to an unknown developer who injected malicious tracking code. Google eventually removed it, but millions of users were exposed before the takeover was discovered.

### Recommended Security Extensions

- **uBlock Origin** -- Blocks ads, trackers, and known malicious domains
- **HTTPS Everywhere** -- Forces HTTPS connections where available (now built into most browsers)
- **Privacy Badger** -- Automatically blocks invisible trackers

Keep your extension list minimal. Each extension is an additional attack surface.

## Download Safety

### The Download Danger Zone

\`\`\`
SAFE downloads:
  ✓ From official websites (microsoft.com, adobe.com)
  ✓ From official app stores (Google Play, Apple App Store)
  ✓ Files you specifically requested from known sources

DANGEROUS downloads:
  ✗ "Your computer is infected! Download this cleaner NOW"
  ✗ Free versions of paid software (cracked/pirated)
  ✗ Email attachments from unknown senders
  ✗ Pop-ups saying you need to "update Flash Player"
  ✗ Software from download aggregator sites
  ✗ Torrented files of any kind on work machines
\`\`\`

**Rule of thumb:** If you didn't go looking for it, don't download it. If something is "free" when it shouldn't be, you're paying with your security.

### Fake Update Scams

One of the most common web-based attacks:

\`\`\`
Pop-up appears:
  "Your browser is out of date!
   Click here to update Chrome immediately."

Reality:
  → Your browser updates itself automatically
  → Legitimate updates NEVER come from pop-ups
  → This "update" is malware

What to do:
  → Close the tab (don't click anything on the page)
  → Update through your browser's settings menu
  → Report the website to IT if on a work network
\`\`\`

## Social Media Privacy

### What You Share Matters

Every piece of information you share online gives attackers material for social engineering:

\`\`\`
What you post:          How attackers use it:
─────────────────────   ────────────────────────────────
Birthday celebration    Password reset security answers
Vacation photos         Know you're away from the office
New job announcement    Spear phishing with company info
Pet name & photos       Common password material
Check-in at airport     Physical security (house empty)
Kids' school name       Social engineering leverage
Political views         Emotional manipulation hooks
Work selfie             Badge info, screen contents, office layout
\`\`\`

### Privacy Settings Audit

Do this quarterly for every social media account:

\`\`\`
Facebook:
  → Settings > Privacy > Who can see your posts? → Friends only
  → Profile > About > Edit each section's audience
  → Timeline > Who can post on your timeline? → Friends

LinkedIn:
  → Settings > Visibility > Profile viewing options
  → Settings > Visibility > Connections list → Only you
  → Don't accept connections from people you don't know

Instagram:
  → Settings > Privacy > Private account → On
  → Settings > Privacy > Activity status → Off

All platforms:
  → Disable location sharing on posts
  → Audit tagged photos regularly
  → Google your own name quarterly to see what's public
\`\`\`

## Cookie Management and Tracking

### What Cookies Do

\`\`\`
Essential cookies:
  → Keep you logged in to websites
  → Remember your preferences
  → Required for sites to function

Tracking cookies (third-party):
  → Follow you across different websites
  → Build advertising profiles
  → Share your browsing habits with data brokers
  → Can reveal sensitive interests (medical, financial)
\`\`\`

### Defense Against Tracking

- **Clear cookies regularly** -- Most browsers have a "clear on exit" option
- **Use private/incognito mode** for sensitive browsing (banking, medical)
- **Block third-party cookies** -- Now default in Firefox and Safari
- **Use a content blocker** like uBlock Origin to stop trackers
- **Consider a privacy-focused browser** like Firefox or Brave for personal use
            `
        },
        {
            id: 'browsing-quiz',
            title: 'Browser Security Check',
            type: 'quiz',
            content: '',
            quiz: {
                question: "While browsing, you see a pop-up that says: 'Warning! Your computer has 3 viruses. Click here to scan and remove them now. Powered by Microsoft Security.' What should you do?",
                options: [
                    "Click the scan button since it says it's from Microsoft Security",
                    "Call the phone number shown in the pop-up to get technical support",
                    "Close the tab immediately without clicking anything on the pop-up, and run your actual antivirus software from your system tray",
                    "Enter your email to receive the free virus removal tool"
                ],
                correctAnswer: 2,
                explanation: "This is a classic 'scareware' scam. Legitimate antivirus software never uses browser pop-ups to alert you about infections. Microsoft will never show virus warnings through random websites. Close the tab without interacting with any element on the page (clicking 'X' buttons within the pop-up may trigger downloads). If concerned, run your actual antivirus from the program installed on your computer, never from a web pop-up. Calling the number would connect you to scammers who want remote access to your machine."
            }
        },
        {
            id: 'remote-work-security',
            title: 'Remote Work Security',
            type: 'theory',
            content: `# Remote Work Security

## Case File: Securing Your Remote Operations

Agent, working from home or on the road means your organization's security perimeter now extends to your kitchen table, the airport lounge, and the hotel lobby. Every remote connection is a potential entry point that attackers can exploit. Here's how to lock it down.

## Home Network Security

Your home WiFi router is now a corporate security device. Treat it like one.

### Router Security Checklist

\`\`\`
CRITICAL -- Do these immediately:
  ✓ Change the default router admin password
    Default: admin/admin or admin/password
    → These are the first things attackers try

  ✓ Change the default WiFi network name (SSID)
    Default: "NETGEAR-5G" or "Linksys-2.4"
    → Default names reveal your router model, making
      attacks easier

  ✓ Use WPA3 encryption (or WPA2 if WPA3 unavailable)
    → Never use WEP (crackable in minutes)
    → Never use "Open" networks

  ✓ Use a strong WiFi password (not your address or name)

RECOMMENDED:
  ✓ Update router firmware regularly
  ✓ Disable WPS (WiFi Protected Setup) -- easily hacked
  ✓ Create a separate guest network for visitors & IoT devices
  ✓ Disable remote router administration
\`\`\`

### Separate Your Networks

\`\`\`
Ideal home setup:
  Network 1: "Home-Work" (5GHz, strong password)
    → Your work laptop ONLY
    → Isolated from smart home devices

  Network 2: "Home-Personal" (2.4GHz)
    → Personal devices, streaming, gaming
    → Smart TVs, speakers, IoT devices

  Network 3: "Home-Guest"
    → Visitors' devices
    → No access to your other networks

Why: A compromised smart lightbulb shouldn't be able
to reach your work laptop.
\`\`\`

## VPN: Your Encrypted Tunnel

A VPN (Virtual Private Network) encrypts all traffic between your device and your company's network, preventing anyone on your local network from seeing your work activity.

\`\`\`
Without VPN:
  Your laptop → [coffee shop WiFi] → Internet
                  ↑
          Attacker can see everything

With VPN:
  Your laptop → [encrypted tunnel] → Company VPN → Internet
                  ↑
          Attacker sees only encrypted gibberish
\`\`\`

### VPN Rules

- **Always use VPN** when working outside the office
- **Especially on public WiFi** -- hotels, coffee shops, airports
- **Connect before** opening work applications or email
- **Don't split tunnel** unless IT approves it (split tunneling sends some traffic outside the VPN)
- **If VPN drops**, stop working until it reconnects

## Video Call Security

Remote work means more video calls -- and more opportunities for information leakage.

### Before the Call

\`\`\`
Check your environment:
  ✓ What's visible behind you? (whiteboards, screens, documents)
  ✓ Use a virtual background or blur for sensitive calls
  ✓ Close unnecessary tabs and applications
  ✓ Disable desktop notifications (they pop up on shared screens)
  ✓ Check screen sharing permissions

Call security:
  ✓ Use waiting rooms for external participants
  ✓ Require passwords for sensitive meetings
  ✓ Lock the meeting once all participants have joined
  ✓ Know how to remove unauthorized participants
\`\`\`

### During the Call

\`\`\`
DO:
  ✓ Share only specific windows, not your entire screen
  ✓ Mute when not speaking (prevents ambient info leakage)
  ✓ Verify participant identities for sensitive discussions
  ✓ Use your organization's approved platform

DON'T:
  ✗ Share your screen while email/Slack is visible
  ✗ Leave meetings open when stepping away
  ✗ Record calls without participant consent
  ✗ Discuss classified info if anyone unverified is present
\`\`\`

**Real Case:** "Zoombombing" became widespread in 2020 when attackers joined unprotected Zoom meetings to disrupt them, steal information, or share inappropriate content. This led to major security upgrades across all video platforms.

## Shared Devices and Family Considerations

If you work from home on a shared computer or in a shared space, additional precautions are needed:

\`\`\`
Shared computers:
  ✓ Use a separate user account for work
  ✓ Log out of all work applications when done
  ✓ Never save work passwords in a shared browser profile
  ✓ Clear browser history after work sessions
  ✓ Use private/incognito mode for work browsing

Shared spaces:
  ✓ Position screen away from high-traffic areas
  ✓ Use headphones for calls with sensitive content
  ✓ Lock your screen every time you step away (even briefly)
  ✓ Don't leave work documents on shared printers
  ✓ Secure your laptop when not at your desk
\`\`\`

## Physical Security for Remote Workers

### Screen Locks

\`\`\`
Lock your screen EVERY TIME you leave your device:
  Windows: Win + L
  Mac:     Cmd + Ctrl + Q  (or close the lid)

Set auto-lock:
  → 2 minutes of inactivity maximum
  → Require password on wake from sleep
  → Enable lock on screensaver
\`\`\`

### Shoulder Surfing Prevention

\`\`\`
In public spaces:
  ✓ Sit with your back to a wall
  ✓ Use a privacy screen filter ($20-40, worth every penny)
  ✓ Reduce screen brightness in public
  ✓ Tilt your screen away from neighbors
  ✓ Be aware of reflective surfaces behind you
  ✓ Never enter passwords when someone can see your screen
\`\`\`

## Public WiFi: Maximum Danger

Public WiFi is the most dangerous environment for work:

\`\`\`
THREAT 1: Evil Twin Networks
  Real network:  "Starbucks_WiFi"
  Fake network:  "Starbucks_Free_WiFi" (attacker-controlled)
  → All your traffic goes through the attacker

THREAT 2: Packet Sniffing
  → Attackers on the same network capture your data
  → Unencrypted traffic (HTTP) is fully visible

THREAT 3: Man-in-the-Middle
  → Attacker intercepts and potentially modifies your traffic
  → Can inject malware into downloads

THREAT 4: Session Hijacking
  → Attacker steals your session cookies
  → Can impersonate you on logged-in websites
\`\`\`

### Public WiFi Survival Guide

1. **Use your phone's hotspot** instead of public WiFi when possible
2. **Always use VPN** if you must use public WiFi
3. **Verify the network name** with staff before connecting
4. **Never access banking or sensitive accounts** on public WiFi
5. **Forget the network** after you're done (don't auto-reconnect)
6. **Turn off WiFi** when not actively using it
7. **Disable file sharing** and AirDrop in public
            `
        },
        {
            id: 'remote-quiz-risk',
            title: 'Remote Work Risk Assessment',
            type: 'quiz',
            content: '',
            quiz: {
                question: "You're working from a coffee shop and need to access your company's financial reporting system. You connected to the coffee shop's WiFi but your company VPN won't connect. What's the safest course of action?",
                options: [
                    "Go ahead and access the system since the website uses HTTPS anyway",
                    "Ask another customer if they know the WiFi password for a different network",
                    "Use your phone's mobile hotspot instead of the coffee shop WiFi, or wait until you have a secure connection",
                    "Try connecting to any other available WiFi network to see if the VPN works on those"
                ],
                correctAnswer: 2,
                explanation: "Your phone's mobile hotspot is far more secure than public WiFi -- it's your own private encrypted connection. If no hotspot is available, wait until you have a secure connection. HTTPS helps but doesn't protect against all attacks on untrusted networks, especially without VPN. Connecting to random WiFi networks is even riskier than the coffee shop's. Never access sensitive systems without VPN on public WiFi -- the financial data you're accessing makes you a high-value target."
            }
        },
        {
            id: 'remote-lab-audit',
            title: 'Workspace Security Audit',
            type: 'lab',
            content: 'You\'ve been asked to audit a remote employee\'s workspace setup. Review the description and identify every security issue.',
            lab: {
                initialCode: `// REMOTE WORKSPACE SECURITY AUDIT
// ================================
// A remote employee described their work setup.
// Identify ALL security issues.

const workspaceDescription = {
  network: {
    routerPassword: "admin",           // Default password
    wifiEncryption: "WPA2",
    wifiPassword: "123 Maple Street",  // Their home address
    networkName: "NETGEAR-R7000",      // Default SSID
    separateGuestNetwork: false,
    iotDevicesOnSameNetwork: true       // Smart speakers, cameras
  },
  physicalSetup: {
    deskLocation: "by the front window facing the street",
    screenPrivacyFilter: false,
    autoLockEnabled: false,
    autoLockTimeout: "never",
    workDocumentsOnDesk: true,         // Printed client reports
    webcamCover: false
  },
  devices: {
    sharedFamilyComputer: true,
    separateWorkAccount: false,
    passwordSavedInBrowser: true,      // On shared browser profile
    workFilesOnPersonalUSB: true,
    personalAppsOnWorkLaptop: true
  },
  connectivity: {
    vpnUsage: "only when I remember",
    publicWifiUsage: "yes, at coffee shops for work",
    autoConnectToKnownNetworks: true,
    bluetoothAlwaysOn: true
  }
};

// YOUR AUDIT: Set each finding to true if it's a security issue.
const securityIssues = {
  // Network issues
  defaultRouterPassword: false,
  weakWifiPassword: false,
  defaultNetworkName: false,
  noNetworkSegmentation: false,
  iotOnWorkNetwork: false,

  // Physical security issues
  screenVisibleFromOutside: false,
  noPrivacyFilter: false,
  noAutoLock: false,
  documentsExposed: false,
  noWebcamCover: false,

  // Device issues
  sharedComputerNoSeparation: false,
  passwordsInSharedBrowser: false,
  workDataOnPersonalUSB: false,
  personalAppsOnWorkDevice: false,

  // Connectivity issues
  inconsistentVPN: false,
  publicWifiForWork: false,
  autoConnectEnabled: false,
  bluetoothAlwaysOn: false
};

// Flag ALL the security issues!`,
                solutionCode: `// REMOTE WORKSPACE SECURITY AUDIT
// ================================
const workspaceDescription = {
  network: {
    routerPassword: "admin",
    wifiEncryption: "WPA2",
    wifiPassword: "123 Maple Street",
    networkName: "NETGEAR-R7000",
    separateGuestNetwork: false,
    iotDevicesOnSameNetwork: true
  },
  physicalSetup: {
    deskLocation: "by the front window facing the street",
    screenPrivacyFilter: false,
    autoLockEnabled: false,
    autoLockTimeout: "never",
    workDocumentsOnDesk: true,
    webcamCover: false
  },
  devices: {
    sharedFamilyComputer: true,
    separateWorkAccount: false,
    passwordSavedInBrowser: true,
    workFilesOnPersonalUSB: true,
    personalAppsOnWorkLaptop: true
  },
  connectivity: {
    vpnUsage: "only when I remember",
    publicWifiUsage: "yes, at coffee shops for work",
    autoConnectToKnownNetworks: true,
    bluetoothAlwaysOn: true
  }
};

// AUDIT FINDINGS: Every item here is a security issue!
const securityIssues = {
  // "admin" is the first password attackers try
  defaultRouterPassword: true,

  // Home address as WiFi password is easily guessable
  weakWifiPassword: true,

  // Reveals router model, enabling targeted attacks
  defaultNetworkName: true,

  // No guest network means all devices share access
  noNetworkSegmentation: true,

  // Smart speakers/cameras can be compromised entry points
  iotOnWorkNetwork: true,

  // Passersby can see screen content through the window
  screenVisibleFromOutside: true,

  // No privacy filter in a window-facing position
  noPrivacyFilter: true,

  // No auto-lock means unattended access is wide open
  noAutoLock: true,

  // Printed client reports visible to anyone in the home
  documentsExposed: true,

  // Webcam could be activated by malware for surveillance
  noWebcamCover: true,

  // Shared computer with no separate work user account
  sharedComputerNoSeparation: true,

  // Family members can access saved work passwords
  passwordsInSharedBrowser: true,

  // Personal USB could be lost, stolen, or infected
  workDataOnPersonalUSB: true,

  // Personal apps increase attack surface on work device
  personalAppsOnWorkDevice: true,

  // VPN must be ALWAYS on outside the office, not optional
  inconsistentVPN: true,

  // Public WiFi without reliable VPN is a critical risk
  publicWifiForWork: true,

  // Auto-connect can join rogue "evil twin" networks
  autoConnectEnabled: true,

  // Bluetooth always on enables proximity-based attacks
  bluetoothAlwaysOn: true
};`,
                instructions: "Review the remote workspace description carefully and identify every security issue. Set each finding in securityIssues to true if the corresponding aspect of the workspace is a security problem. Consider network security, physical security, device hygiene, and connectivity practices. HINT: This employee has prioritized convenience over security at every turn -- every item is a genuine issue."
            }
        }
    ]
};
