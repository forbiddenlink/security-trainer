import type { Module } from '../../types';

export const pciDssEssentials: Module = {
    id: 'pci-dss-essentials',
    title: 'PCI-DSS Essentials',
    description: 'Understand the Payment Card Industry Data Security Standard -- the rules that govern how every organization handling credit card data must protect it. Learn the 12 requirements, SAQ levels, and secure payment implementation.',
    difficulty: 'Intermediate',
    xpReward: 350,
    locked: false,
    lessons: [
        {
            id: 'pci-overview',
            title: 'Understanding PCI-DSS',
            type: 'theory',
            content: `
# Mission Briefing: PCI-DSS

The Payment Card Industry Data Security Standard (PCI-DSS) is a set of security requirements created by the major card brands (Visa, Mastercard, American Express, Discover, JCB) through the PCI Security Standards Council. Any organization that stores, processes, or transmits cardholder data must comply.

## Who Needs PCI Compliance?

If your system touches credit card numbers at any point -- even briefly -- PCI-DSS applies. This includes:

- **Merchants** (online stores, brick-and-mortar retailers, SaaS with billing)
- **Payment processors** (Stripe, Square, Adyen)
- **Service providers** (hosting companies, managed security providers)
- **Any third party** with access to cardholder data

## The 12 Requirements (PCI-DSS v4.0)

PCI-DSS is organized into 6 goals with 12 requirements:

### Build and Maintain a Secure Network and Systems
1. **Install and maintain network security controls** (firewalls, WAFs, network segmentation)
2. **Apply secure configurations to all system components** (change defaults, disable unnecessary services)

### Protect Account Data
3. **Protect stored account data** (encryption, truncation, masking, hashing)
4. **Protect cardholder data with strong cryptography during transmission** over open, public networks (TLS 1.2+)

### Maintain a Vulnerability Management Program
5. **Protect all systems and networks from malicious software** (anti-malware, application whitelisting)
6. **Develop and maintain secure systems and software** (patching, secure SDLC, code reviews)

### Implement Strong Access Control Measures
7. **Restrict access to system components and cardholder data by business need to know**
8. **Identify users and authenticate access** (unique IDs, MFA for remote access, strong passwords)
9. **Restrict physical access to cardholder data** (badges, cameras, visitor logs)

### Regularly Monitor and Test Networks
10. **Log and monitor all access to system components and cardholder data** (audit trails, centralized logging)
11. **Test security of systems and networks regularly** (vulnerability scans, penetration tests, file integrity monitoring)

### Maintain an Information Security Policy
12. **Support information security with organizational policies and programs** (security policies, risk assessments, security awareness training)

## Merchant Levels

Visa defines four merchant levels based on annual transaction volume:

| Level | Annual Transactions | Validation Requirements |
|-------|-------------------|----------------------|
| 1 | Over 6 million | Annual on-site audit by QSA, quarterly network scan |
| 2 | 1-6 million | Annual SAQ, quarterly network scan |
| 3 | 20,000-1 million (e-commerce) | Annual SAQ, quarterly network scan |
| 4 | Under 20,000 (e-commerce) or up to 1 million (other) | Annual SAQ, quarterly network scan recommended |

## Self-Assessment Questionnaires (SAQs)

SAQs are how most small-to-medium businesses validate compliance:

- **SAQ A:** Card-not-present merchants who fully outsource payment processing (e.g., Stripe Checkout redirect). Fewest requirements.
- **SAQ A-EP:** E-commerce merchants that partially outsource but control the payment page (e.g., Stripe Elements on your page).
- **SAQ B:** Merchants using only imprint machines or standalone terminals.
- **SAQ C:** Merchants with payment application systems connected to the internet.
- **SAQ D:** Everyone else -- the full assessment with all requirements.

## Case Files: Payment Data Breaches

**Heartland Payment Systems (2008):**
The largest payment card breach at the time -- 130 million card numbers stolen via SQL injection. Heartland was processing 100 million transactions per month. The breach cost them over **$200 million** in settlements and they were temporarily removed from Visa's list of PCI-compliant providers.

**Target (2013):**
40 million credit and debit card numbers stolen during the holiday shopping season. Attackers entered through an HVAC vendor's compromised credentials, moved laterally to point-of-sale systems, and installed RAM-scraping malware. The breach cost Target **$292 million**, including an $18.5 million multi-state settlement.

**Home Depot (2014):**
56 million payment cards compromised over 5 months. Attackers used a vendor's stolen credentials to access the network, then deployed custom malware on self-checkout terminals. The breach cost Home Depot **$179 million** in settlements and remediation.

**British Airways (2018):**
Magecart attackers injected malicious JavaScript into BA's payment page, skimming 380,000 payment cards over two weeks. The script modified the payment form to send card details to an attacker-controlled server while still processing the legitimate transaction.
            `
        },
        {
            id: 'pci-quiz-basics',
            title: 'PCI Compliance Basics',
            type: 'quiz',
            content: '',
            quiz: {
                question: "Your startup uses Stripe Checkout (customers are redirected to Stripe's hosted page to enter card details). Your server never sees or handles raw card numbers. Which SAQ type most likely applies to you?",
                options: [
                    "SAQ D -- because you process payments online",
                    "SAQ A -- because you fully outsource all cardholder data processing to Stripe",
                    "SAQ C -- because your system connects to the internet",
                    "No SAQ is needed -- Stripe handles all PCI compliance for you"
                ],
                correctAnswer: 1,
                explanation: "SAQ A applies to merchants who fully outsource all cardholder data functions to a PCI-compliant third party like Stripe. Since Stripe Checkout redirects the customer to Stripe's hosted page, your systems never touch card data. However, you still need to complete SAQ A -- using a compliant processor doesn't eliminate your own compliance obligations."
            }
        },
        {
            id: 'pci-implementation-theory',
            title: 'Implementing PCI Requirements',
            type: 'theory',
            content: `
# Intel Report: PCI Requirements in Practice

## Network Segmentation

Network segmentation is the most effective way to reduce your PCI scope. By isolating the Cardholder Data Environment (CDE) from the rest of your network, only the CDE systems need to meet PCI requirements.

\`\`\`
                    [Internet]
                        |
                    [Firewall]
                        |
            +-----------+-----------+
            |                       |
     [General Network]      [CDE Segment]
     (lower PCI scope)      (full PCI scope)
     - Web servers          - Payment gateway
     - App servers          - Tokenization service
     - Internal tools       - Card processing
\`\`\`

Without segmentation, your **entire network** is in scope for PCI compliance.

## Encryption Requirements

### At Rest (Requirement 3)
- Primary Account Numbers (PANs) must be rendered unreadable anywhere they are stored
- Acceptable methods: **strong one-way hash** (SHA-256 with salt), **truncation** (first 6 / last 4 only), **tokenization**, or **strong encryption** (AES-256)
- Encryption keys must be managed according to industry best practices (key rotation, split knowledge, dual control)

### In Transit (Requirement 4)
- TLS 1.2 or higher for all transmission of cardholder data over public networks
- SSL and early TLS (1.0, 1.1) are explicitly prohibited
- Internal network transmission should also use encryption where feasible

\`\`\`typescript
// GOOD: Using tokenization -- your server never sees the real card number
const paymentIntent = await stripe.paymentIntents.create({
  amount: 2000,
  currency: 'usd',
  payment_method: 'pm_card_visa',  // This is a token, not a card number
});

// BAD: Handling raw card numbers in your backend
app.post('/pay', (req, res) => {
  const { cardNumber, cvv, expiry } = req.body;  // NEVER DO THIS
  // Your entire server is now in PCI scope
});
\`\`\`

## What You Must NEVER Store

PCI-DSS absolutely prohibits storing certain data after authorization:

| Data Element | Can Store? | Protection Required |
|-------------|-----------|-------------------|
| Primary Account Number (PAN) | Yes | Must be rendered unreadable |
| Cardholder Name | Yes | Protection required |
| Expiration Date | Yes | Protection required |
| Service Code | Yes | Protection required |
| **Full Magnetic Stripe** | **NEVER** | N/A |
| **CVV/CVC** | **NEVER** | N/A |
| **PIN / PIN Block** | **NEVER** | N/A |

## Tokenization vs Encryption

**Tokenization** replaces sensitive data with a non-sensitive placeholder (token) that has no exploitable value. The original data is stored in a secure token vault (typically managed by your payment processor).

**Encryption** transforms data using an algorithm and key. The original data can be recovered with the decryption key.

For PCI compliance, **tokenization is generally preferred** because:
- Tokens are useless if stolen (no mathematical relationship to the original)
- Reduces your PCI scope dramatically
- No key management burden on your side

## Access Control (Requirements 7-8)

\`\`\`typescript
// Implement least-privilege access
const accessRoles = {
  developer: {
    canViewMaskedPAN: true,    // Last 4 digits only
    canViewFullPAN: false,
    canAccessCDE: false,
    canModifyPaymentCode: true  // With code review
  },
  supportAgent: {
    canViewMaskedPAN: true,     // For customer identification
    canViewFullPAN: false,
    canAccessCDE: false,
    canModifyPaymentCode: false
  },
  paymentAdmin: {
    canViewMaskedPAN: true,
    canViewFullPAN: true,       // With MFA + audit log
    canAccessCDE: true,
    canModifyPaymentCode: false
  }
};
\`\`\`

## Logging and Monitoring (Requirement 10)

All access to cardholder data must be logged:

- **Who** accessed the data (unique user ID)
- **What** action was performed (read, write, delete)
- **When** it happened (timestamp with time zone)
- **Where** it happened (system component)
- **Whether** it succeeded or failed

Logs must be retained for at least **12 months**, with a minimum of **3 months immediately available** for analysis.

## Vulnerability Management (Requirement 11)

- **Quarterly external vulnerability scans** by an Approved Scanning Vendor (ASV)
- **Annual penetration testing** of the CDE
- **Internal vulnerability scans** at least quarterly and after significant changes
- **File integrity monitoring** on critical system files
- **Wireless analyzer scans** quarterly (if wireless is in scope)

## PCI-DSS v4.0 Key Changes

PCI-DSS v4.0 (effective March 2025) introduces:
- **Customized approach:** Organizations can meet requirements through alternative controls
- **Targeted risk analysis:** Flexibility in determining frequency of certain activities
- **Enhanced authentication:** MFA required for all access into the CDE (not just remote)
- **Client-side security:** New requirements for managing payment page scripts (anti-Magecart)
            `
        },
        {
            id: 'pci-quiz-requirements',
            title: 'Requirement Mapping',
            type: 'quiz',
            content: '',
            quiz: {
                question: "Your e-commerce application logs all API requests for debugging purposes. A developer discovers that the payment endpoint logs include the full credit card number and CVV in the request body. Which PCI-DSS requirements does this violate?",
                options: [
                    "Only Requirement 3 (Protect stored account data) -- because card data is being stored in logs",
                    "Requirements 3 and 10 -- storing account data improperly and logging access incorrectly",
                    "Requirement 3 (stored data protection) and the absolute prohibition on storing CVV after authorization",
                    "Only Requirement 10 -- because logging should not include sensitive data"
                ],
                correctAnswer: 2,
                explanation: "This violates Requirement 3 because the PAN is stored unmasked in logs, AND it violates the absolute prohibition on storing CVV/CVC after authorization (Requirement 3.3.2). CVV must NEVER be stored after authorization, regardless of encryption. The PAN in logs must be rendered unreadable (masked, truncated, or encrypted)."
            }
        },
        {
            id: 'pci-lab-payment-flow',
            title: 'Payment Flow Security Review',
            type: 'lab',
            content: 'The following checkout flow code has multiple PCI-DSS violations. Your mission: Fix all security issues by removing prohibited data storage, adding proper masking, and implementing secure payment handling.',
            lab: {
                initialCode: `
// INSECURE checkout flow -- find and fix all PCI violations

const express = require('express');
const app = express();

// Payment processing endpoint
app.post('/api/checkout', async (req, res) => {
  const { cardNumber, cvv, expiryDate, cardholderName, amount } = req.body;

  // VIOLATION 1: Logging full card details
  console.log(\`Processing payment: card=\${cardNumber}, cvv=\${cvv}, amount=\${amount}\`);

  // VIOLATION 2: Storing card data in the database
  await db.transactions.insert({
    cardNumber: cardNumber,        // Full PAN stored in plaintext
    cvv: cvv,                      // CVV stored after authorization
    expiryDate: expiryDate,
    cardholderName: cardholderName,
    amount: amount,
    timestamp: new Date()
  });

  // VIOLATION 3: Sending card data to analytics
  analytics.track('payment_processed', {
    cardNumber: cardNumber,
    amount: amount
  });

  // Process with payment gateway
  const result = await paymentGateway.charge({
    card: cardNumber,
    cvv: cvv,
    expiry: expiryDate,
    amount: amount
  });

  // VIOLATION 4: Returning card data in response
  res.json({
    success: true,
    transactionId: result.id,
    cardNumber: cardNumber,
    message: 'Payment processed'
  });
});
`,
                solutionCode: `
// SECURE checkout flow using tokenization

const express = require('express');
const app = express();

// Payment processing endpoint -- uses payment token, not raw card data
app.post('/api/checkout', async (req, res) => {
  // Card details are tokenized client-side via Stripe Elements / similar
  const { paymentToken, amount } = req.body;

  // FIXED: Log only non-sensitive data
  console.log(\`Processing payment: token=\${paymentToken.substring(0, 8)}..., amount=\${amount}\`);

  // Process with payment gateway using token
  const result = await paymentGateway.charge({
    token: paymentToken,    // Token, not raw card data
    amount: amount
  });

  // FIXED: Store only transaction metadata -- no card data
  await db.transactions.insert({
    transactionId: result.id,
    lastFourDigits: result.card.last4,  // Only last 4 from gateway response
    cardBrand: result.card.brand,        // Visa, Mastercard, etc.
    amount: amount,
    status: result.status,
    timestamp: new Date()
  });

  // FIXED: Analytics with no card data
  analytics.track('payment_processed', {
    transactionId: result.id,
    amount: amount,
    cardBrand: result.card.brand
  });

  // FIXED: Response contains no card data
  res.json({
    success: true,
    transactionId: result.id,
    lastFour: result.card.last4,
    message: 'Payment processed'
  });
});
`,
                instructions: "Fix all PCI-DSS violations: 1) Remove all raw card data from logs -- use tokens or masked values only, 2) Never store CVV after authorization -- remove it entirely, 3) Use tokenization instead of handling raw card numbers server-side, 4) Store only transaction metadata (last 4 digits, brand) not full card data, 5) Never return card data in API responses, 6) Remove card data from analytics tracking."
            }
        }
    ]
};
