/**
 * Authored scenarios for Scam Survival. Everything here is fictional: fake
 * brands, placeholder domains (.example) and reserved fictional phone numbers
 * (555-01xx). Messages are rendered as static text only. Red flag names and
 * the defence habits (pause, inspect, verify) come from the existing
 * phishing and social engineering lessons, which each level links to.
 */

export type HabitTag = "pause" | "verify" | "resist_escalation" | "balanced";
export type ScamOutcome = "safe" | "risky" | "over_cautious";
export type ScenarioType = "email" | "text" | "thread" | "mixed";

export interface ScamChoice {
  id: string;
  label: string;
  outcome: ScamOutcome;
  feedback: string;
  /** Shares credentials, installs something, sends money or grants remote access. */
  catastrophic?: boolean;
}

export interface ScamScenario {
  id: string;
  /** Scenarios that share a template are the same trick in a new costume. */
  template: string;
  level: 1 | 2 | 3 | 4 | 5;
  scenario_type: ScenarioType;
  is_legitimate: boolean;
  messages: { from: string; text: string }[];
  red_flags: string[];
  choices: ScamChoice[];
  habit_tags: HabitTag[];
  /** One light line, shown only when humour is on. */
  quip?: string;
  /** Recovery guidance shown after the decision, never in the message itself. */
  recovery?: "password" | "transfer" | "gift-card";
}

export interface ScamLevel {
  level: 1 | 2 | 3 | 4 | 5;
  title: string;
  goal: string;
  /** Existing lesson to read for the theory. */
  lesson: { moduleId: string; lessonId: string; label: string };
}

export const SCAM_LEVELS: ScamLevel[] = [
  {
    level: 1,
    title: "Awareness and pausing",
    goal: "Stop and look before you click.",
    lesson: {
      moduleId: "phishing-awareness",
      lessonId: "phishing-recognizing",
      label: "Recognizing Phishing Attacks",
    },
  },
  {
    level: 2,
    title: "Verification",
    goal: "Check through a second channel you already trust.",
    lesson: {
      moduleId: "phishing-awareness",
      lessonId: "phishing-advanced-social",
      label: "Advanced Social Engineering via Email",
    },
  },
  {
    level: 3,
    title: "Social engineering",
    goal: "Slow down when a message pushes your feelings.",
    lesson: {
      moduleId: "social-engineering",
      lessonId: "social-intro",
      label: "The Human Attack Vector",
    },
  },
  {
    level: 4,
    title: "The long game",
    goal: "Notice when a normal chat drifts, and leave safely.",
    lesson: {
      moduleId: "social-engineering",
      lessonId: "pretexting-deepfakes",
      label: "Pretexting and Deepfakes",
    },
  },
  {
    level: 5,
    title: "Balanced skeptic",
    goal: "Tell real from fake without distrusting everything.",
    lesson: {
      moduleId: "phishing-awareness",
      lessonId: "phishing-recognizing",
      label: "Recognizing Phishing Attacks",
    },
  },
];

export const HABIT_BADGES: {
  tag: HabitTag;
  name: string;
  description: string;
  threshold: number;
}[] = [
  {
    tag: "pause",
    name: "Steady Pause",
    description: "You stopped and looked before acting.",
    threshold: 3,
  },
  {
    tag: "verify",
    name: "Known Channel",
    description: "You checked through a channel you already trusted.",
    threshold: 3,
  },
  {
    tag: "resist_escalation",
    name: "Pressure Proof",
    description: "You held steady when a message pushed you.",
    threshold: 3,
  },
  {
    tag: "balanced",
    name: "Balanced Skeptic",
    description: "You trusted the real ones and caught the fake ones.",
    threshold: 3,
  },
];

export const SCAM_SCENARIOS: ScamScenario[] = [
  // Level 1: awareness and pausing
  {
    id: "l1-parcel-fee",
    template: "delivery-fee",
    level: 1,
    scenario_type: "text",
    is_legitimate: false,
    messages: [
      {
        from: "+00 555-0101",
        text: "ParcelPigeon: your parcel is on hold. Pay a 1.99 fee at https://parcelpigeon-redeliver.example/pay within 12 hours or it goes back.",
      },
    ],
    red_flags: [
      "Unsolicited fee for a parcel you may not be expecting",
      "Link domain is not a delivery company's own site",
      "Deadline in hours to rush you",
    ],
    choices: [
      {
        id: "a",
        label: "Tap the link and pay the small fee",
        outcome: "risky",
        catastrophic: true,
        feedback:
          "The small fee is the bait. The payment page would collect your card details. Next time, pause before tapping.",
      },
      {
        id: "b",
        label: "Do not tap. Check your orders in the shop's app or site",
        outcome: "safe",
        feedback:
          "Nothing was waiting for you there, which is the answer. Checking in your own app is a quiet, strong habit.",
      },
      {
        id: "c",
        label: "Reply STOP to the number",
        outcome: "risky",
        feedback:
          "Replying tells the sender your number is live. Ignore and delete is better.",
      },
      {
        id: "d",
        label: "Turn off text messages from everyone forever",
        outcome: "over_cautious",
        feedback:
          "Understandable, but you would miss real codes and alerts. You only needed to skip this one link.",
      },
    ],
    habit_tags: ["pause"],
    quip: "A parcel that costs 1.99 to come home is the most expensive stamp in history.",
  },
  {
    id: "l1-locked-account",
    recovery: "password",
    template: "account-locked",
    level: 1,
    scenario_type: "email",
    is_legitimate: false,
    messages: [
      {
        from: "Pinecrest Bank Support <help@pinecrest-secure-login.example>",
        text: "Your account has been locked for your safety. Restore access now: https://pinecrest-secure-login.example/restore",
      },
    ],
    red_flags: [
      "Sender domain is not the bank's real site",
      "Urgency and a lock threat",
      "Asks you to log in through a link in the message",
    ],
    choices: [
      {
        id: "a",
        label: "Click the link and log in to unlock it",
        outcome: "risky",
        catastrophic: true,
        feedback:
          "That page would copy your login. If you have already done this, change the password and call the bank on the number on your card.",
      },
      {
        id: "b",
        label: "Look at the sender address, then open the bank app on your own",
        outcome: "safe",
        feedback:
          "Good. The address did not match, and your own app showed no lock. You paused and inspected first.",
      },
      {
        id: "c",
        label: "Forward it to friends so they know",
        outcome: "over_cautious",
        feedback:
          "Kind, but sharing live links can get someone clicked. Report it and delete it instead.",
      },
    ],
    habit_tags: ["pause"],
    quip: "If the bank really locked you out, it would not do it by email with a typo-flavoured domain.",
  },
  {
    id: "l1-gift-prize",
    template: "prize-win",
    level: 1,
    scenario_type: "email",
    is_legitimate: false,
    messages: [
      {
        from: "Lucky Spin <rewards@lucky-spin-win.example>",
        text: "Congratulations! You won a 500 gift card. Claim it before midnight: https://lucky-spin-win.example/claim",
      },
    ],
    red_flags: [
      "A prize for a contest you did not enter",
      "Claim deadline",
      "Unknown sender domain",
    ],
    choices: [
      {
        id: "a",
        label: "Claim it. It is free, what could go wrong?",
        outcome: "risky",
        catastrophic: true,
        feedback:
          "Claim pages ask for personal details or a small shipping fee. Free prizes you did not enter are a classic hook.",
      },
      {
        id: "b",
        label: "Pause, notice you never entered, and delete or report it",
        outcome: "safe",
        feedback:
          "Exactly. You did not need a link to know this one. Pausing is the habit.",
      },
      {
        id: "c",
        label: "Move your savings to a new bank, just in case",
        outcome: "over_cautious",
        feedback:
          "You did nothing wrong yet, so no big action is needed. Delete and carry on.",
      },
    ],
    habit_tags: ["pause"],
    quip: "You have not entered a draw since the school raffle in 2009.",
  },

  // Level 2: verification
  {
    id: "l2-new-bank-details",
    recovery: "transfer",
    template: "invoice-change",
    level: 2,
    scenario_type: "email",
    is_legitimate: false,
    messages: [
      {
        from: "Ledgerly Billing <billing@ledgerly-accounts.example>",
        text: "Hello, our bank details have changed. Please pay the attached overdue invoice to the new account this week.",
      },
    ],
    red_flags: [
      "Changed payment details sent by email only",
      "Pressure to pay quickly",
      "Sender domain does not match earlier invoices",
    ],
    choices: [
      {
        id: "a",
        label: "Pay to the new account to stay on good terms",
        outcome: "risky",
        catastrophic: true,
        feedback:
          "Money sent to the wrong account is hard to get back. Payment detail changes are a common trick.",
      },
      {
        id: "b",
        label: "Call the supplier on the number you already have and confirm",
        outcome: "safe",
        feedback:
          "They had not changed anything. A second, known channel beat the email.",
      },
      {
        id: "c",
        label: "Reply to the email and ask if it is real",
        outcome: "risky",
        feedback:
          "The sender controls that reply. Ask through a channel you already trust, not the one you were given.",
      },
      {
        id: "d",
        label: "Cancel the supplier and find a new one",
        outcome: "over_cautious",
        feedback:
          "A quick call would have cleared it up. No need to end a good relationship.",
      },
    ],
    habit_tags: ["verify"],
    quip: "Your supplier has never once emailed you about a bank detail change with this much enthusiasm.",
  },
  {
    id: "l2-bank-callback",
    template: "callback-number",
    level: 2,
    scenario_type: "text",
    is_legitimate: false,
    messages: [
      {
        from: "Cobalt Credit Union",
        text: "Unusual activity on your card. Call our fraud team now on 555-0142 to stop the payment.",
      },
    ],
    red_flags: [
      "Number supplied in the message, not from your card",
      "Urgency about a payment in progress",
    ],
    choices: [
      {
        id: "a",
        label: "Call 555-0142 right away",
        outcome: "risky",
        feedback:
          "The number in the message may ring the scammer. They would then ask for your card details.",
      },
      {
        id: "b",
        label: "Hang up on the idea and call the number printed on your card",
        outcome: "safe",
        feedback:
          "That is the right second channel. The real fraud team can tell you if anything is wrong.",
      },
      {
        id: "c",
        label:
          "Read your card number out to the person who answers to prove it is you",
        outcome: "risky",
        catastrophic: true,
        feedback:
          "Giving card details to an inbound caller is how these scams work. A real bank will never need that to protect you.",
      },
      {
        id: "d",
        label: "Cut up the card and close the account",
        outcome: "over_cautious",
        feedback:
          "Bigger than needed. A call to the number on your card sorts it out.",
      },
    ],
    habit_tags: ["verify"],
    quip: "A fraud team that texts you a number to call is the world's fastest-growing hobby.",
  },
  {
    id: "l2-password-expiry",
    recovery: "password",
    template: "it-password-expiry",
    level: 2,
    scenario_type: "email",
    is_legitimate: false,
    messages: [
      {
        from: "IT Helpdesk <it-helpdesk@brightcart-support.example>",
        text: "Your password expires in 24 hours. Sign in here to keep it: https://brightcart-support.example/sso",
      },
    ],
    red_flags: [
      "Sender domain is not your company's",
      "Deadline on a password change",
      "Link to a sign-in page from an email",
    ],
    choices: [
      {
        id: "a",
        label: "Sign in through the link before it expires",
        outcome: "risky",
        catastrophic: true,
        feedback:
          "That sign-in page would store your password. Real password changes happen in the tools you already use.",
      },
      {
        id: "b",
        label: "Ask the IT desk through the chat channel you normally use",
        outcome: "safe",
        feedback:
          "IT confirmed there is no expiry campaign. Asking through your own channel is the habit that wins here.",
      },
      {
        id: "c",
        label: "Never change a password again, to be safe",
        outcome: "over_cautious",
        feedback:
          "Stale passwords are also a risk. Keep your normal routine, just not through this link.",
      },
    ],
    habit_tags: ["verify"],
    quip: "Passwords do not set alarms for 24 hours from now.",
  },

  // Level 3: social engineering
  {
    id: "l3-boss-gift-cards",
    recovery: "gift-card",
    template: "authority-gift-cards",
    level: 3,
    scenario_type: "text",
    is_legitimate: false,
    messages: [
      {
        from: "Dana (CEO) +00 555-0103",
        text: "I am in a meeting and cannot talk. I need 5 store gift cards for a client today. Buy them and send me the codes. Keep it between us.",
      },
    ],
    red_flags: [
      "Authority figure from an unknown number",
      "Secrecy and urgency",
      "Gift card codes are a payment method scammers prefer",
    ],
    choices: [
      {
        id: "a",
        label: "Buy the cards and send the codes",
        outcome: "risky",
        catastrophic: true,
        feedback:
          "Gift card codes are as good as cash and cannot be recalled. Tell your finance team right away if this happened.",
      },
      {
        id: "b",
        label:
          "Say nothing yet, then check with Dana on her usual number or chat",
        outcome: "safe",
        feedback:
          "Dana knew nothing about it. Delaying and checking removed the pressure. You did not overshare either.",
      },
      {
        id: "c",
        label: "Reply asking for more details so you can judge it",
        outcome: "risky",
        feedback:
          "Engaging keeps the scammer in the conversation. Better to go to a known channel.",
      },
      {
        id: "d",
        label: "Report your boss to HR for suspicious messages",
        outcome: "over_cautious",
        feedback:
          "Your boss was not the sender. Report the message, not the person.",
      },
    ],
    habit_tags: ["resist_escalation", "verify"],
    quip: "Executives have assistants for gift cards. And for texting from unknown numbers. Mostly.",
  },
  {
    id: "l3-tax-threat",
    template: "fear-authority-threat",
    level: 3,
    scenario_type: "email",
    is_legitimate: false,
    messages: [
      {
        from: "Fenwick Tax Office <notices@fenwick-tax-refunds.example>",
        text: "FINAL NOTICE: unpaid balance. A warrant will be issued today. Confirm your full ID number and pay now to cancel it.",
      },
    ],
    red_flags: [
      "Threats of arrest or a warrant",
      "Demand for ID details and instant payment",
      "Official-sounding name on a made-up domain",
    ],
    choices: [
      {
        id: "a",
        label: "Reply with your ID number to fix it quickly",
        outcome: "risky",
        catastrophic: true,
        feedback:
          "ID numbers are what identity thieves want. Real tax bodies do not demand it by email under threat.",
      },
      {
        id: "b",
        label:
          "Take a breath, do not reply, and contact the tax office via its official site",
        outcome: "safe",
        feedback:
          "Fear makes us hurry. You waited and used an official route. That is how to beat urgency.",
      },
      {
        id: "c",
        label: "Panic, stay home, and ignore all mail for a month",
        outcome: "over_cautious",
        feedback:
          "A deep breath is plenty. You can still open real mail, just verify before acting on threats.",
      },
    ],
    habit_tags: ["resist_escalation"],
    quip: "The warrant would arrive by courier, not by a typo.",
  },
  {
    id: "l3-lost-phone-cousin",
    template: "pity-new-number",
    level: 3,
    scenario_type: "text",
    is_legitimate: false,
    messages: [
      {
        from: "Unknown number",
        text: "Hi it is me, your cousin. I lost my phone and this is my new number. I am stuck abroad. Could you send 200 for a ticket? I will pay you back.",
      },
    ],
    red_flags: [
      "New number with a sad story",
      "Request for money",
      "Does not use your name or any private detail",
    ],
    choices: [
      {
        id: "a",
        label: "Send the money, family is family",
        outcome: "risky",
        catastrophic: true,
        feedback:
          "This is a common trick that leans on kindness. Always check first, even if it feels rude.",
      },
      {
        id: "b",
        label: "Contact your cousin on the old number or through a relative",
        outcome: "safe",
        feedback:
          "Your cousin was at home with a cold. Checking on a known channel is kind and quick.",
      },
      {
        id: "c",
        label: "Ask for their bank balance as proof",
        outcome: "risky",
        feedback:
          "That does not prove who they are. Use a way you already know to reach them.",
      },
      {
        id: "d",
        label: "Block every unknown number on your phone forever",
        outcome: "over_cautious",
        feedback:
          "You would miss deliveries and real calls. Verify first, block later if it is a scam.",
      },
    ],
    habit_tags: ["resist_escalation", "verify"],
    quip: "Your cousin has never said 'stuck abroad' without a cheesy story first.",
  },

  // Level 4: the long game (threads)
  {
    id: "l4-job-offer-drift",
    template: "job-offer-advance-fee",
    level: 4,
    scenario_type: "thread",
    is_legitimate: false,
    messages: [
      {
        from: "Recruiter (Orchard Works)",
        text: "Hi, we liked your profile. Would you be open to a remote admin role?",
      },
      {
        from: "You",
        text: "Sure, I can tell you more about my background.",
      },
      {
        from: "Recruiter (Orchard Works)",
        text: "Great. The job is yours. Before you start we need a copy of your ID and your bank details for payroll.",
      },
      {
        from: "Recruiter (Orchard Works)",
        text: "You also need to buy your starter kit now, 180, and we will refund it on your first pay day.",
      },
    ],
    red_flags: [
      "Hired with no interview",
      "ID and bank details requested before a signed contract",
      "You pay for the kit up front",
    ],
    choices: [
      {
        id: "a",
        label: "Pay for the kit. You have come this far",
        outcome: "risky",
        catastrophic: true,
        feedback:
          "Already having shared a lot is no reason to share more. Stepping away costs less than carrying on.",
      },
      {
        id: "b",
        label:
          "Stop, verify the company on its official site, and leave the chat",
        outcome: "safe",
        feedback:
          "You spotted the drift, from friendly to paying them. Leaving early is a good exit.",
      },
      {
        id: "c",
        label: "Send the ID but not the money",
        outcome: "risky",
        feedback:
          "Your ID is already valuable to a scammer. Stop at the first request that feels off.",
      },
      {
        id: "d",
        label: "Give up on all online job offers",
        outcome: "over_cautious",
        feedback:
          "Plenty of recruiters are real. Verify the company and never pay to be hired.",
      },
    ],
    habit_tags: ["resist_escalation"],
    quip: "A job that makes you pay to work there is a subscription.",
  },
  {
    id: "l4-investment-friend",
    template: "friendship-investment",
    level: 4,
    scenario_type: "thread",
    is_legitimate: false,
    messages: [
      {
        from: "Marta",
        text: "Hi! We are in the same hiking group. Loved your photos from the ridge walk.",
      },
      {
        from: "Marta",
        text: "Funny story, my uncle started a small trading app on the side. I made a nice bit last month.",
      },
      {
        from: "Marta",
        text: "Try a tiny deposit on StackBloom. I will show you how. The window closes this week.",
      },
    ],
    red_flags: [
      "A friendly chat that steers toward money",
      "Pressure to deposit this week",
      "An app you cannot find independent information about",
    ],
    choices: [
      {
        id: "a",
        label: "Deposit a small amount to try it",
        outcome: "risky",
        catastrophic: true,
        feedback:
          "Small first deposits show small first profits, then ask for more. Decide before you have anything to lose.",
      },
      {
        id: "b",
        label: "Say thanks, no thanks, and keep the chat about hiking",
        outcome: "safe",
        feedback:
          "Polite and firm. You noticed when the topic drifted from hiking to deposits.",
      },
      {
        id: "c",
        label: "Block Marta and leave the hiking group",
        outcome: "over_cautious",
        feedback:
          "She may be a real hiker whose account was hijacked, or a scammer. Telling the group admin is enough.",
      },
    ],
    habit_tags: ["resist_escalation"],
    quip: "Even the best views on the ridge do not come with a trading app.",
  },
  {
    id: "l4-tech-support-remote",
    template: "support-remote-access",
    level: 4,
    scenario_type: "thread",
    is_legitimate: false,
    messages: [
      {
        from: "Hexa Care Support",
        text: "We noticed your device is sending alerts. May we help you check it?",
      },
      {
        from: "Hexa Care Support",
        text: "I can see three errors on our side. They are not serious yet. Can you read me what is on your screen?",
      },
      {
        from: "Hexa Care Support",
        text: "To clear them, please install our helper app and share the access code it shows.",
      },
    ],
    red_flags: [
      "Support that contacts you first",
      "Slow walk from a chat to a screen share",
      "Asking you to install an app and share a code",
    ],
    choices: [
      {
        id: "a",
        label: "Install the app and share the code",
        outcome: "risky",
        catastrophic: true,
        feedback:
          "That code gives them control of your device. If it happened, disconnect from the internet and change your passwords from another device.",
      },
      {
        id: "b",
        label:
          "End the chat. Contact your device maker through its official site",
        outcome: "safe",
        feedback:
          "The real maker had sent nothing. Leaving at the first odd step, before sunk cost builds, was the right call.",
      },
      {
        id: "c",
        label: "Read out the errors but do not install anything",
        outcome: "risky",
        feedback:
          "It feels harmless, but each answer helps them sound more real. It is OK to stop earlier.",
      },
      {
        id: "d",
        label: "Throw the device away",
        outcome: "over_cautious",
        feedback:
          "Nothing is wrong with the device. You only needed to end the chat.",
      },
    ],
    habit_tags: ["resist_escalation"],
    quip: "Your laptop has been perfectly happy this whole time, thank you.",
  },

  // Level 5: balanced skeptic (mixed real and fake)
  {
    id: "l5-real-card-alert",
    template: "bank-alert-real",
    level: 5,
    scenario_type: "text",
    is_legitimate: true,
    messages: [
      {
        from: "Cobalt Credit Union",
        text: "Card ending 4417 was used for 42.10 at a grocery store. If this was not you, open the app or call the number on your card.",
      },
    ],
    red_flags: [],
    choices: [
      {
        id: "a",
        label:
          "Recognise the purchase, check the app on your own, and carry on",
        outcome: "safe",
        feedback:
          "This one is normal: it names no link, asks for nothing and points to your own app. Trusting it is fine.",
      },
      {
        id: "b",
        label: "Reply with your full card number to dispute it",
        outcome: "risky",
        catastrophic: true,
        feedback:
          "Even for a real alert, never send card details by text. Use the app or the card's number.",
      },
      {
        id: "c",
        label: "Block the sender and report it as a scam",
        outcome: "over_cautious",
        feedback:
          "That blocks real alerts. A message that asks for nothing and points to your own app is fine.",
      },
    ],
    habit_tags: ["balanced"],
    quip: "Sometimes a text really is just a text.",
  },
  {
    id: "l5-fake-shared-doc",
    recovery: "password",
    template: "shared-file-login",
    level: 5,
    scenario_type: "email",
    is_legitimate: false,
    messages: [
      {
        from: "Docs Share <noreply@docs-share-notice.example>",
        text: "A colleague shared 'Q3 payroll changes.pdf' with you. Sign in to view: https://docs-share-notice.example/view",
      },
    ],
    red_flags: [
      "Unexpected file with a tempting name",
      "Sign-in required through the link",
      "Sender domain you do not know",
    ],
    choices: [
      {
        id: "a",
        label: "Sign in to see the file",
        outcome: "risky",
        catastrophic: true,
        feedback:
          "A fake sign-in page copies your password. Open shared files from the tool itself, not an email link.",
      },
      {
        id: "b",
        label: "Do not click. Ask your colleague on chat if they sent it",
        outcome: "safe",
        feedback:
          "They did not. A short check on a known channel stopped a copied sign-in page.",
      },
      {
        id: "c",
        label: "Block every shared file from everyone",
        outcome: "over_cautious",
        feedback:
          "Colleagues share real files often. Check first, then decide.",
      },
    ],
    habit_tags: ["balanced"],
    quip: "No payroll document has ever been this eager to be opened.",
  },
  {
    id: "l5-real-meeting-invite",
    template: "colleague-invite-real",
    level: 5,
    scenario_type: "email",
    is_legitimate: true,
    messages: [
      {
        from: "Priya Rao <priya.rao@brightcart.example>",
        text: "Following up on our call this morning. Here is the calendar invite for Thursday's planning session. No prep needed.",
      },
    ],
    red_flags: [],
    choices: [
      {
        id: "a",
        label: "It matches the call you had. Accept the invite",
        outcome: "safe",
        feedback:
          "Expected sender, expected topic, nothing asked of you. Accepting is sensible. Calibration means trusting this too.",
      },
      {
        id: "b",
        label: "Report it as phishing to be safe",
        outcome: "over_cautious",
        feedback:
          "It was real and expected. Reporting everything buries the messages that matter.",
      },
      {
        id: "c",
        label:
          "Reply with your phone number and home address for Priya's records",
        outcome: "risky",
        feedback:
          "Nothing in the message asked for that. Only share what is needed.",
      },
    ],
    habit_tags: ["balanced"],
    quip: "A meeting invite. The most dangerous thing in it is the agenda.",
  },
  {
    id: "l5-fake-refund",
    template: "refund-overpayment",
    level: 5,
    scenario_type: "email",
    is_legitimate: false,
    messages: [
      {
        from: "Ledgerly Refunds <refunds@ledgerly-returns.example>",
        text: "We charged you twice by mistake. To receive your 89 refund, confirm your card details at https://ledgerly-returns.example/refund",
      },
    ],
    red_flags: [
      "A refund that asks for your card details",
      "Sender domain that is not the shop's",
      "You are not sure you bought from them",
    ],
    choices: [
      {
        id: "a",
        label: "Enter your card details to get the refund",
        outcome: "risky",
        catastrophic: true,
        feedback:
          "Refunds go back to the original payment method. They never need your card number again.",
      },
      {
        id: "b",
        label:
          "Check your own order history and statement, then ignore the email",
        outcome: "safe",
        feedback:
          "No double charge. You checked the facts yourself before reacting.",
      },
      {
        id: "c",
        label: "Cancel your card and never shop online again",
        outcome: "over_cautious",
        feedback:
          "You were never charged twice. A quick look at your statement settles it.",
      },
    ],
    habit_tags: ["balanced"],
    quip: "Refunds are the only gift that comes with a form.",
  },
];
