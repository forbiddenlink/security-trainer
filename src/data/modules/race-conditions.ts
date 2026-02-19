import type { Module } from "../../types";

export const raceConditions: Module = {
  id: "race-conditions",
  title: "Race Conditions",
  description:
    "Learn to identify and prevent timing-based vulnerabilities that occur when multiple operations compete for shared resources.",
  difficulty: "Intermediate",
  xpReward: 150,
  locked: false,
  lessons: [
    {
      id: "race-conditions-intro",
      title: "What Are Race Conditions?",
      type: "theory",
      content: `# What Are Race Conditions?

A **race condition** occurs when the behavior of a system depends on the timing of uncontrollable events. In security, this creates a window of opportunity for attackers to exploit.

## The TOCTOU Problem

The most common race condition is **Time-Of-Check to Time-Of-Use (TOCTOU)**:

1. **Check** - Verify a condition (e.g., "Does user have sufficient balance?")
2. **Gap** - Time passes between check and action
3. **Use** - Perform the action (e.g., "Deduct from balance")

The vulnerability exists in the **gap** between checking and acting.

## The ATM Example

Imagine you have $100 in your account. You try to withdraw $100 from two ATMs simultaneously:

\`\`\`
Timeline:
─────────────────────────────────────────────────────►
     │                    │                    │
  ATM A checks         ATM B checks        Both withdraw
  balance: $100        balance: $100       $100 each!
     │                    │                    │
     └──── Both see $100 available ──────────►│
                                              │
                                        Final balance: -$100
\`\`\`

Both ATMs checked the balance before either completed the withdrawal. Result: $200 withdrawn from a $100 account.

## Why This Happens

In concurrent systems, multiple requests can:
- Execute simultaneously on different threads
- Interleave operations in unexpected ways
- See stale data before updates complete

Modern web servers handle requests concurrently by default, making every shared resource a potential race condition target.

## Real-World Impact

Race conditions have been used to:
- Withdraw money multiple times from the same balance
- Redeem coupons repeatedly
- Vote multiple times in polls
- Bypass rate limits
- Escalate privileges`,
    },
    {
      id: "race-conditions-patterns",
      title: "Common Vulnerable Patterns",
      type: "theory",
      content: `# Common Vulnerable Patterns

Two patterns account for most race condition vulnerabilities in web applications.

## Pattern 1: Check-Then-Act

The application checks a condition, then acts based on that check:

\`\`\`javascript
// VULNERABLE: Coupon redemption
app.post('/redeem-coupon', async (req, res) => {
  const coupon = await db.getCoupon(req.body.code);

  if (!coupon.used) {           // CHECK: Is coupon available?
    await giveDiscount(user);   // Attacker's window
    await db.markUsed(coupon);  // ACT: Mark as used (too late!)
  }
});
\`\`\`

**The vulnerability:** Between checking \`coupon.used\` and calling \`markUsed()\`, another request can slip through with the same coupon.

## Pattern 2: Read-Modify-Write

The application reads a value, modifies it in memory, then writes it back:

\`\`\`javascript
// VULNERABLE: Balance transfer
app.post('/transfer', async (req, res) => {
  const balance = await db.getBalance(userId);  // READ

  if (balance >= amount) {
    const newBalance = balance - amount;        // MODIFY (in memory)
    await db.setBalance(userId, newBalance);    // WRITE
  }
});
\`\`\`

**The vulnerability:** Two simultaneous requests both read $100, both calculate $100 - $75 = $25, both write $25. The user transferred $150 but only lost $75.

## Why Async/Await Makes It Worse

Every \`await\` is a pause where other code can run:

\`\`\`javascript
const balance = await db.getBalance(userId);  // Pause here
// ─── Other requests execute while we wait ───
if (balance >= amount) {
  await giveReward();  // Pause here too
  // ─── Race window widens ───
  await db.deductBalance(userId, amount);
}
\`\`\`

The more async operations between check and act, the larger the attack window.

## Identifying Vulnerable Code

Look for these red flags:
- Separate read and write operations on the same data
- Business logic between database queries
- \`if\` statements checking data that could change
- Any "check then do" pattern with shared state`,
    },
    {
      id: "race-conditions-quiz-1",
      title: "Spot the Vulnerability",
      type: "quiz",
      content: "",
      quiz: {
        question: "Which code snippet has a race condition vulnerability?",
        options: [
          "UPDATE inventory SET quantity = quantity - 1 WHERE product_id = 5 AND quantity > 0",
          "const qty = await db.getQuantity(productId); if (qty > 0) { await db.setQuantity(productId, qty - 1); }",
          "await db.query('UPDATE ... SET quantity = quantity - 1 WHERE product_id = ? AND quantity > 0', [id])",
          "BEGIN TRANSACTION; UPDATE inventory SET quantity = quantity - 1 WHERE product_id = 5; COMMIT;",
        ],
        correctAnswer: 1,
        explanation:
          "Option B is vulnerable because it reads the quantity, checks it in JavaScript, then writes back. Two requests could both read the same quantity and both succeed. The other options perform atomic database operations that check and update in a single statement.",
      },
    },
    {
      id: "race-conditions-quiz-2",
      title: "Exploiting Race Conditions",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "A voting system uses: `if (!await hasUserVoted(userId)) { await recordVote(userId, choice); }`. How can an attacker exploit this?",
        options: [
          "Use SQL injection in the userId parameter",
          "Modify the hasVoted response in transit with a MITM attack",
          "Send multiple vote requests simultaneously before the first recordVote() completes",
          "This code is not exploitable - the async/await ensures sequential execution",
        ],
        correctAnswer: 2,
        explanation:
          "The check-then-act pattern allows multiple simultaneous requests to all pass the hasUserVoted check before any recordVote completes, allowing multiple votes from the same user. Async/await only sequences code within a single request, not across multiple concurrent requests.",
      },
    },
    {
      id: "race-conditions-exploits",
      title: "Real-World Exploits",
      type: "theory",
      content: `# Real-World Race Condition Exploits

Race conditions have led to significant security breaches and financial losses. Understanding these attacks helps you recognize vulnerable patterns.

## Double-Spending Attacks

**Scenario:** E-commerce site with gift card balance

\`\`\`javascript
// Vulnerable endpoint
app.post('/purchase', async (req, res) => {
  const balance = await db.getGiftCardBalance(cardId);
  if (balance >= price) {
    await processOrder(orderId);
    await db.setGiftCardBalance(cardId, balance - price);
  }
});
\`\`\`

**Attack:** Send 10 simultaneous purchase requests for a $50 item with a $100 gift card:
- All 10 requests read balance: $100
- All 10 pass the check: $100 >= $50
- All 10 process orders (10 items shipped!)
- All 10 write: $100 - $50 = $50

**Result:** Attacker gets $500 worth of items for $50.

## Coupon Stacking

**Scenario:** One-time-use discount codes

\`\`\`javascript
// Vulnerable
if (!await isCouponUsed(code)) {
  await applyDiscount(cart, code);
  await markCouponUsed(code);
}
\`\`\`

**Attack:** Race 100 requests with the same coupon code. Multiple requests pass the "not used" check before any marks it used.

**Bug Bounty Example:** A major retailer paid $5,000 for this exact vulnerability allowing unlimited use of single-use coupons.

## Account Limit Bypass

**Scenario:** Free tier limited to 3 projects

\`\`\`javascript
const projectCount = await db.countProjects(userId);
if (projectCount < 3) {
  await db.createProject(userId, projectData);
}
\`\`\`

**Attack:** Send 10 create-project requests simultaneously. All see count < 3, all create projects.

## How Attackers Exploit Race Conditions

Tools commonly used:
- **Burp Suite Turbo Intruder** - Sends hundreds of parallel requests
- **curl with xargs** - \`seq 100 | xargs -P100 -I{} curl -X POST ...\`
- **Custom scripts** - Python asyncio, Node.js Promise.all

The attack window can be milliseconds, but parallel requests make exploitation reliable.`,
    },
    {
      id: "race-conditions-defenses",
      title: "Defense Strategies",
      type: "theory",
      content: `# Defense Strategies

Multiple techniques can prevent race conditions. Choose based on your specific use case.

## 1. Atomic Database Operations

Combine check and update into a single query:

\`\`\`javascript
// SECURE: Atomic balance update
app.post('/transfer', async (req, res) => {
  const result = await db.query(
    'UPDATE accounts SET balance = balance - $1 WHERE id = $2 AND balance >= $1 RETURNING balance',
    [amount, userId]
  );

  if (result.rowCount === 0) {
    return res.status(400).json({ error: 'Insufficient funds' });
  }

  res.json({ newBalance: result.rows[0].balance });
});
\`\`\`

**Why it works:** The database ensures no other transaction can see or modify the row between the check (\`balance >= $1\`) and the update (\`balance - $1\`).

## 2. Row-Level Locking

Lock the row while you work with it:

\`\`\`javascript
// SECURE: Pessimistic locking
await db.query('BEGIN');

const coupon = await db.query(
  'SELECT * FROM coupons WHERE code = $1 FOR UPDATE',  // Lock this row
  [code]
);

if (!coupon.rows[0].used) {
  await applyDiscount(user);
  await db.query('UPDATE coupons SET used = true WHERE code = $1', [code]);
}

await db.query('COMMIT');
\`\`\`

**Why it works:** \`FOR UPDATE\` blocks other transactions from reading or modifying the row until we commit.

## 3. Idempotency Keys

Require clients to send a unique key; reject duplicates:

\`\`\`javascript
// SECURE: Idempotency key pattern
app.post('/payment', async (req, res) => {
  const { idempotencyKey, amount } = req.body;

  // Try to insert the key (fails if duplicate)
  try {
    await db.query(
      'INSERT INTO processed_requests (key) VALUES ($1)',
      [idempotencyKey]
    );
  } catch (e) {
    if (e.code === '23505') {  // Unique violation
      return res.status(409).json({ error: 'Already processed' });
    }
    throw e;
  }

  await processPayment(amount);
});
\`\`\`

**Why it works:** Database unique constraint guarantees only one request with a given key succeeds.

## Choosing the Right Defense

| Technique | Best For | Trade-off |
|-----------|----------|-----------|
| Atomic operations | Simple increment/decrement | Limited to single-statement logic |
| Row locking | Complex multi-step operations | Can cause deadlocks if misused |
| Idempotency keys | Payment/external API calls | Requires client cooperation |`,
    },
    {
      id: "race-conditions-lab",
      title: "Lab: Fix a Vulnerable Endpoint",
      type: "lab",
      content:
        "A gift card redemption system has a race condition vulnerability. Your mission: Rewrite the endpoint to use an atomic database operation. The UPDATE query should check balance AND deduct in a single statement, then check rowCount to detect insufficient funds.",
      lab: {
        initialCode: `app.post('/redeem-gift-card', async (req, res) => {
  const { cardId, amount } = req.body;

  // VULNERABLE: Read-modify-write pattern
  const card = await db.query(
    'SELECT balance FROM gift_cards WHERE id = $1',
    [cardId]
  );

  const balance = card.rows[0].balance;

  if (balance < amount) {
    return res.status(400).json({ error: 'Insufficient balance' });
  }

  await db.query(
    'UPDATE gift_cards SET balance = $1 WHERE id = $2',
    [balance - amount, cardId]
  );

  await creditUserAccount(req.user.id, amount);
  res.json({ success: true, newBalance: balance - amount });
});`,
        solutionCode: `app.post('/redeem-gift-card', async (req, res) => {
  const { cardId, amount } = req.body;

  // SECURE: Atomic update with balance check in WHERE clause
  const result = await db.query(
    'UPDATE gift_cards SET balance = balance - $1 WHERE id = $2 AND balance >= $1 RETURNING balance',
    [amount, cardId]
  );

  if (result.rowCount === 0) {
    return res.status(400).json({ error: 'Insufficient balance' });
  }

  await creditUserAccount(req.user.id, amount);
  res.json({ success: true, newBalance: result.rows[0].balance });
});`,
        instructions:
          "Remove the separate SELECT query. Use a single UPDATE with WHERE clause that checks balance >= amount. Check rowCount to detect if update succeeded.",
      },
    },
  ],
};
