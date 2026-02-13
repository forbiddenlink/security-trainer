import type { Module } from '../../types';

export const businessLogic: Module = {
    id: 'business-logic',
    title: 'Business Logic Flaws',
    description: 'Learn to identify vulnerabilities that exploit flawed application logic rather than technical weaknesses.',
    difficulty: 'Advanced',
    xpReward: 500,
    locked: false,
    lessons: [
        {
            id: 'business-logic-theory',
            title: 'Understanding Business Logic Flaws',
            type: 'theory',
            content: `
# Business Logic Flaws

Business logic flaws are vulnerabilities that arise from faulty assumptions in application design, not from coding errors like SQL injection or XSS. They're often missed by automated scanners because they require understanding of how the application *should* work.

## Mission Briefing: Why These Matter

A business logic flaw might let you:
- Buy items for negative prices (getting paid to shop!)
- Apply multiple "one-time" discount codes
- Skip payment steps in a checkout flow
- Escalate privileges by manipulating workflows

## Common Attack Patterns

### 1. Race Conditions
When two requests execute simultaneously, unexpected things can happen:

\`\`\`javascript
// User has $100 balance, tries to withdraw $100 twice simultaneously
Thread 1: Check balance → $100 ✓ → Withdraw $100
Thread 2: Check balance → $100 ✓ → Withdraw $100
// Result: User withdraws $200 from a $100 account!
\`\`\`

### 2. Price Manipulation
Negative quantities, modified prices in hidden fields, or currency confusion:

\`\`\`html
<!-- Attacker modifies hidden field -->
<input type="hidden" name="price" value="-50.00">
\`\`\`

### 3. Workflow Bypass
Skipping required steps in a process:

\`\`\`
Normal flow: Cart → Address → Payment → Confirmation
Attack:      Cart → ——————————————→ Confirmation (skip payment!)
\`\`\`

### 4. Coupon/Discount Abuse
- Applying expired coupons
- Stacking "one per customer" discounts
- Referring yourself for referral bonuses

## Real-World Intel

**Case File: Steam (2015)** - Race condition allowed users to generate unlimited wallet funds.

**Case File: Uber (2017)** - Referral system flaw allowed users to refer themselves infinitely.

**Case File: Airlines** - Multiple booking systems have allowed negative taxes or fees.

## Defense Strategy

1. **Server-side validation** - Never trust client-side prices or quantities
2. **Atomic transactions** - Use database locks for financial operations
3. **State machine validation** - Enforce workflow order
4. **Rate limiting** - Prevent rapid-fire exploitation
5. **Comprehensive logging** - Detect unusual patterns
            `
        },
        {
            id: 'business-logic-quiz-1',
            title: 'Race Condition Recognition',
            type: 'quiz',
            content: '',
            quiz: {
                question: "A banking app checks balance, then processes withdrawal in separate operations. What vulnerability does this create?",
                options: [
                    "SQL Injection - the balance query can be manipulated",
                    "Race condition - two simultaneous requests could both pass the balance check",
                    "XSS - the balance display could contain scripts",
                    "CSRF - the withdrawal could be forged"
                ],
                correctAnswer: 1,
                explanation: "This is a classic race condition (TOCTOU - Time Of Check to Time Of Use). If the balance check and withdrawal are not atomic, two simultaneous requests could both pass the check before either completes the withdrawal, allowing double-spending."
            }
        },
        {
            id: 'business-logic-quiz-2',
            title: 'Price Manipulation Defense',
            type: 'quiz',
            content: '',
            quiz: {
                question: "An e-commerce site stores the item price in a hidden form field. What's the correct fix?",
                options: [
                    "Encrypt the hidden field value",
                    "Use JavaScript to validate the price before submission",
                    "Look up the price server-side using the item ID, ignore the submitted price",
                    "Add a CAPTCHA to the checkout form"
                ],
                correctAnswer: 2,
                explanation: "Never trust client-submitted prices. Always look up the authoritative price from your database using the item ID. Client-side validation and encryption can both be bypassed by an attacker who controls their browser."
            }
        },
        {
            id: 'business-logic-quiz-3',
            title: 'Coupon System Security',
            type: 'quiz',
            content: '',
            quiz: {
                question: "A coupon system allows 'SAVE20' to be applied once per customer. How should this be enforced?",
                options: [
                    "Check if the coupon was used in the current session",
                    "Use JavaScript to disable the coupon field after first use",
                    "Store used coupons in a cookie",
                    "Record coupon usage in the database, check before applying"
                ],
                correctAnswer: 3,
                explanation: "Server-side database tracking is the only reliable method. Sessions can be cleared, JavaScript can be disabled, and cookies can be deleted. Record each coupon usage with the user ID and check the database before allowing any coupon application."
            }
        },
        {
            id: 'business-logic-quiz-4',
            title: 'Workflow Security',
            type: 'quiz',
            content: '',
            quiz: {
                question: "How should a checkout flow ensure users can't skip the payment step?",
                options: [
                    "Hide the confirmation page URL from users",
                    "Use a state machine that validates the current step before allowing progression",
                    "Require JavaScript to be enabled for checkout",
                    "Send confirmation emails immediately after adding to cart"
                ],
                correctAnswer: 1,
                explanation: "A server-side state machine tracks where each order is in the workflow. Before allowing access to any step, verify the order has completed all previous steps. Security through obscurity (hiding URLs) is not sufficient - attackers can guess or discover endpoints."
            }
        },
        {
            id: 'business-logic-lab',
            title: 'Fix the Checkout Logic',
            type: 'lab',
            content: 'The checkout code below has multiple business logic flaws: it trusts client-side prices and has no workflow validation. Your mission: Fix these vulnerabilities.',
            lab: {
                initialCode: `
async function processCheckout(req, res) {
  const { itemId, price, quantity } = req.body;
  const userId = req.session.userId;

  // VULNERABLE: Trusts client-provided price!
  const total = price * quantity;

  // VULNERABLE: No check if user completed previous steps!

  // Process payment
  await chargeUser(userId, total);

  // Create order
  const order = await createOrder(userId, itemId, quantity, total);

  return res.json({ success: true, orderId: order.id });
}
                `,
                solutionCode: `
async function processCheckout(req, res) {
  const { itemId, quantity } = req.body;
  const userId = req.session.userId;

  // SECURE: Look up price from database
  const item = await db.items.findById(itemId);
  if (!item) {
    return res.status(400).json({ error: 'Item not found' });
  }
  const serverPrice = item.price;
  const total = serverPrice * quantity;

  // SECURE: Validate checkout state
  const checkoutState = await db.checkoutStates.findByUser(userId);
  if (checkoutState.step !== 'payment_pending') {
    return res.status(400).json({ error: 'Invalid checkout state' });
  }

  // Process payment
  await chargeUser(userId, total);

  // Update state and create order
  await db.checkoutStates.update(userId, { step: 'completed' });
  const order = await createOrder(userId, itemId, quantity, total);

  return res.json({ success: true, orderId: order.id });
}
                `,
                instructions: "Fix the checkout logic: 1) Look up item price from db.items.findById(itemId) and use item.price as serverPrice, 2) Add checkout state validation by checking if checkoutState.step === 'payment_pending', 3) Update checkout state to 'completed' after payment."
            }
        }
    ]
};
