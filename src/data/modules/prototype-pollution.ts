import type { Module } from '../../types';

export const prototypePollution: Module = {
    id: 'prototype-pollution',
    title: 'Prototype Pollution',
    description: 'Understand and defend against prototype pollution attacks that exploit JavaScript\'s prototype chain to inject malicious properties into all objects.',
    difficulty: 'Advanced',
    xpReward: 400,
    locked: false,
    lessons: [
        {
            id: 'proto-theory-chain',
            title: 'JavaScript Prototype Chain',
            type: 'theory',
            content: `
# JavaScript Prototype Chain

Every object in JavaScript has a hidden link to another object called its **prototype**. This chain is the backbone of JavaScript's inheritance model — and a critical attack surface.

## How Property Lookup Works

When you access a property on an object, the engine:

1. Checks the object itself
2. Checks the object's prototype (\`__proto__\`)
3. Continues up the chain until \`Object.prototype\`
4. Returns \`undefined\` if not found anywhere

\`\`\`javascript
const agent = { codename: "Shadow" };

// Direct property
agent.codename; // "Shadow"

// Inherited from Object.prototype
agent.toString(); // "[object Object]"
agent.hasOwnProperty("codename"); // true
\`\`\`

## __proto__ vs prototype

These are frequently confused, but the distinction matters for security:

- **\`__proto__\`** — Every object has this. It points to the object's prototype (the object it inherits from). This is the property attackers target.
- **\`prototype\`** — Only functions have this. It's the object that will become \`__proto__\` of instances created with \`new\`.

\`\`\`javascript
function Agent(name) { this.name = name; }
Agent.prototype.greet = function() { return "Agent " + this.name; };

const a = new Agent("X");
a.__proto__ === Agent.prototype; // true
a.__proto__.__proto__ === Object.prototype; // true
a.__proto__.__proto__.__proto__ === null; // true (end of chain)
\`\`\`

## Object.prototype: The Root of All Objects

\`Object.prototype\` sits at the top of nearly every prototype chain. If an attacker can modify it, **every object in the application inherits the modification**.

\`\`\`javascript
// If an attacker does this:
Object.prototype.isAdmin = true;

// Then EVERY object is affected:
const user = {};
user.isAdmin; // true — even though we never set it

const config = { debug: false };
config.isAdmin; // true — inherited from polluted prototype
\`\`\`

## Why This Matters for Security

Authorization checks like \`if (user.isAdmin)\` will pass for every object. Template engines may render attacker-controlled properties. Server configurations can be overridden. The damage is application-wide and often invisible until exploited.
            `
        },
        {
            id: 'proto-quiz-basics',
            title: 'Prototype Basics',
            type: 'quiz',
            content: '',
            quiz: {
                question: "If an attacker successfully sets `Object.prototype.role = 'admin'`, what happens when code checks `user.role` on a newly created empty object `const user = {}`?",
                options: [
                    "It returns undefined because the property was never set on the user object directly",
                    "It throws a TypeError because Object.prototype is read-only",
                    "It returns 'admin' because the property is inherited through the prototype chain",
                    "It returns null because prototype properties are not enumerable"
                ],
                correctAnswer: 2,
                explanation: "When a property is not found on the object itself, JavaScript walks up the prototype chain. Since Object.prototype now has `role = 'admin'`, any object without its own `role` property will inherit this value. This is exactly why prototype pollution is so dangerous — it affects all objects."
            }
        },
        {
            id: 'proto-theory-attacks',
            title: 'Prototype Pollution Attacks',
            type: 'theory',
            content: `
# Prototype Pollution Attacks

Prototype pollution occurs when an attacker can inject properties into \`Object.prototype\` through unsafe object manipulation functions. The most common vector: **recursive merge and clone operations** on user-controlled input.

## The Attack Pattern

\`\`\`javascript
// A typical vulnerable merge function
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Attacker sends this JSON payload:
const malicious = JSON.parse('{"__proto__": {"isAdmin": true}}');

// When merged into any object:
const config = {};
merge(config, malicious);

// Now EVERY object has isAdmin:
const newUser = {};
console.log(newUser.isAdmin); // true
\`\`\`

## How JSON.parse Enables the Attack

\`JSON.parse\` creates objects with \`__proto__\` as a **regular property key**, not the special accessor. When a merge function iterates over keys and encounters \`__proto__\`, it traverses into the actual prototype object and writes properties there.

\`\`\`javascript
const parsed = JSON.parse('{"__proto__": {"polluted": true}}');
// parsed has a key literally named "__proto__"
// A naive merge will follow this into Object.prototype
\`\`\`

## Real-World Vulnerabilities

### lodash.merge — CVE-2018-3721
The most widely-used utility library in Node.js (downloaded 40M+ times/week) was vulnerable. \`lodash.merge()\` and \`lodash.defaultsDeep()\` allowed prototype pollution through nested \`__proto__\` keys.

\`\`\`javascript
// Exploit payload
const payload = JSON.parse('{"__proto__": {"polluted": "yes"}}');
_.merge({}, payload);
({}).polluted; // "yes" — all objects polluted
\`\`\`

### jQuery $.extend — CVE-2019-11358
jQuery's deep extend was vulnerable to the same pattern. Since jQuery runs in browsers, this meant any site using \`$.extend\` on user input could have its entire DOM environment polluted.

### Hoek (Hapi.js ecosystem) — CVE-2018-3728
The \`hoek.merge()\` utility in the popular Hapi.js ecosystem allowed prototype pollution, affecting the entire Hapi middleware chain.

### minimist — CVE-2020-7598
The CLI argument parser used by thousands of Node.js tools was vulnerable. Passing \`--__proto__.polluted=true\` as a command-line argument would pollute Object.prototype.

## Attack Payloads

Beyond \`__proto__\`, attackers can also use:

\`\`\`javascript
// Via constructor.prototype
{"constructor": {"prototype": {"isAdmin": true}}}

// Nested pollution
{"__proto__": {"__proto__": {"deep": true}}}
\`\`\`

## Impact Scenarios

- **Authentication bypass:** \`if (user.isAdmin)\` passes for all users
- **Remote Code Execution:** Polluting template engine options (e.g., Handlebars \`allowProtoMethodsByDefault\`)
- **Denial of Service:** Overriding \`toString\` or \`valueOf\` breaks object coercion
- **Property injection:** Adding unexpected properties to configuration objects
            `
        },
        {
            id: 'proto-quiz-vulnerable',
            title: 'Identifying Vulnerable Code',
            type: 'quiz',
            content: '',
            quiz: {
                question: "Which of these merge implementations is vulnerable to prototype pollution?",
                options: [
                    "Object.assign({}, userInput) — shallow copy using built-in method",
                    "A recursive merge that iterates with `for (const key in source)` and assigns `target[key] = source[key]` without checking key names",
                    "Using the spread operator: const merged = { ...defaults, ...userInput }",
                    "JSON.parse(JSON.stringify(source)) — deep clone via serialization"
                ],
                correctAnswer: 1,
                explanation: "A recursive merge that blindly iterates keys and assigns them will follow `__proto__` into the actual prototype chain. Object.assign, spread, and JSON round-tripping are safe because they only operate on own enumerable properties and don't traverse into prototype objects."
            }
        },
        {
            id: 'proto-theory-defense',
            title: 'Defense & Mitigation',
            type: 'theory',
            content: `
# Defense & Mitigation

Prototype pollution is preventable with disciplined coding patterns and the right tools.

## 1. Object.create(null) for Lookup Maps

Create objects with **no prototype** when using them as dictionaries or lookup tables:

\`\`\`javascript
// VULNERABLE: inherits from Object.prototype
const permissions = {};
permissions[userInput] = true; // could set __proto__

// SAFE: no prototype chain at all
const permissions = Object.create(null);
permissions[userInput] = true; // __proto__ is just a normal key
\`\`\`

## 2. Object.freeze(Object.prototype)

Freeze the prototype so it cannot be modified:

\`\`\`javascript
Object.freeze(Object.prototype);

// Now pollution attempts silently fail (or throw in strict mode)
const malicious = JSON.parse('{"__proto__": {"isAdmin": true}}');
merge({}, malicious);
({}).isAdmin; // undefined — prototype was frozen
\`\`\`

**Caveat:** This can break libraries that legitimately extend Object.prototype (rare in modern code, but test thoroughly).

## 3. Key Validation Before Merge

Block dangerous keys in any merge/clone function:

\`\`\`javascript
const DANGEROUS_KEYS = ['__proto__', 'constructor', 'prototype'];

function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (DANGEROUS_KEYS.includes(key)) continue;

    if (typeof source[key] === 'object' && source[key] !== null) {
      target[key] = target[key] || {};
      safeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
\`\`\`

## 4. Use Map Instead of Plain Objects

\`Map\` has no prototype chain for stored data:

\`\`\`javascript
// VULNERABLE: plain object as key-value store
const cache = {};
cache[userKey] = userValue;

// SAFE: Map doesn't have prototype pollution risks
const cache = new Map();
cache.set(userKey, userValue);
\`\`\`

## 5. Schema Validation

Validate input structure before processing:

\`\`\`javascript
import { z } from 'zod';

const ConfigSchema = z.object({
  theme: z.string(),
  language: z.string(),
  debug: z.boolean().optional(),
}).strict(); // Reject unknown keys

// Rejects any __proto__ or constructor keys
const validated = ConfigSchema.parse(userInput);
\`\`\`

## 6. Lint Rules

ESLint can catch prototype pollution patterns:

- **eslint-plugin-security:** Flags \`obj[variable]\` bracket notation
- **no-proto rule:** Disallows \`__proto__\` usage
- **Custom rules:** Flag \`for...in\` without \`hasOwnProperty\` guard

## 7. Use Patched Libraries

- \`lodash >= 4.17.12\` — patched merge/defaultsDeep
- \`jQuery >= 3.4.0\` — patched $.extend
- \`minimist >= 1.2.3\` — patched argument parsing
            `
        },
        {
            id: 'proto-lab',
            title: 'Fix the Merge Function',
            type: 'lab',
            content: 'The recursive merge function below is vulnerable to prototype pollution. Your mission: add key blacklisting to reject dangerous keys like __proto__, constructor, and prototype while preserving normal merge behavior.',
            lab: {
                initialCode: `
function deepMerge(target, source) {
  for (const key in source) {
    if (source.hasOwnProperty(key)) {
      if (
        typeof source[key] === 'object' &&
        source[key] !== null &&
        !Array.isArray(source[key])
      ) {
        if (!target[key]) {
          target[key] = {};
        }
        deepMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
  }
  return target;
}
                `,
                solutionCode: `
function deepMerge(target, source) {
  const BLACKLISTED_KEYS = ['__proto__', 'constructor', 'prototype'];

  for (const key in source) {
    if (source.hasOwnProperty(key)) {
      if (BLACKLISTED_KEYS.includes(key)) {
        continue;
      }
      if (
        typeof source[key] === 'object' &&
        source[key] !== null &&
        !Array.isArray(source[key])
      ) {
        if (!target[key]) {
          target[key] = {};
        }
        deepMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
  }
  return target;
}
                `,
                instructions: "Secure the deepMerge function: 1) Define a BLACKLISTED_KEYS array containing '__proto__', 'constructor', and 'prototype', 2) Add a check at the start of the loop to skip any key that is in BLACKLISTED_KEYS using .includes(), 3) Keep all existing merge logic intact for non-dangerous keys."
            }
        }
    ]
};
