import type { Module } from '../../types';

export const insecureDeserialization: Module = {
    id: 'insecure-deserialization',
    title: 'Insecure Deserialization',
    description: 'Master the detection and prevention of deserialization attacks that can lead to remote code and system compromise.',
    difficulty: 'Advanced',
    xpReward: 450,
    locked: false,
    lessons: [
        {
            id: 'deser-theory',
            title: 'Understanding Deserialization Attacks',
            type: 'theory',
            content: `
# Insecure Deserialization

Insecure deserialization is a critical vulnerability that occurs when untrusted data is used to abuse application logic, cause denial of service, or invoke arbitrary code.

## What is Serialization?

**Serialization** is converting an object into a format that can be stored or transmitted.
**Deserialization** is reconstructing the object from that format.

\`\`\`javascript
// Serialization example
const user = { id: 1, name: "Agent007" };
const serialized = JSON.stringify(user);

// Deserialization
const restored = JSON.parse(serialized);
\`\`\`

While JSON is relatively safe (only basic data types), many languages have **native serialization formats** that can serialize entire objects including their methods:

- **Java:** ObjectInputStream
- **PHP:** unserialize()
- **Python:** pickle
- **Ruby:** Marshal
- **.NET:** BinaryFormatter

## The Problem: Gadget Chains

A **gadget chain** is a sequence of existing classes that, when combined during deserialization, leads to code execution. Attackers don't need to upload code—they abuse classes already in your classpath.

## Case Files

### Equifax Breach (2017)
**Impact:** 147 million Americans' data exposed

The breach exploited a deserialization vulnerability in Apache Struts. Attackers sent crafted payloads that achieved remote code execution.

### Apache Commons Collections (2015)
Researchers published "gadget chain" techniques using Apache Commons Collections that affected thousands of Java applications including WebLogic, WebSphere, JBoss, and Jenkins.

## Defense Strategies

1. **Never deserialize untrusted data** - Use JSON instead
2. **Use safe data formats** - JSON, Protocol Buffers, MessagePack
3. **Implement type allowlists** - Restrict which classes can be deserialized
4. **Validate before deserializing** - Check integrity with HMAC signatures
            `
        },
        {
            id: 'deser-quiz-1',
            title: 'Deserialization Fundamentals',
            type: 'quiz',
            content: '',
            quiz: {
                question: "What makes native serialization formats more dangerous than JSON?",
                options: [
                    "They are slower to parse, allowing timing attacks",
                    "They can serialize and deserialize objects with methods, not just data",
                    "They do not support encryption",
                    "They are not compatible with web browsers"
                ],
                correctAnswer: 1,
                explanation: "Native serialization formats can serialize entire objects including their methods. During deserialization, this can trigger code through magic methods or gadget chains. JSON only supports primitive data types and cannot invoke code."
            }
        },
        {
            id: 'deser-quiz-2',
            title: 'Gadget Chain Analysis',
            type: 'quiz',
            content: '',
            quiz: {
                question: "What is a 'gadget chain' in the context of deserialization attacks?",
                options: [
                    "A hardware device used to intercept network traffic",
                    "A sequence of existing classes that, when combined during deserialization, leads to code invocation",
                    "A cryptographic key chain for encrypting serialized data",
                    "A debugging tool for tracing object creation"
                ],
                correctAnswer: 1,
                explanation: "A gadget chain is a sequence of method calls triggered during deserialization that chains together existing classes to achieve dangerous operations like invoking system commands."
            }
        },
        {
            id: 'deser-quiz-3',
            title: 'Real-World Breach Analysis',
            type: 'quiz',
            content: '',
            quiz: {
                question: "The 2017 Equifax breach, which exposed 147 million Americans' data, was caused by:",
                options: [
                    "SQL injection in the customer portal",
                    "An unpatched deserialization vulnerability in Apache Struts",
                    "Weak password policies for administrator accounts",
                    "A misconfigured firewall rule"
                ],
                correctAnswer: 1,
                explanation: "The Equifax breach exploited CVE-2017-5638, a deserialization vulnerability in Apache Struts. The patch had been available for two months before the breach."
            }
        },
        {
            id: 'deser-quiz-4',
            title: 'Defense Strategy Evaluation',
            type: 'quiz',
            content: '',
            quiz: {
                question: "Which defense strategy provides the STRONGEST protection against insecure deserialization?",
                options: [
                    "Encrypting serialized data before transmission",
                    "Avoiding native serialization entirely and using JSON for untrusted data",
                    "Compressing serialized data to hide the payload structure",
                    "Using HTTPS for all data transmission"
                ],
                correctAnswer: 1,
                explanation: "The safest approach is to avoid native serialization formats entirely for untrusted data. JSON cannot invoke code during parsing."
            }
        },
        {
            id: 'deser-quiz-5',
            title: 'Attack Vector Recognition',
            type: 'quiz',
            content: '',
            quiz: {
                question: "A PHP application uses unserialize() on user-provided cookie data. An attacker could exploit this by:",
                options: [
                    "Injecting SQL commands into the cookie value",
                    "Crafting a serialized payload that instantiates classes with malicious property values, triggering magic methods",
                    "Overflowing the cookie buffer to inject shellcode",
                    "Using XSS to modify the cookie in the browser"
                ],
                correctAnswer: 1,
                explanation: "PHP's unserialize() will instantiate objects with dangerous magic methods (__destruct, __wakeup) that can perform unintended actions when triggered."
            }
        },
        {
            id: 'deser-lab',
            title: 'Implement Safe Deserialization',
            type: 'lab',
            content: 'The function below deserializes user session data using an unsafe method. Your mission: Replace it with a safe approach using JSON, type validation, and HMAC signature verification.',
            lab: {
                initialCode: `
function loadSession(serializedData) {
  // VULNERABLE: Direct object construction from string
  // This could allow arbitrary code!
  const session = Function('return ' + serializedData)();

  return session;
}
                `,
                solutionCode: `
function loadSession(serializedData, signature, secretKey) {
  // SECURE: Verify HMAC signature first
  const expectedSignature = crypto
    .createHmac('sha256', secretKey)
    .update(serializedData)
    .digest('hex');

  if (signature !== expectedSignature) {
    throw new Error('Invalid signature');
  }

  // SECURE: Use JSON.parse instead of Function constructor
  const session = JSON.parse(serializedData);

  // SECURE: Validate expected types
  if (typeof session.userId !== 'string') {
    throw new Error('Invalid session format');
  }
  if (typeof session.role !== 'string') {
    throw new Error('Invalid session format');
  }

  // SECURE: Allowlist valid roles
  const allowedRoles = ['user', 'admin', 'moderator'];
  if (!allowedRoles.includes(session.role)) {
    throw new Error('Invalid role');
  }

  return session;
}
                `,
                instructions: "Secure the deserialization: 1) Add signature and secretKey parameters, 2) Verify HMAC signature, 3) Use JSON.parse instead of Function, 4) Validate session.userId and session.role are strings, 5) Validate role against allowedRoles array."
            }
        }
    ]
};
