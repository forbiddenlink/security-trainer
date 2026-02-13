import type { Module } from '../../types';

export const xxeAttacks: Module = {
    id: 'xxe-attacks',
    title: 'XML External Entity (XXE) Injection',
    description: 'Master the detection and prevention of XXE attacks that exploit XML parsers to leak data, perform SSRF, and cause denial of service.',
    difficulty: 'Advanced',
    xpReward: 400,
    locked: false,
    lessons: [
        {
            id: 'xxe-theory',
            title: 'Understanding XXE Attacks',
            type: 'theory',
            content: `
# XML External Entity (XXE) Injection

XML External Entity (XXE) injection is a web security vulnerability that allows attackers to interfere with an application's processing of XML data. It exploits features of XML parsers that allow the definition and resolution of external entities.

## Understanding XML and DTDs

A Document Type Definition (DTD) defines the structure of an XML document and can define **entities**—variables that get replaced when the XML is parsed.

### The Danger: External Entities

XML allows entities to reference **external resources**—files, URLs, or other data:

\`\`\`xml
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
\`\`\`

When an insecure parser processes this, it reads the file and includes its contents in the response.

## Attack Vectors

1. **Local File Disclosure**: Reading files from the server
2. **SSRF via XXE**: Making the server perform requests to internal resources
3. **Billion Laughs Attack (DoS)**: Exponential memory expansion
4. **Blind XXE**: Out-of-band data exfiltration

## Attack Variants

### Billion Laughs Attack (XML bomb)
An attack causing exponential memory expansion through nested entity definitions.

## Case Files

### Facebook XXE (2014)
Security researcher Reginaldo Silva discovered that Facebook's "Forgot Password" feature parsed XML using a vulnerable parser. Facebook awarded a $33,500 bug bounty.

### XXE in SAML Implementations
SAML (Security Assertion Markup Language) uses XML for SSO. Multiple SAML implementations have been vulnerable to XXE, allowing authentication bypass.

## Defense Strategies

1. **Disable DTD Processing Entirely** - The safest option
2. **Disable External Entities Specifically**
3. **Use Safe XML Libraries** (defusedxml for Python)
4. **Input Validation** - Reject XML containing DTD declarations
            `
        },
        {
            id: 'xxe-quiz-1',
            title: 'XXE Fundamentals Assessment',
            type: 'quiz',
            content: '',
            quiz: {
                question: "What feature of XML does XXE exploit?",
                options: [
                    "XML namespaces that allow cross-origin data access",
                    "External entity declarations in DTDs that reference files or URLs",
                    "XPath queries that can be injected like SQL",
                    "XML schema validation that exposes internal errors"
                ],
                correctAnswer: 1,
                explanation: "XXE exploits the XML feature of external entities defined in DTDs. When a parser resolves an entity like <!ENTITY xxe SYSTEM 'file:///etc/passwd'>, it reads the file and includes its contents."
            }
        },
        {
            id: 'xxe-quiz-2',
            title: 'Attack Vector Recognition',
            type: 'quiz',
            content: '',
            quiz: {
                question: "An attacker sends XML containing: <!ENTITY xxe SYSTEM 'http://169.254.169.254/latest/meta-data/'>. What attack is being attempted?",
                options: [
                    "SQL Injection to access the database",
                    "XSS to inject malicious scripts",
                    "SSRF via XXE to access cloud metadata credentials",
                    "CSRF to forge authenticated requests"
                ],
                correctAnswer: 2,
                explanation: "This is SSRF performed via XXE. The attacker is using the XML parser to make a request to the AWS metadata endpoint, attempting to steal IAM credentials."
            }
        },
        {
            id: 'xxe-quiz-3',
            title: 'Billion Laughs Analysis',
            type: 'quiz',
            content: '',
            quiz: {
                question: "The 'Billion Laughs' attack (XML bomb) works by:",
                options: [
                    "Sending a billion HTTP requests to overwhelm the server",
                    "Using nested entity definitions that expand exponentially in memory",
                    "Including malicious JavaScript that runs in an infinite loop",
                    "Exploiting buffer overflow in the XML parser code"
                ],
                correctAnswer: 1,
                explanation: "The Billion Laughs attack defines entities that reference other entities in a nested pattern. When expanded, a few kilobytes of XML can consume gigabytes of memory."
            }
        },
        {
            id: 'xxe-quiz-4',
            title: 'Defense Strategy Evaluation',
            type: 'quiz',
            content: '',
            quiz: {
                question: "Which is the MOST effective defense against XXE attacks?",
                options: [
                    "Encoding XML special characters in input",
                    "Using HTTPS for all XML data transfers",
                    "Disabling DTD processing and external entity resolution in the parser",
                    "Validating XML against a strict schema"
                ],
                correctAnswer: 2,
                explanation: "The most effective defense is to disable DTD processing entirely, or at minimum disable external entity resolution."
            }
        },
        {
            id: 'xxe-quiz-5',
            title: 'Real-World Breach Analysis',
            type: 'quiz',
            content: '',
            quiz: {
                question: "In the 2014 Facebook XXE vulnerability, what made SAML implementations particularly susceptible to XXE?",
                options: [
                    "SAML uses JSON which is vulnerable to entity expansion",
                    "SAML is an XML-based protocol, and many parsers processed DTDs by default",
                    "SAML passwords are stored in plaintext",
                    "SAML implementations use weak encryption"
                ],
                correctAnswer: 1,
                explanation: "SAML is XML-based by design. Many SAML implementations used XML parsers with default settings that processed DTDs and resolved external entities."
            }
        },
        {
            id: 'xxe-lab',
            title: 'Secure the XML Parser',
            type: 'lab',
            content: 'The code below uses an XML parser with insecure default settings. Your mission: Configure the parser to disable external entity processing and DTD handling.',
            lab: {
                initialCode: `
function parseUserXml(xmlInput) {
  // VULNERABLE: Parser uses insecure defaults
  const parser = new XMLParser({
    // No security configuration!
  });

  const result = parser.parse(xmlInput);
  return result;
}
                `,
                solutionCode: `
function parseUserXml(xmlInput) {
  // SECURE: Reject DTD declarations in input
  if (xmlInput.includes('<!DOCTYPE') || xmlInput.includes('<!ENTITY')) {
    throw new Error('DTD and entities are not allowed');
  }

  // SECURE: Configure parser to disable dangerous features
  const parser = new XMLParser({
    allowDtd: false,
    resolveExternalEntities: false,
    processEntities: false,
    expandEntityReferences: false
  });

  const result = parser.parse(xmlInput);
  return result;
}
                `,
                instructions: "Secure the XML parser: 1) Reject input containing '<!DOCTYPE' or '<!ENTITY', 2) Configure parser with allowDtd: false, resolveExternalEntities: false, processEntities: false, expandEntityReferences: false."
            }
        }
    ]
};
