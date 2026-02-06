import { describe, it, expect } from 'vitest';
import { MODULES } from './modules';
import { labVerifiers, verifyLabSubmission } from '../utils/labVerification';

describe('MODULES data', () => {
    it('has at least 5 training modules', () => {
        expect(MODULES.length).toBeGreaterThanOrEqual(5);
    });

    it('all modules have required fields', () => {
        for (const module of MODULES) {
            expect(module).toHaveProperty('id');
            expect(module).toHaveProperty('title');
            expect(module).toHaveProperty('description');
            expect(module).toHaveProperty('difficulty');
            expect(module).toHaveProperty('xpReward');
            expect(module).toHaveProperty('lessons');
            expect(module.lessons.length).toBeGreaterThan(0);
        }
    });

    it('all module IDs are unique', () => {
        const ids = MODULES.map(m => m.id);
        const uniqueIds = new Set(ids);
        expect(uniqueIds.size).toBe(ids.length);
    });

    it('all lesson IDs are unique within modules', () => {
        for (const module of MODULES) {
            const lessonIds = module.lessons.map(l => l.id);
            const uniqueIds = new Set(lessonIds);
            expect(uniqueIds.size).toBe(lessonIds.length);
        }
    });

    it('all labs have corresponding verifiers', () => {
        const labLessons = MODULES.flatMap(m =>
            m.lessons.filter(l => l.type === 'lab')
        );

        for (const lab of labLessons) {
            expect(
                labVerifiers[lab.id],
                `Missing verifier for lab: ${lab.id}`
            ).toBeDefined();
        }
    });

    it('all quizzes have valid structure', () => {
        const quizLessons = MODULES.flatMap(m =>
            m.lessons.filter(l => l.type === 'quiz')
        );

        for (const quiz of quizLessons) {
            expect(quiz.quiz).toBeDefined();
            expect(quiz.quiz!.question).toBeTruthy();
            expect(quiz.quiz!.options.length).toBeGreaterThanOrEqual(2);
            expect(quiz.quiz!.correctAnswer).toBeGreaterThanOrEqual(0);
            expect(quiz.quiz!.correctAnswer).toBeLessThan(quiz.quiz!.options.length);
            expect(quiz.quiz!.explanation).toBeTruthy();
        }
    });

    it('difficulty values are valid', () => {
        const validDifficulties = ['Beginner', 'Intermediate', 'Advanced'];

        for (const module of MODULES) {
            expect(validDifficulties).toContain(module.difficulty);
        }
    });

    it('XP rewards are positive numbers', () => {
        for (const module of MODULES) {
            expect(module.xpReward).toBeGreaterThan(0);
        }
    });
});

describe('CSRF Module', () => {
    const csrfModule = MODULES.find(m => m.id === 'csrf-attacks');

    it('exists in the modules list', () => {
        expect(csrfModule).toBeDefined();
    });

    it('has correct structure', () => {
        expect(csrfModule!.title).toBe('Cross-Site Request Forgery (CSRF)');
        expect(csrfModule!.difficulty).toBe('Intermediate');
        expect(csrfModule!.xpReward).toBe(350);
        expect(csrfModule!.locked).toBe(false);
    });

    it('has theory, quiz, and lab lessons', () => {
        const lessonTypes = csrfModule!.lessons.map(l => l.type);
        expect(lessonTypes).toContain('theory');
        expect(lessonTypes).toContain('quiz');
        expect(lessonTypes).toContain('lab');
    });

    it('has exactly 6 lessons (1 theory, 4 quizzes, 1 lab)', () => {
        expect(csrfModule!.lessons.length).toBe(6);
        expect(csrfModule!.lessons.filter(l => l.type === 'theory').length).toBe(1);
        expect(csrfModule!.lessons.filter(l => l.type === 'quiz').length).toBe(4);
        expect(csrfModule!.lessons.filter(l => l.type === 'lab').length).toBe(1);
    });

    it('has a registered lab verifier', () => {
        expect(labVerifiers['csrf-lab']).toBeDefined();
    });
});

describe('CSRF Lab Verifier', () => {
    const vulnerableCode = `
function handleTransfer(req, res) {
  const { to, amount } = req.body;

  if (!req.session.userId) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  const result = transferFunds(req.session.userId, to, amount);
  return res.json({ success: true, result });
}
    `;

    const secureCode = `
function handleTransfer(req, res) {
  const { to, amount, csrfToken } = req.body;

  if (!req.session.userId) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  if (!csrfToken || csrfToken !== req.session.csrfToken) {
    return res.status(403).json({ error: "Invalid CSRF token" });
  }

  const result = transferFunds(req.session.userId, to, amount);
  return res.json({ success: true, result });
}
    `;

    const partialFix = `
function handleTransfer(req, res) {
  const { to, amount, csrfToken } = req.body;

  if (!req.session.userId) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  // Missing actual validation logic
  const result = transferFunds(req.session.userId, to, amount);
  return res.json({ success: true, result });
}
    `;

    it('rejects vulnerable code without CSRF protection', () => {
        expect(verifyLabSubmission('csrf-lab', vulnerableCode)).toBe(false);
    });

    it('accepts properly secured code with CSRF token validation', () => {
        expect(verifyLabSubmission('csrf-lab', secureCode)).toBe(true);
    });

    it('rejects partial fix that only extracts token but does not validate', () => {
        expect(verifyLabSubmission('csrf-lab', partialFix)).toBe(false);
    });
});

describe('Security Misconfiguration Module', () => {
    const misconfigModule = MODULES.find(m => m.id === 'security-misconfig');

    it('exists in the modules list', () => {
        expect(misconfigModule).toBeDefined();
    });

    it('has correct structure', () => {
        expect(misconfigModule!.title).toBe('Security Misconfiguration');
        expect(misconfigModule!.difficulty).toBe('Intermediate');
        expect(misconfigModule!.xpReward).toBe(350);
        expect(misconfigModule!.locked).toBe(false);
    });

    it('has theory, quiz, and lab lessons', () => {
        const lessonTypes = misconfigModule!.lessons.map(l => l.type);
        expect(lessonTypes).toContain('theory');
        expect(lessonTypes).toContain('quiz');
        expect(lessonTypes).toContain('lab');
    });

    it('has exactly 7 lessons (1 theory, 5 quizzes, 1 lab)', () => {
        expect(misconfigModule!.lessons.length).toBe(7);
        expect(misconfigModule!.lessons.filter(l => l.type === 'theory').length).toBe(1);
        expect(misconfigModule!.lessons.filter(l => l.type === 'quiz').length).toBe(5);
        expect(misconfigModule!.lessons.filter(l => l.type === 'lab').length).toBe(1);
    });

    it('has a registered lab verifier', () => {
        expect(labVerifiers['misconfig-lab']).toBeDefined();
    });
});

describe('Security Misconfiguration Lab Verifier', () => {
    const vulnerableConfig = `
const serverConfig = {
  port: 3000,
  environment: 'production',
  debug: true,

  admin: {
    username: 'admin',
    password: 'admin'
  },

  headers: {
    'X-Powered-By': 'Express'
  }
};
    `;

    const secureConfig = `
const serverConfig = {
  port: 3000,
  environment: 'production',
  debug: false,

  admin: {
    username: 'sysop_7x9k2',
    password: 'K#9xL$mP2@vN8qR!'
  },

  headers: {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
  }
};
    `;

    const partialFixDebugOnly = `
const serverConfig = {
  port: 3000,
  environment: 'production',
  debug: false,

  admin: {
    username: 'admin',
    password: 'admin'
  },

  headers: {
    'X-Powered-By': 'Express'
  }
};
    `;

    const partialFixMissingHeaders = `
const serverConfig = {
  port: 3000,
  environment: 'production',
  debug: false,

  admin: {
    username: 'secure_admin',
    password: 'StrongP@ss123!'
  },

  headers: {}
};
    `;

    const partialFixDefaultPassword = `
const serverConfig = {
  port: 3000,
  environment: 'production',
  debug: false,

  admin: {
    username: 'secure_admin',
    password: 'password'
  },

  headers: {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY'
  }
};
    `;

    it('rejects vulnerable configuration with all issues', () => {
        expect(verifyLabSubmission('misconfig-lab', vulnerableConfig)).toBe(false);
    });

    it('accepts properly secured configuration', () => {
        expect(verifyLabSubmission('misconfig-lab', secureConfig)).toBe(true);
    });

    it('rejects partial fix that only disables debug', () => {
        expect(verifyLabSubmission('misconfig-lab', partialFixDebugOnly)).toBe(false);
    });

    it('rejects partial fix missing security headers', () => {
        expect(verifyLabSubmission('misconfig-lab', partialFixMissingHeaders)).toBe(false);
    });

    it('rejects config with common default password', () => {
        expect(verifyLabSubmission('misconfig-lab', partialFixDefaultPassword)).toBe(false);
    });
});

describe('SSRF Module', () => {
    const ssrfModule = MODULES.find(m => m.id === 'ssrf-attacks');

    it('exists in the modules list', () => {
        expect(ssrfModule).toBeDefined();
    });

    it('has correct structure', () => {
        expect(ssrfModule!.title).toBe('Server-Side Request Forgery (SSRF)');
        expect(ssrfModule!.difficulty).toBe('Advanced');
        expect(ssrfModule!.xpReward).toBe(400);
        expect(ssrfModule!.locked).toBe(false);
    });

    it('has theory, quiz, and lab lessons', () => {
        const lessonTypes = ssrfModule!.lessons.map(l => l.type);
        expect(lessonTypes).toContain('theory');
        expect(lessonTypes).toContain('quiz');
        expect(lessonTypes).toContain('lab');
    });

    it('has exactly 7 lessons (1 theory, 5 quizzes, 1 lab)', () => {
        expect(ssrfModule!.lessons.length).toBe(7);
        expect(ssrfModule!.lessons.filter(l => l.type === 'theory').length).toBe(1);
        expect(ssrfModule!.lessons.filter(l => l.type === 'quiz').length).toBe(5);
        expect(ssrfModule!.lessons.filter(l => l.type === 'lab').length).toBe(1);
    });

    it('has a registered lab verifier', () => {
        expect(labVerifiers['ssrf-lab']).toBeDefined();
    });

    it('theory covers real-world breaches (Capital One)', () => {
        const theoryLesson = ssrfModule!.lessons.find(l => l.id === 'ssrf-theory');
        expect(theoryLesson!.content).toContain('Capital One');
        expect(theoryLesson!.content).toContain('169.254.169.254');
    });

    it('theory covers cloud metadata endpoints', () => {
        const theoryLesson = ssrfModule!.lessons.find(l => l.id === 'ssrf-theory');
        expect(theoryLesson!.content).toContain('AWS');
        expect(theoryLesson!.content).toContain('metadata');
        expect(theoryLesson!.content).toContain('IAM');
    });
});

describe('SSRF Lab Verifier', () => {
    const vulnerableCode = `
async function fetchUrl(userUrl) {
  const response = await fetch(userUrl);
  return response.text();
}
    `;

    const secureCode = `
async function fetchUrl(userUrl) {
  const url = new URL(userUrl);

  if (url.protocol !== 'https:') {
    throw new Error('Only HTTPS URLs are allowed');
  }

  const allowedDomains = ['api.trusted.com', 'cdn.example.com'];
  if (!allowedDomains.includes(url.hostname)) {
    throw new Error('Domain not in allowlist');
  }

  const ip = url.hostname;
  if (isPrivateIP(ip)) {
    throw new Error('Internal IPs are blocked');
  }

  const response = await fetch(userUrl);
  return response.text();
}

function isPrivateIP(hostname) {
  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    return true;
  }
  if (hostname === '169.254.169.254') {
    return true;
  }
  if (hostname.startsWith('10.') || hostname.startsWith('192.168.')) {
    return true;
  }
  return false;
}
    `;

    const partialFixNoProtocolCheck = `
async function fetchUrl(userUrl) {
  const url = new URL(userUrl);

  const allowedDomains = ['api.trusted.com', 'cdn.example.com'];
  if (!allowedDomains.includes(url.hostname)) {
    throw new Error('Domain not in allowlist');
  }

  if (isPrivateIP(url.hostname)) {
    throw new Error('Internal IPs are blocked');
  }

  const response = await fetch(userUrl);
  return response.text();
}

function isPrivateIP(hostname) {
  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    return true;
  }
  if (hostname === '169.254.169.254') {
    return true;
  }
  return false;
}
    `;

    const partialFixNoMetadataBlock = `
async function fetchUrl(userUrl) {
  const url = new URL(userUrl);

  if (url.protocol !== 'https:') {
    throw new Error('Only HTTPS URLs are allowed');
  }

  const allowedDomains = ['api.trusted.com', 'cdn.example.com'];
  if (!allowedDomains.includes(url.hostname)) {
    throw new Error('Domain not in allowlist');
  }

  if (isPrivateIP(url.hostname)) {
    throw new Error('Internal IPs are blocked');
  }

  const response = await fetch(userUrl);
  return response.text();
}

function isPrivateIP(hostname) {
  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    return true;
  }
  // Missing metadata endpoint check!
  return false;
}
    `;

    const partialFixNoAllowlist = `
async function fetchUrl(userUrl) {
  const url = new URL(userUrl);

  if (url.protocol !== 'https:') {
    throw new Error('Only HTTPS URLs are allowed');
  }

  if (isPrivateIP(url.hostname)) {
    throw new Error('Internal IPs are blocked');
  }

  const response = await fetch(userUrl);
  return response.text();
}

function isPrivateIP(hostname) {
  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    return true;
  }
  if (hostname === '169.254.169.254') {
    return true;
  }
  return false;
}
    `;

    it('rejects vulnerable code without any validation', () => {
        expect(verifyLabSubmission('ssrf-lab', vulnerableCode)).toBe(false);
    });

    it('accepts properly secured code with all protections', () => {
        expect(verifyLabSubmission('ssrf-lab', secureCode)).toBe(true);
    });

    it('rejects partial fix missing protocol check', () => {
        expect(verifyLabSubmission('ssrf-lab', partialFixNoProtocolCheck)).toBe(false);
    });

    it('rejects partial fix missing metadata endpoint block', () => {
        expect(verifyLabSubmission('ssrf-lab', partialFixNoMetadataBlock)).toBe(false);
    });

    it('rejects partial fix missing domain allowlist', () => {
        expect(verifyLabSubmission('ssrf-lab', partialFixNoAllowlist)).toBe(false);
    });
});

describe('XXE Module', () => {
    const xxeModule = MODULES.find(m => m.id === 'xxe-attacks');

    it('exists in the modules list', () => {
        expect(xxeModule).toBeDefined();
    });

    it('has correct structure', () => {
        expect(xxeModule!.title).toBe('XML External Entity (XXE) Injection');
        expect(xxeModule!.difficulty).toBe('Advanced');
        expect(xxeModule!.xpReward).toBe(400);
        expect(xxeModule!.locked).toBe(false);
    });

    it('has theory, quiz, and lab lessons', () => {
        const lessonTypes = xxeModule!.lessons.map(l => l.type);
        expect(lessonTypes).toContain('theory');
        expect(lessonTypes).toContain('quiz');
        expect(lessonTypes).toContain('lab');
    });

    it('has exactly 7 lessons (1 theory, 5 quizzes, 1 lab)', () => {
        expect(xxeModule!.lessons.length).toBe(7);
        expect(xxeModule!.lessons.filter(l => l.type === 'theory').length).toBe(1);
        expect(xxeModule!.lessons.filter(l => l.type === 'quiz').length).toBe(5);
        expect(xxeModule!.lessons.filter(l => l.type === 'lab').length).toBe(1);
    });

    it('has a registered lab verifier', () => {
        expect(labVerifiers['xxe-lab']).toBeDefined();
    });

    it('theory covers real-world breaches (Facebook XXE)', () => {
        const theoryLesson = xxeModule!.lessons.find(l => l.id === 'xxe-theory');
        expect(theoryLesson!.content).toContain('Facebook');
        expect(theoryLesson!.content).toContain('2014');
    });

    it('theory covers SAML vulnerabilities', () => {
        const theoryLesson = xxeModule!.lessons.find(l => l.id === 'xxe-theory');
        expect(theoryLesson!.content).toContain('SAML');
        expect(theoryLesson!.content).toContain('authentication');
    });

    it('theory covers Billion Laughs attack', () => {
        const theoryLesson = xxeModule!.lessons.find(l => l.id === 'xxe-theory');
        expect(theoryLesson!.content).toContain('Billion Laughs');
        expect(theoryLesson!.content).toContain('XML bomb');
    });

    it('theory explains XML and DTD basics', () => {
        const theoryLesson = xxeModule!.lessons.find(l => l.id === 'xxe-theory');
        expect(theoryLesson!.content).toContain('Document Type Definition');
        expect(theoryLesson!.content).toContain('DTD');
        expect(theoryLesson!.content).toContain('entities');
    });
});

describe('XXE Lab Verifier', () => {
    const vulnerableCode = `
function parseUserXml(xmlInput) {
  const parser = new XMLParser({});
  const result = parser.parse(xmlInput);
  return result;
}
    `;

    const secureCode = `
function parseUserXml(xmlInput) {
  if (xmlInput.includes('<!DOCTYPE') || xmlInput.includes('<!ENTITY')) {
    throw new Error('DTD and entities are not allowed');
  }

  const parser = new XMLParser({
    allowDtd: false,
    resolveExternalEntities: false,
    processEntities: false,
    expandEntityReferences: false
  });

  const result = parser.parse(xmlInput);
  return result;
}
    `;

    const partialFixNoInputValidation = `
function parseUserXml(xmlInput) {
  const parser = new XMLParser({
    allowDtd: false,
    resolveExternalEntities: false,
    processEntities: false,
    expandEntityReferences: false
  });

  const result = parser.parse(xmlInput);
  return result;
}
    `;

    const partialFixNoParserConfig = `
function parseUserXml(xmlInput) {
  if (xmlInput.includes('<!DOCTYPE') || xmlInput.includes('<!ENTITY')) {
    throw new Error('DTD and entities are not allowed');
  }

  const parser = new XMLParser({});
  const result = parser.parse(xmlInput);
  return result;
}
    `;

    const partialFixMissingOptions = `
function parseUserXml(xmlInput) {
  if (xmlInput.includes('<!DOCTYPE') || xmlInput.includes('<!ENTITY')) {
    throw new Error('DTD and entities are not allowed');
  }

  const parser = new XMLParser({
    allowDtd: false,
    resolveExternalEntities: false
  });

  const result = parser.parse(xmlInput);
  return result;
}
    `;

    it('rejects vulnerable code without any protection', () => {
        expect(verifyLabSubmission('xxe-lab', vulnerableCode)).toBe(false);
    });

    it('accepts properly secured code with all protections', () => {
        expect(verifyLabSubmission('xxe-lab', secureCode)).toBe(true);
    });

    it('rejects partial fix missing input validation', () => {
        expect(verifyLabSubmission('xxe-lab', partialFixNoInputValidation)).toBe(false);
    });

    it('rejects partial fix missing parser configuration', () => {
        expect(verifyLabSubmission('xxe-lab', partialFixNoParserConfig)).toBe(false);
    });

    it('rejects partial fix missing some parser options', () => {
        expect(verifyLabSubmission('xxe-lab', partialFixMissingOptions)).toBe(false);
    });
});
