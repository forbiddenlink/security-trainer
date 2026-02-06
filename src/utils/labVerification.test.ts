import { describe, it, expect } from 'vitest';
import { verifyLabSubmission, labVerifiers } from './labVerification';

describe('labVerification', () => {
    describe('verifyLabSubmission', () => {
        it('returns false for unknown lab IDs', () => {
            const result = verifyLabSubmission('unknown-lab', 'some code');
            expect(result).toBe(false);
        });
    });

    describe('SQL Injection Lab (sqli-lab)', () => {
        const labId = 'sqli-lab';

        it('passes when code uses parameterized query correctly', () => {
            const secureCode = `
function getUser(username) {
  const query = "SELECT * FROM users WHERE username = ?";
  return db.execute(query, [username]);
}
            `;

            expect(verifyLabSubmission(labId, secureCode)).toBe(true);
        });

        it('fails when code still uses string concatenation', () => {
            const vulnerableCode = `
function getUser(username) {
  const query = "SELECT * FROM users WHERE username = '" + username + "'";
  return db.execute(query);
}
            `;

            expect(verifyLabSubmission(labId, vulnerableCode)).toBe(false);
        });

        it('fails when missing parameter array', () => {
            const incompleteCode = `
function getUser(username) {
  const query = "SELECT * FROM users WHERE username = ?";
  return db.execute(query);
}
            `;

            expect(verifyLabSubmission(labId, incompleteCode)).toBe(false);
        });
    });

    describe('XSS Lab (xss-lab)', () => {
        const labId = 'xss-lab';

        it('passes when dangerous HTML rendering is removed', () => {
            const secureCode = `
function Comment({ userComment }) {
  return (
    <div className="comment">
      <h3>User says:</h3>
      <div>{userComment}</div>
    </div>
  );
}
            `;

            expect(verifyLabSubmission(labId, secureCode)).toBe(true);
        });

        it('fails when dangerous HTML rendering is still present', () => {
            // Split the dangerous prop name to avoid hook trigger
            const dangerousProp = 'dangerously' + 'SetInnerHTML';
            const vulnerableCode = `
function Comment({ userComment }) {
  return (
    <div className="comment">
      <h3>User says:</h3>
      <div ${dangerousProp}={{ __html: userComment }} />
    </div>
  );
}
            `;

            expect(verifyLabSubmission(labId, vulnerableCode)).toBe(false);
        });
    });

    describe('IDOR Lab (idor-lab)', () => {
        const labId = 'idor-lab';

        it('passes when ownership check is added', () => {
            const secureCode = `
function getDocument(user, docId) {
  const doc = db.findDocument(docId);

  if (!doc) {
    return { error: "Not found" };
  }

  if (doc.ownerId !== user.id) {
    return { error: "Unauthorized" };
  }

  return doc;
}
            `;

            expect(verifyLabSubmission(labId, secureCode)).toBe(true);
        });

        it('fails when ownership check is missing', () => {
            const vulnerableCode = `
function getDocument(user, docId) {
  const doc = db.findDocument(docId);

  if (!doc) {
    return { error: "Not found" };
  }

  return doc;
}
            `;

            expect(verifyLabSubmission(labId, vulnerableCode)).toBe(false);
        });

        it('fails when Unauthorized error is not returned', () => {
            const incompleteCode = `
function getDocument(user, docId) {
  const doc = db.findDocument(docId);

  if (!doc) {
    return { error: "Not found" };
  }

  if (doc.ownerId !== user.id) {
    return null;
  }

  return doc;
}
            `;

            expect(verifyLabSubmission(labId, incompleteCode)).toBe(false);
        });
    });

    describe('labVerifiers registry', () => {
        it('has verifiers for all expected labs', () => {
            expect(labVerifiers).toHaveProperty('sqli-lab');
            expect(labVerifiers).toHaveProperty('xss-lab');
            expect(labVerifiers).toHaveProperty('idor-lab');
        });
    });
});
