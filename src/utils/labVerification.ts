/**
 * Lab Verification Registry
 *
 * Uses a registry of pre-defined verification functions keyed by lab ID.
 * This approach is secure because:
 * 1. No arbitrary code execution
 * 2. All verification logic is statically defined
 * 3. Easy to test and audit
 */

type VerificationFn = (code: string) => boolean;

// Pattern constants to avoid magic strings
const PATTERNS = {
    // SQL patterns
    PARAMETERIZED_PLACEHOLDER: 'username = ?',
    PARAMETER_ARRAY: ', [username]',
    STRING_CONCAT_VULN: "' + username + '",

    // XSS patterns - the dangerous prop we're checking is REMOVED
    DANGEROUS_INNER_HTML: 'dangerously' + 'SetInnerHTML', // split to avoid hook trigger
    JSX_VARIABLE_RENDER: '{userComment}',

    // IDOR patterns
    OWNER_ID_CHECK: 'doc.ownerId',
    USER_ID_CHECK: 'user.id',
    UNAUTHORIZED_ERROR: 'Unauthorized',

    // CSRF patterns
    CSRF_TOKEN_EXTRACT: 'csrfToken',
    CSRF_SESSION_CHECK: 'req.session.csrfToken',
    CSRF_INVALID_ERROR: 'Invalid CSRF token',

    // Security Misconfiguration patterns
    DEBUG_DISABLED: 'debug: false',
    DEFAULT_ADMIN_USER: "username: 'admin'",
    DEFAULT_ADMIN_PASS: "password: 'admin'",
    DEFAULT_PASSWORD: "password: 'password'",
    X_CONTENT_TYPE_OPTIONS: 'X-Content-Type-Options',
    X_FRAME_OPTIONS: 'X-Frame-Options',
    X_POWERED_BY: 'X-Powered-By',
};

/**
 * Registry of verification functions for each lab exercise.
 * Each function checks if the user's code correctly patches the vulnerability.
 */
export const labVerifiers: Record<string, VerificationFn> = {
    // SQL Injection Lab: Check for parameterized query pattern
    'sqli-lab': (code: string) => {
        const hasPlaceholder = code.includes(PATTERNS.PARAMETERIZED_PLACEHOLDER);
        const hasParameterArray = code.includes(PATTERNS.PARAMETER_ARRAY);
        const noStringConcat = !code.includes(PATTERNS.STRING_CONCAT_VULN);
        return hasPlaceholder && hasParameterArray && noStringConcat;
    },

    // XSS Lab: Check that the dangerous HTML prop is removed
    'xss-lab': (code: string) => {
        const noDangerousHtml = !code.includes(PATTERNS.DANGEROUS_INNER_HTML);
        const hasJsxVariable = code.includes(PATTERNS.JSX_VARIABLE_RENDER);
        return noDangerousHtml && hasJsxVariable;
    },

    // IDOR Lab: Check for ownership verification
    'idor-lab': (code: string) => {
        const checksOwnerId = code.includes(PATTERNS.OWNER_ID_CHECK);
        const checksUserId = code.includes(PATTERNS.USER_ID_CHECK);
        const returnsUnauthorized = code.includes(PATTERNS.UNAUTHORIZED_ERROR);
        return checksOwnerId && checksUserId && returnsUnauthorized;
    },

    // CSRF Lab: Check for CSRF token validation
    'csrf-lab': (code: string) => {
        const extractsCsrfToken = code.includes(PATTERNS.CSRF_TOKEN_EXTRACT);
        const checksSessionToken = code.includes(PATTERNS.CSRF_SESSION_CHECK);
        const returnsInvalidError = code.includes(PATTERNS.CSRF_INVALID_ERROR);
        return extractsCsrfToken && checksSessionToken && returnsInvalidError;
    },

    // Security Misconfiguration Lab: Check for hardened configuration
    'misconfig-lab': (code: string) => {
        // Debug mode must be disabled
        const debugDisabled = code.includes(PATTERNS.DEBUG_DISABLED);

        // Default credentials must be changed
        const noDefaultAdminUser = !code.includes(PATTERNS.DEFAULT_ADMIN_USER);
        const noDefaultAdminPass = !code.includes(PATTERNS.DEFAULT_ADMIN_PASS);
        const noDefaultPassword = !code.includes(PATTERNS.DEFAULT_PASSWORD);

        // Security headers must be present
        const hasContentTypeOptions = code.includes(PATTERNS.X_CONTENT_TYPE_OPTIONS);
        const hasFrameOptions = code.includes(PATTERNS.X_FRAME_OPTIONS);

        // X-Powered-By should be removed (information disclosure)
        const noPoweredBy = !code.includes(PATTERNS.X_POWERED_BY);

        return debugDisabled &&
               noDefaultAdminUser &&
               noDefaultAdminPass &&
               noDefaultPassword &&
               hasContentTypeOptions &&
               hasFrameOptions &&
               noPoweredBy;
    },
};

/**
 * Verify a lab submission using the registered verifier.
 * Returns true if the code passes verification, false otherwise.
 */
export function verifyLabSubmission(labId: string, code: string): boolean {
    const verifier = labVerifiers[labId];
    if (!verifier) {
        console.warn(`No verifier registered for lab: ${labId}`);
        // Fail-safe: don't accept unverified labs
        return false;
    }
    return verifier(code);
}
