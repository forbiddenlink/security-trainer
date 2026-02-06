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

    // SSRF patterns
    SSRF_URL_PARSE: 'new URL(',
    SSRF_PROTOCOL_CHECK: "protocol !== 'https:'",
    SSRF_ALLOWED_DOMAINS: 'allowedDomains',
    SSRF_DOMAIN_NOT_ALLOWED: 'Domain not in allowlist',
    SSRF_PRIVATE_IP_CHECK: 'isPrivateIP',
    SSRF_LOCALHOST_CHECK: 'localhost',
    SSRF_LOOPBACK_CHECK: '127.0.0.1',
    SSRF_METADATA_CHECK: '169.254.169.254',
    SSRF_INTERNAL_BLOCKED: 'Internal IPs are blocked',

    // XXE patterns
    XXE_DOCTYPE_CHECK: '<!DOCTYPE',
    XXE_ENTITY_CHECK: '<!ENTITY',
    XXE_INPUT_VALIDATION_ERROR: 'DTD and entities are not allowed',
    XXE_ALLOW_DTD_FALSE: 'allowDtd: false',
    XXE_RESOLVE_EXTERNAL_FALSE: 'resolveExternalEntities: false',
    XXE_PROCESS_ENTITIES_FALSE: 'processEntities: false',
    XXE_EXPAND_ENTITY_FALSE: 'expandEntityReferences: false',

    // Insecure Deserialization patterns
    DESER_HMAC_VERIFY: 'createHmac',
    DESER_SHA256: 'sha256',
    DESER_INVALID_SIGNATURE: 'Invalid signature',
    DESER_JSON_PARSE: 'JSON.parse',
    DESER_FUNCTION_CONSTRUCTOR: "Function('return '",
    DESER_TYPE_CHECK_USERID: "typeof session.userId",
    DESER_TYPE_CHECK_ROLE: "typeof session.role",
    DESER_INVALID_FORMAT: 'Invalid session format',
    DESER_ALLOWED_ROLES: 'allowedRoles',
    DESER_INVALID_ROLE: 'Invalid role',
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

    // SSRF Lab: Check for proper URL validation
    'ssrf-lab': (code: string) => {
        // Must parse the URL properly
        const parsesUrl = code.includes(PATTERNS.SSRF_URL_PARSE);

        // Must check for HTTPS protocol
        const checksProtocol = code.includes(PATTERNS.SSRF_PROTOCOL_CHECK);

        // Must have domain allowlist
        const hasAllowedDomains = code.includes(PATTERNS.SSRF_ALLOWED_DOMAINS);
        const hasDomainError = code.includes(PATTERNS.SSRF_DOMAIN_NOT_ALLOWED);

        // Must have private IP detection function
        const hasPrivateIpCheck = code.includes(PATTERNS.SSRF_PRIVATE_IP_CHECK);

        // Must block critical internal IPs
        const blocksLocalhost = code.includes(PATTERNS.SSRF_LOCALHOST_CHECK);
        const blocksLoopback = code.includes(PATTERNS.SSRF_LOOPBACK_CHECK);
        const blocksMetadata = code.includes(PATTERNS.SSRF_METADATA_CHECK);

        // Must have proper error message
        const hasInternalBlockedError = code.includes(PATTERNS.SSRF_INTERNAL_BLOCKED);

        return parsesUrl &&
               checksProtocol &&
               hasAllowedDomains &&
               hasDomainError &&
               hasPrivateIpCheck &&
               blocksLocalhost &&
               blocksLoopback &&
               blocksMetadata &&
               hasInternalBlockedError;
    },

    // XXE Lab: Check for secure XML parser configuration
    'xxe-lab': (code: string) => {
        // Must validate input for DOCTYPE and ENTITY declarations
        const checksDoctypeInInput = code.includes(PATTERNS.XXE_DOCTYPE_CHECK);
        const checksEntityInInput = code.includes(PATTERNS.XXE_ENTITY_CHECK);
        const hasInputValidationError = code.includes(PATTERNS.XXE_INPUT_VALIDATION_ERROR);

        // Must configure parser with security options
        const disablesDtd = code.includes(PATTERNS.XXE_ALLOW_DTD_FALSE);
        const disablesExternalEntities = code.includes(PATTERNS.XXE_RESOLVE_EXTERNAL_FALSE);
        const disablesProcessEntities = code.includes(PATTERNS.XXE_PROCESS_ENTITIES_FALSE);
        const disablesExpandEntity = code.includes(PATTERNS.XXE_EXPAND_ENTITY_FALSE);

        return checksDoctypeInInput &&
               checksEntityInInput &&
               hasInputValidationError &&
               disablesDtd &&
               disablesExternalEntities &&
               disablesProcessEntities &&
               disablesExpandEntity;
    },

    // Insecure Deserialization Lab: Check for safe deserialization practices
    'deser-lab': (code: string) => {
        // Must use HMAC for signature verification
        const usesHmac = code.includes(PATTERNS.DESER_HMAC_VERIFY);
        const usesSha256 = code.includes(PATTERNS.DESER_SHA256);
        const hasInvalidSignatureError = code.includes(PATTERNS.DESER_INVALID_SIGNATURE);

        // Must use JSON.parse instead of Function constructor
        const usesJsonParse = code.includes(PATTERNS.DESER_JSON_PARSE);
        const noFunctionConstructor = !code.includes(PATTERNS.DESER_FUNCTION_CONSTRUCTOR);

        // Must validate types
        const checksUserIdType = code.includes(PATTERNS.DESER_TYPE_CHECK_USERID);
        const checksRoleType = code.includes(PATTERNS.DESER_TYPE_CHECK_ROLE);
        const hasInvalidFormatError = code.includes(PATTERNS.DESER_INVALID_FORMAT);

        // Must have role allowlist
        const hasAllowedRoles = code.includes(PATTERNS.DESER_ALLOWED_ROLES);
        const hasInvalidRoleError = code.includes(PATTERNS.DESER_INVALID_ROLE);

        return usesHmac &&
               usesSha256 &&
               hasInvalidSignatureError &&
               usesJsonParse &&
               noFunctionConstructor &&
               checksUserIdType &&
               checksRoleType &&
               hasInvalidFormatError &&
               hasAllowedRoles &&
               hasInvalidRoleError;
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
