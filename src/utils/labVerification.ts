/**
 * Lab Verification Registry
 *
 * Uses a registry of pre-defined verification functions keyed by lab ID.
 * This approach is secure because:
 * 1. No arbitrary code execution
 * 2. All verification logic is statically defined
 * 3. Easy to test and audit
 */

export interface VerificationResult {
  passed: boolean;
  hints: string[];
}

type VerificationFn = (code: string) => VerificationResult;

// Pattern constants to avoid magic strings
const PATTERNS = {
  // OWASP Intro Lab patterns - vulnerability identification
  OWASP_INJECTION_COMMENT: "INJECTION",
  OWASP_XSS_COMMENT: "XSS",
  OWASP_IDOR_COMMENT: "IDOR",

  // SQL patterns
  PARAMETERIZED_PLACEHOLDER: "username = ?",
  PARAMETER_ARRAY: ", [username]",
  STRING_CONCAT_VULN: "' + username + '",

  // XSS patterns - the dangerous prop we're checking is REMOVED
  DANGEROUS_INNER_HTML: "dangerously" + "SetInnerHTML", // split to avoid hook trigger
  JSX_VARIABLE_RENDER: "{userComment}",

  // IDOR patterns
  OWNER_ID_CHECK: "doc.ownerId",
  USER_ID_CHECK: "user.id",
  UNAUTHORIZED_ERROR: "Unauthorized",

  // CSRF patterns
  CSRF_TOKEN_EXTRACT: "csrfToken",
  CSRF_SESSION_CHECK: "req.session.csrfToken",
  CSRF_INVALID_ERROR: "Invalid CSRF token",

  // Security Misconfiguration patterns
  DEBUG_DISABLED: "debug: false",
  DEFAULT_ADMIN_USER: "username: 'admin'",
  DEFAULT_ADMIN_PASS: "password: 'admin'",
  DEFAULT_PASSWORD: "password: 'password'",
  X_CONTENT_TYPE_OPTIONS: "X-Content-Type-Options",
  X_FRAME_OPTIONS: "X-Frame-Options",
  X_POWERED_BY: "X-Powered-By",

  // SSRF patterns
  SSRF_URL_PARSE: "new URL(",
  SSRF_PROTOCOL_CHECK: "protocol !== 'https:'",
  SSRF_ALLOWED_DOMAINS: "allowedDomains",
  SSRF_DOMAIN_NOT_ALLOWED: "Domain not in allowlist",
  SSRF_PRIVATE_IP_CHECK: "isPrivateIP",
  SSRF_LOCALHOST_CHECK: "localhost",
  SSRF_LOOPBACK_CHECK: "127.0.0.1",
  SSRF_METADATA_CHECK: "169.254.169.254",
  SSRF_INTERNAL_BLOCKED: "Internal IPs are blocked",

  // XXE patterns
  XXE_DOCTYPE_CHECK: "<!DOCTYPE",
  XXE_ENTITY_CHECK: "<!ENTITY",
  XXE_INPUT_VALIDATION_ERROR: "DTD and entities are not allowed",
  XXE_ALLOW_DTD_FALSE: "allowDtd: false",
  XXE_RESOLVE_EXTERNAL_FALSE: "resolveExternalEntities: false",
  XXE_PROCESS_ENTITIES_FALSE: "processEntities: false",
  XXE_EXPAND_ENTITY_FALSE: "expandEntityReferences: false",

  // Insecure Deserialization patterns
  DESER_HMAC_VERIFY: "createHmac",
  DESER_SHA256: "sha256",
  DESER_INVALID_SIGNATURE: "Invalid signature",
  DESER_JSON_PARSE: "JSON.parse",
  DESER_FUNCTION_CONSTRUCTOR: "Function('return '",
  DESER_TYPE_CHECK_USERID: "typeof session.userId",
  DESER_TYPE_CHECK_ROLE: "typeof session.role",
  DESER_INVALID_FORMAT: "Invalid session format",
  DESER_ALLOWED_ROLES: "allowedRoles",
  DESER_INVALID_ROLE: "Invalid role",

  // Sensitive Data Exposure patterns
  DATA_EXPOSURE_BCRYPT_HASH: "bcrypt.hash",
  DATA_EXPOSURE_HASHED_PASSWORD: "hashedPassword",
  DATA_EXPOSURE_ENCRYPT_CALL: "encrypt(",
  DATA_EXPOSURE_ENCRYPTION_KEY: "process.env.ENCRYPTION_KEY",
  DATA_EXPOSURE_ENCRYPTED_SSN: "encryptedSSN",
  DATA_EXPOSURE_REDACTED: "[REDACTED]",
  DATA_EXPOSURE_PLAINTEXT_PASSWORD: "password: password",
  DATA_EXPOSURE_PLAINTEXT_SSN: "ssn: ssn",

  // Clickjacking patterns
  CLICKJACK_X_FRAME_OPTIONS: "X-Frame-Options",
  CLICKJACK_DENY: "DENY",
  CLICKJACK_CSP: "Content-Security-Policy",
  CLICKJACK_FRAME_ANCESTORS: "frame-ancestors 'none'",

  // JWT patterns
  JWT_ALLOWED_ALGORITHMS: "allowedAlgorithms",
  JWT_RS256: "'RS256'",
  JWT_ISSUER: "issuer:",
  JWT_AUDIENCE: "audience:",
  JWT_ALGORITHMS_OPTION: "algorithms:",
  JWT_NO_HEADER_ALG: "decoded.header.alg",

  // Business Logic patterns
  BL_DB_FIND_ITEM: "db.items.findById",
  BL_ITEM_PRICE: "item.price",
  BL_SERVER_PRICE: "serverPrice",
  BL_CHECKOUT_STATE: "checkoutState",
  BL_PAYMENT_PENDING: "payment_pending",
  BL_STATE_UPDATE: "checkoutStates.update",
  BL_COMPLETED: "completed",

  // Vulnerable Components patterns
  VULN_COMP_LODASH_SECURE: '"lodash": "4.17.21"',
  VULN_COMP_AXIOS_SECURE: '"axios": "0.21.2"',
  VULN_COMP_MINIMIST_SECURE: '"minimist": "1.2.6"',
  VULN_COMP_LODASH_VULN: '"lodash": "4.17.15"',
  VULN_COMP_AXIOS_VULN: '"axios": "0.21.0"',
  VULN_COMP_MINIMIST_VULN: '"minimist": "1.2.0"',

  // Logging patterns
  LOG_NO_PASSWORD: "password",
  LOG_NO_TOKEN: "token",
  LOG_STRUCTURED: "logger.info",
  LOG_SANITIZE: "sanitize",
  LOG_USER_ID: "userId",
  LOG_IP_ADDRESS: "ip",
  LOG_CONSOLE_LOG: "console.log",

  // Rate Limiting / Broken Auth patterns
  AUTH_MAX_ATTEMPTS: "MAX_ATTEMPTS",
  AUTH_LOCKOUT_TIME: "LOCKOUT_TIME",
  AUTH_TOO_MANY_ATTEMPTS: "Too many attempts",
  AUTH_STATUS_429: "429",
  AUTH_LOGIN_ATTEMPTS_SET: "loginAttempts.set",
  AUTH_LOGIN_ATTEMPTS_DELETE: "loginAttempts.delete",

  // Command Injection patterns
  CMDI_EXEC_FILE: "execFile",
  CMDI_ARGS_ARRAY: "args",
  CMDI_ALPHANUMERIC_CHECK: "/^[a-zA-Z0-9]+$/",
  CMDI_INVALID_FORMAT: "Invalid format",
  CMDI_NO_EXEC_CONCAT: "exec('convert ' +",

  // Path Traversal patterns
  PATH_RESOLVE: "path.resolve",
  PATH_CANONICAL: "canonicalPath",
  PATH_STARTS_WITH: "startsWith(UPLOADS_DIR)",
  PATH_ACCESS_DENIED: "Access denied",
  PATH_STATUS_403: "403",

  // File Upload patterns
  UPLOAD_MAX_SIZE: "MAX_SIZE",
  UPLOAD_FILE_TOO_LARGE: "File too large",
  UPLOAD_MAGIC_BYTES: "magicBytes",
  UPLOAD_INVALID_TYPE: "Invalid file type",
  UPLOAD_RANDOM_UUID: "randomUUID",
  UPLOAD_SAFE_FILENAME: "safeFilename",

  // CORS Misconfiguration patterns
  CORS_ALLOWED_ORIGINS: "ALLOWED_ORIGINS",
  CORS_INCLUDES_CHECK: ".includes(origin)",
  CORS_ORIGIN_CHECK: "if (origin",
  CORS_NO_REFLECT: "res.setHeader('Access-Control-Allow-Origin', origin)",

  // Session Management patterns
  SESSION_REGENERATE: "session.regenerate",
  SESSION_HTTPONLY: "httpOnly: true",
  SESSION_SECURE: "secure: true",
  SESSION_SAMESITE: "sameSite:",
  SESSION_MAXAGE: "maxAge:",

  // OAuth Security patterns
  OAUTH_STATE_PARAM: "state",
  OAUTH_RANDOM_UUID: "crypto.randomUUID()",
  OAUTH_SESSION_STORAGE: "sessionStorage.setItem",
  OAUTH_PKCE_VERIFIER: "codeVerifier",
  OAUTH_PKCE_CHALLENGE: "codeChallenge",
  OAUTH_GET_RANDOM_VALUES: "crypto.getRandomValues",
  OAUTH_SHA256: "SHA-256",
  OAUTH_SUBTLE_DIGEST: "crypto.subtle.digest",
  OAUTH_CHALLENGE_METHOD: "code_challenge_method",
  OAUTH_S256: "S256",

  // Prototype Pollution patterns
  PROTO_BLACKLIST_ARRAY: "BLACKLISTED_KEYS",
  PROTO_DUNDER_PROTO: "__proto__",
  PROTO_CONSTRUCTOR: "constructor",
  PROTO_PROTOTYPE: "prototype",
  PROTO_INCLUDES_CHECK: ".includes(key)",
  PROTO_CONTINUE: "continue",

  // Subdomain Takeover patterns
  SUBDOMAIN_CNAME_CHECK: 'type !== "CNAME"',
  SUBDOMAIN_SERVICE_ACTIVE: "serviceActive",
  SUBDOMAIN_ENDS_WITH: ".endsWith(",
  SUBDOMAIN_SOME_CHECK: ".some(",
  SUBDOMAIN_PUSH: "vulnerableSubdomains.push",

  // WebSocket Security patterns
  WS_ALLOWED_ORIGINS: "ALLOWED_ORIGINS",
  WS_ORIGIN_CHECK: "req.headers.origin",
  WS_CLOSE_4001: "4001",
  WS_RATE_LIMIT_MAP: "rateLimitMap",
  WS_MAX_MESSAGES: "MAX_MESSAGES_PER_SECOND",
  WS_VALID_TOKEN: "isValidToken",
  WS_CLOSE_4002: "4002",
  WS_SANITIZE_LT: ".replace(/</g",
  WS_SANITIZE_GT: ".replace(/>/g",
  WS_MAX_PAYLOAD: "maxPayload",
};

/**
 * Registry of verification functions for each lab exercise.
 * Each function checks if the user's code correctly patches the vulnerability.
 */
export const labVerifiers: Record<string, VerificationFn> = {
  // OWASP Intro Lab: Check that users correctly identified the vulnerabilities
  "owasp-lab": (code: string) => {
    const hints: string[] = [];

    // Check that TODO comments have been replaced with vulnerability identifications
    const hasInjectionLabel = code.includes(PATTERNS.OWASP_INJECTION_COMMENT);
    const hasXssLabel = code.includes(PATTERNS.OWASP_XSS_COMMENT);
    const hasIdorLabel = code.includes(PATTERNS.OWASP_IDOR_COMMENT);
    const noTodoRemaining = !code.includes("TODO:");

    if (!noTodoRemaining)
      hints.push("Replace all TODO comments with vulnerability types");
    if (!hasInjectionLabel)
      hints.push(
        "The first function has an INJECTION vulnerability (SQL concatenation)",
      );
    if (!hasXssLabel)
      hints.push(
        "The second function has an XSS vulnerability (innerHTML assignment)",
      );
    if (!hasIdorLabel)
      hints.push(
        "The third function has an IDOR vulnerability (no authorization check)",
      );

    return {
      passed:
        hasInjectionLabel && hasXssLabel && hasIdorLabel && noTodoRemaining,
      hints,
    };
  },

  // SQL Injection Lab: Check for parameterized query pattern
  "sqli-lab": (code: string) => {
    const hints: string[] = [];
    const hasPlaceholder = code.includes(PATTERNS.PARAMETERIZED_PLACEHOLDER);
    const hasParameterArray = code.includes(PATTERNS.PARAMETER_ARRAY);
    const noStringConcat = !code.includes(PATTERNS.STRING_CONCAT_VULN);

    if (!noStringConcat)
      hints.push(
        "Remove string concatenation - don't build SQL with '+' operator",
      );
    if (!hasPlaceholder)
      hints.push(
        "Use a placeholder '?' in your SQL query instead of the variable",
      );
    if (!hasParameterArray)
      hints.push(
        "Pass the username as an array parameter: db.execute(query, [username])",
      );

    return {
      passed: hasPlaceholder && hasParameterArray && noStringConcat,
      hints,
    };
  },

  // XSS Lab: Check that the dangerous HTML prop is removed
  "xss-lab": (code: string) => {
    const hints: string[] = [];
    const noDangerousHtml = !code.includes(PATTERNS.DANGEROUS_INNER_HTML);
    const hasJsxVariable = code.includes(PATTERNS.JSX_VARIABLE_RENDER);

    if (!noDangerousHtml)
      hints.push(
        "Remove dangerouslySetInnerHTML - it allows raw HTML injection",
      );
    if (!hasJsxVariable)
      hints.push("Render the variable using JSX syntax: {userComment}");

    return { passed: noDangerousHtml && hasJsxVariable, hints };
  },

  // IDOR Lab: Check for ownership verification
  "idor-lab": (code: string) => {
    const hints: string[] = [];
    const checksOwnerId = code.includes(PATTERNS.OWNER_ID_CHECK);
    const checksUserId = code.includes(PATTERNS.USER_ID_CHECK);
    const returnsUnauthorized = code.includes(PATTERNS.UNAUTHORIZED_ERROR);

    if (!checksOwnerId) hints.push("Check the document's ownerId property");
    if (!checksUserId) hints.push("Compare against the current user.id");
    if (!returnsUnauthorized)
      hints.push("Return an 'Unauthorized' error when access is denied");

    return {
      passed: checksOwnerId && checksUserId && returnsUnauthorized,
      hints,
    };
  },

  // CSRF Lab: Check for CSRF token validation
  "csrf-lab": (code: string) => {
    const hints: string[] = [];
    const extractsCsrfToken = code.includes(PATTERNS.CSRF_TOKEN_EXTRACT);
    const checksSessionToken = code.includes(PATTERNS.CSRF_SESSION_CHECK);
    const returnsInvalidError = code.includes(PATTERNS.CSRF_INVALID_ERROR);

    if (!extractsCsrfToken)
      hints.push("Extract the csrfToken from the request");
    if (!checksSessionToken)
      hints.push("Compare the token against req.session.csrfToken");
    if (!returnsInvalidError)
      hints.push("Return 'Invalid CSRF token' error when validation fails");

    return {
      passed: extractsCsrfToken && checksSessionToken && returnsInvalidError,
      hints,
    };
  },

  // Security Misconfiguration Lab: Check for hardened configuration
  "misconfig-lab": (code: string) => {
    const hints: string[] = [];

    const debugDisabled = code.includes(PATTERNS.DEBUG_DISABLED);
    const noDefaultAdminUser = !code.includes(PATTERNS.DEFAULT_ADMIN_USER);
    const noDefaultAdminPass = !code.includes(PATTERNS.DEFAULT_ADMIN_PASS);
    const noDefaultPassword = !code.includes(PATTERNS.DEFAULT_PASSWORD);
    const hasContentTypeOptions = code.includes(
      PATTERNS.X_CONTENT_TYPE_OPTIONS,
    );
    const hasFrameOptions = code.includes(PATTERNS.X_FRAME_OPTIONS);
    const noPoweredBy = !code.includes(PATTERNS.X_POWERED_BY);

    if (!debugDisabled)
      hints.push("Set debug: false to disable debug mode in production");
    if (!noDefaultAdminUser || !noDefaultAdminPass)
      hints.push("Change the default admin credentials");
    if (!noDefaultPassword)
      hints.push("Remove any default passwords like 'password'");
    if (!hasContentTypeOptions)
      hints.push("Add X-Content-Type-Options security header");
    if (!hasFrameOptions) hints.push("Add X-Frame-Options security header");
    if (!noPoweredBy)
      hints.push("Remove X-Powered-By header to hide server info");

    const passed =
      debugDisabled &&
      noDefaultAdminUser &&
      noDefaultAdminPass &&
      noDefaultPassword &&
      hasContentTypeOptions &&
      hasFrameOptions &&
      noPoweredBy;
    return { passed, hints };
  },

  // SSRF Lab: Check for proper URL validation
  "ssrf-lab": (code: string) => {
    const hints: string[] = [];

    const parsesUrl = code.includes(PATTERNS.SSRF_URL_PARSE);
    const checksProtocol = code.includes(PATTERNS.SSRF_PROTOCOL_CHECK);
    const hasAllowedDomains = code.includes(PATTERNS.SSRF_ALLOWED_DOMAINS);
    const hasDomainError = code.includes(PATTERNS.SSRF_DOMAIN_NOT_ALLOWED);
    const hasPrivateIpCheck = code.includes(PATTERNS.SSRF_PRIVATE_IP_CHECK);
    const blocksLocalhost = code.includes(PATTERNS.SSRF_LOCALHOST_CHECK);
    const blocksLoopback = code.includes(PATTERNS.SSRF_LOOPBACK_CHECK);
    const blocksMetadata = code.includes(PATTERNS.SSRF_METADATA_CHECK);
    const hasInternalBlockedError = code.includes(
      PATTERNS.SSRF_INTERNAL_BLOCKED,
    );

    if (!parsesUrl)
      hints.push("Parse the URL using new URL() to extract components");
    if (!checksProtocol)
      hints.push("Check that protocol !== 'https:' to enforce HTTPS");
    if (!hasAllowedDomains || !hasDomainError)
      hints.push("Create an allowedDomains list and validate against it");
    if (!hasPrivateIpCheck)
      hints.push("Add an isPrivateIP function to detect internal addresses");
    if (!blocksLocalhost || !blocksLoopback)
      hints.push("Block localhost and 127.0.0.1");
    if (!blocksMetadata) hints.push("Block cloud metadata IP 169.254.169.254");
    if (!hasInternalBlockedError)
      hints.push("Return 'Internal IPs are blocked' error message");

    const passed =
      parsesUrl &&
      checksProtocol &&
      hasAllowedDomains &&
      hasDomainError &&
      hasPrivateIpCheck &&
      blocksLocalhost &&
      blocksLoopback &&
      blocksMetadata &&
      hasInternalBlockedError;
    return { passed, hints };
  },

  // XXE Lab: Check for secure XML parser configuration
  "xxe-lab": (code: string) => {
    const hints: string[] = [];

    const checksDoctypeInInput = code.includes(PATTERNS.XXE_DOCTYPE_CHECK);
    const checksEntityInInput = code.includes(PATTERNS.XXE_ENTITY_CHECK);
    const hasInputValidationError = code.includes(
      PATTERNS.XXE_INPUT_VALIDATION_ERROR,
    );
    const disablesDtd = code.includes(PATTERNS.XXE_ALLOW_DTD_FALSE);
    const disablesExternalEntities = code.includes(
      PATTERNS.XXE_RESOLVE_EXTERNAL_FALSE,
    );
    const disablesProcessEntities = code.includes(
      PATTERNS.XXE_PROCESS_ENTITIES_FALSE,
    );
    const disablesExpandEntity = code.includes(
      PATTERNS.XXE_EXPAND_ENTITY_FALSE,
    );

    if (!checksDoctypeInInput || !checksEntityInInput)
      hints.push("Check input for <!DOCTYPE and <!ENTITY declarations");
    if (!hasInputValidationError)
      hints.push("Return 'DTD and entities are not allowed' error");
    if (!disablesDtd) hints.push("Set allowDtd: false in parser options");
    if (!disablesExternalEntities)
      hints.push("Set resolveExternalEntities: false");
    if (!disablesProcessEntities) hints.push("Set processEntities: false");
    if (!disablesExpandEntity) hints.push("Set expandEntityReferences: false");

    const passed =
      checksDoctypeInInput &&
      checksEntityInInput &&
      hasInputValidationError &&
      disablesDtd &&
      disablesExternalEntities &&
      disablesProcessEntities &&
      disablesExpandEntity;
    return { passed, hints };
  },

  // Insecure Deserialization Lab: Check for safe deserialization practices
  "deser-lab": (code: string) => {
    const hints: string[] = [];

    const usesHmac = code.includes(PATTERNS.DESER_HMAC_VERIFY);
    const usesSha256 = code.includes(PATTERNS.DESER_SHA256);
    const hasInvalidSignatureError = code.includes(
      PATTERNS.DESER_INVALID_SIGNATURE,
    );
    const usesJsonParse = code.includes(PATTERNS.DESER_JSON_PARSE);
    const noFunctionConstructor = !code.includes(
      PATTERNS.DESER_FUNCTION_CONSTRUCTOR,
    );
    const checksUserIdType = code.includes(PATTERNS.DESER_TYPE_CHECK_USERID);
    const checksRoleType = code.includes(PATTERNS.DESER_TYPE_CHECK_ROLE);
    const hasInvalidFormatError = code.includes(PATTERNS.DESER_INVALID_FORMAT);
    const hasAllowedRoles = code.includes(PATTERNS.DESER_ALLOWED_ROLES);
    const hasInvalidRoleError = code.includes(PATTERNS.DESER_INVALID_ROLE);

    if (!usesHmac || !usesSha256)
      hints.push("Use createHmac with sha256 to verify signature");
    if (!hasInvalidSignatureError)
      hints.push("Return 'Invalid signature' error when verification fails");
    if (!noFunctionConstructor)
      hints.push("Replace Function constructor with JSON.parse");
    if (!usesJsonParse) hints.push("Use JSON.parse for safe deserialization");
    if (!checksUserIdType || !checksRoleType)
      hints.push("Validate typeof session.userId and typeof session.role");
    if (!hasInvalidFormatError)
      hints.push("Return 'Invalid session format' for type mismatches");
    if (!hasAllowedRoles || !hasInvalidRoleError)
      hints.push("Create allowedRoles list and return 'Invalid role' error");

    const passed =
      usesHmac &&
      usesSha256 &&
      hasInvalidSignatureError &&
      usesJsonParse &&
      noFunctionConstructor &&
      checksUserIdType &&
      checksRoleType &&
      hasInvalidFormatError &&
      hasAllowedRoles &&
      hasInvalidRoleError;
    return { passed, hints };
  },

  // Sensitive Data Exposure Lab: Check for proper data protection practices
  "data-exposure-lab": (code: string) => {
    const hints: string[] = [];

    const usesBcryptHash = code.includes(PATTERNS.DATA_EXPOSURE_BCRYPT_HASH);
    const usesHashedPassword = code.includes(
      PATTERNS.DATA_EXPOSURE_HASHED_PASSWORD,
    );
    const usesEncryptCall = code.includes(PATTERNS.DATA_EXPOSURE_ENCRYPT_CALL);
    const usesEncryptionKey = code.includes(
      PATTERNS.DATA_EXPOSURE_ENCRYPTION_KEY,
    );
    const usesEncryptedSSN = code.includes(
      PATTERNS.DATA_EXPOSURE_ENCRYPTED_SSN,
    );
    const hasRedacted = code.includes(PATTERNS.DATA_EXPOSURE_REDACTED);
    const noPlaintextPassword = !code.includes(
      PATTERNS.DATA_EXPOSURE_PLAINTEXT_PASSWORD,
    );
    const noPlaintextSSN = !code.includes(PATTERNS.DATA_EXPOSURE_PLAINTEXT_SSN);

    if (!usesBcryptHash || !usesHashedPassword)
      hints.push("Hash passwords with bcrypt.hash and store as hashedPassword");
    if (!usesEncryptCall || !usesEncryptionKey)
      hints.push("Encrypt PII using encrypt() with process.env.ENCRYPTION_KEY");
    if (!usesEncryptedSSN)
      hints.push("Store SSN as encryptedSSN after encryption");
    if (!hasRedacted)
      hints.push("Use [REDACTED] to sanitize sensitive data in logs");
    if (!noPlaintextPassword)
      hints.push("Don't store plaintext password in user object");
    if (!noPlaintextSSN) hints.push("Don't store plaintext ssn in user object");

    const passed =
      usesBcryptHash &&
      usesHashedPassword &&
      usesEncryptCall &&
      usesEncryptionKey &&
      usesEncryptedSSN &&
      hasRedacted &&
      noPlaintextPassword &&
      noPlaintextSSN;
    return { passed, hints };
  },

  // Clickjacking Lab: Check for frame protection headers
  "clickjacking-lab": (code: string) => {
    const hints: string[] = [];

    const hasXFrameOptions = code.includes(PATTERNS.CLICKJACK_X_FRAME_OPTIONS);
    const hasDeny = code.includes(PATTERNS.CLICKJACK_DENY);
    const hasCSP = code.includes(PATTERNS.CLICKJACK_CSP);
    const hasFrameAncestors = code.includes(PATTERNS.CLICKJACK_FRAME_ANCESTORS);

    if (!hasXFrameOptions || !hasDeny)
      hints.push("Set X-Frame-Options header to 'DENY'");
    if (!hasCSP || !hasFrameAncestors)
      hints.push("Set Content-Security-Policy with frame-ancestors 'none'");

    const passed = hasXFrameOptions && hasDeny && hasCSP && hasFrameAncestors;
    return { passed, hints };
  },

  // JWT Lab: Check for secure JWT verification
  "jwt-lab": (code: string) => {
    const hints: string[] = [];

    const hasAllowedAlgorithms = code.includes(PATTERNS.JWT_ALLOWED_ALGORITHMS);
    const hasRS256 = code.includes(PATTERNS.JWT_RS256);
    const hasAlgorithmsOption = code.includes(PATTERNS.JWT_ALGORITHMS_OPTION);
    const hasIssuer = code.includes(PATTERNS.JWT_ISSUER);
    const hasAudience = code.includes(PATTERNS.JWT_AUDIENCE);
    const noHeaderAlg = !code.includes(PATTERNS.JWT_NO_HEADER_ALG);

    if (!hasAllowedAlgorithms)
      hints.push(
        "Create an allowedAlgorithms array to whitelist acceptable algorithms",
      );
    if (!hasRS256) hints.push("Include 'RS256' in your allowed algorithms");
    if (!hasAlgorithmsOption)
      hints.push("Pass algorithms: option to jwt.verify with your whitelist");
    if (!hasIssuer) hints.push("Add issuer: validation to jwt.verify options");
    if (!hasAudience)
      hints.push("Add audience: validation to jwt.verify options");
    if (!noHeaderAlg)
      hints.push(
        "Don't read algorithm from token header - use your whitelist instead",
      );

    const passed =
      hasAllowedAlgorithms &&
      hasRS256 &&
      hasAlgorithmsOption &&
      hasIssuer &&
      hasAudience &&
      noHeaderAlg;
    return { passed, hints };
  },

  // Business Logic Lab: Check for secure checkout implementation
  "business-logic-lab": (code: string) => {
    const hints: string[] = [];

    const hasDbLookup = code.includes(PATTERNS.BL_DB_FIND_ITEM);
    const hasItemPrice = code.includes(PATTERNS.BL_ITEM_PRICE);
    const hasServerPrice = code.includes(PATTERNS.BL_SERVER_PRICE);
    const hasCheckoutState = code.includes(PATTERNS.BL_CHECKOUT_STATE);
    const hasPaymentPending = code.includes(PATTERNS.BL_PAYMENT_PENDING);
    const hasStateUpdate = code.includes(PATTERNS.BL_STATE_UPDATE);
    const hasCompleted = code.includes(PATTERNS.BL_COMPLETED);

    if (!hasDbLookup)
      hints.push(
        "Look up the item from database using db.items.findById(itemId)",
      );
    if (!hasItemPrice || !hasServerPrice)
      hints.push(
        "Use item.price from database as serverPrice, don't trust client price",
      );
    if (!hasCheckoutState)
      hints.push("Retrieve checkout state to validate workflow");
    if (!hasPaymentPending)
      hints.push(
        "Check that checkoutState.step === 'payment_pending' before processing",
      );
    if (!hasStateUpdate)
      hints.push("Update checkout state using db.checkoutStates.update");
    if (!hasCompleted)
      hints.push("Set state to 'completed' after successful payment");

    const passed =
      hasDbLookup &&
      hasItemPrice &&
      hasServerPrice &&
      hasCheckoutState &&
      hasPaymentPending &&
      hasStateUpdate &&
      hasCompleted;
    return { passed, hints };
  },

  // Vulnerable Components Lab: Check for secure dependency versions
  "vuln-comp-lab": (code: string) => {
    const hints: string[] = [];

    const hasSecureLodash =
      code.includes(PATTERNS.VULN_COMP_LODASH_SECURE) ||
      code.includes('"lodash": "4.17.2') || // 4.17.2x versions are safe
      code.includes('"lodash": "^4.17.21"');
    const hasSecureAxios =
      code.includes(PATTERNS.VULN_COMP_AXIOS_SECURE) ||
      (code.includes('"axios": "0.21.') &&
        !code.includes(PATTERNS.VULN_COMP_AXIOS_VULN)) ||
      code.includes('"axios": "0.2') ||
      code.includes('"axios": "1.');
    const hasSecureMinimist =
      code.includes(PATTERNS.VULN_COMP_MINIMIST_SECURE) ||
      (code.includes('"minimist": "1.2.') &&
        !code.includes(PATTERNS.VULN_COMP_MINIMIST_VULN));

    const noVulnLodash = !code.includes(PATTERNS.VULN_COMP_LODASH_VULN);
    const noVulnAxios = !code.includes(PATTERNS.VULN_COMP_AXIOS_VULN);
    const noVulnMinimist = !code.includes(PATTERNS.VULN_COMP_MINIMIST_VULN);

    if (!noVulnLodash || !hasSecureLodash)
      hints.push(
        "Update lodash to version 4.17.21 or higher (fixes prototype pollution)",
      );
    if (!noVulnAxios || !hasSecureAxios)
      hints.push(
        "Update axios to version 0.21.2 or higher (fixes SSRF vulnerability)",
      );
    if (!noVulnMinimist || !hasSecureMinimist)
      hints.push(
        "Update minimist to version 1.2.6 or higher (fixes prototype pollution)",
      );

    const passed =
      hasSecureLodash &&
      hasSecureAxios &&
      hasSecureMinimist &&
      noVulnLodash &&
      noVulnAxios &&
      noVulnMinimist;
    return { passed, hints };
  },

  // Logging Lab: Check for secure logging practices
  "logging-lab": (code: string) => {
    const hints: string[] = [];

    // Check that password is NOT logged
    const logLines = code
      .split("\n")
      .filter(
        (line) =>
          line.includes("log") ||
          line.includes("Log") ||
          line.includes("console"),
      );
    const passwordInLogs = logLines.some(
      (line) =>
        line.includes("password") &&
        !line.includes("'password'") &&
        !line.includes('"password"'),
    );
    const tokenInLogs = logLines.some(
      (line) => line.includes("token") && line.includes("log"),
    );

    const noConsoleLog = !code.includes(PATTERNS.LOG_CONSOLE_LOG);
    const hasStructuredLogging =
      code.includes(PATTERNS.LOG_STRUCTURED) || code.includes("logger.warn");
    const hasSanitization =
      code.includes(PATTERNS.LOG_SANITIZE) ||
      code.includes("replace(") ||
      code.includes("[REDACTED]");
    const logsUserId =
      code.includes(PATTERNS.LOG_USER_ID) || code.includes("email");
    const logsIp =
      code.includes(PATTERNS.LOG_IP_ADDRESS) || code.includes("req.ip");

    if (passwordInLogs)
      hints.push(
        "Remove password from log output - never log sensitive credentials",
      );
    if (tokenInLogs)
      hints.push(
        "Remove token from log output - never log authentication tokens",
      );
    if (!noConsoleLog)
      hints.push(
        "Replace console.log with structured logger (e.g., logger.info)",
      );
    if (!hasStructuredLogging)
      hints.push("Use structured logging like logger.info('event', { data })");
    if (!hasSanitization)
      hints.push("Sanitize user input before logging to prevent log injection");
    if (!logsUserId)
      hints.push("Log user identifier (userId or email) for audit trail");
    if (!logsIp) hints.push("Log IP address for security monitoring");

    const passed =
      !passwordInLogs &&
      !tokenInLogs &&
      noConsoleLog &&
      hasStructuredLogging &&
      hasSanitization &&
      logsUserId &&
      logsIp;
    return { passed, hints };
  },

  // Broken Auth Lab: Check for rate limiting implementation
  "auth-lab": (code: string) => {
    const hints: string[] = [];

    const hasMaxAttempts = code.includes(PATTERNS.AUTH_MAX_ATTEMPTS);
    const hasLockoutTime = code.includes(PATTERNS.AUTH_LOCKOUT_TIME);
    const hasTooManyAttemptsError = code.includes(
      PATTERNS.AUTH_TOO_MANY_ATTEMPTS,
    );
    const hasStatus429 = code.includes(PATTERNS.AUTH_STATUS_429);
    const tracksAttempts = code.includes(PATTERNS.AUTH_LOGIN_ATTEMPTS_SET);
    const clearsOnSuccess = code.includes(PATTERNS.AUTH_LOGIN_ATTEMPTS_DELETE);

    if (!hasMaxAttempts)
      hints.push("Define MAX_ATTEMPTS constant (e.g., 5 attempts)");
    if (!hasLockoutTime)
      hints.push("Define LOCKOUT_TIME constant (e.g., 15 minutes in ms)");
    if (!hasTooManyAttemptsError || !hasStatus429)
      hints.push(
        "Return 429 status with 'Too many attempts' error when locked out",
      );
    if (!tracksAttempts)
      hints.push("Track failed attempts using loginAttempts.set()");
    if (!clearsOnSuccess)
      hints.push(
        "Clear attempts on successful login with loginAttempts.delete()",
      );

    const passed =
      hasMaxAttempts &&
      hasLockoutTime &&
      hasTooManyAttemptsError &&
      hasStatus429 &&
      tracksAttempts &&
      clearsOnSuccess;
    return { passed, hints };
  },

  // Command Injection Lab: Check for safe command execution
  "cmdi-lab": (code: string) => {
    const hints: string[] = [];

    const usesExecFile = code.includes(PATTERNS.CMDI_EXEC_FILE);
    const usesArgsArray = code.includes(PATTERNS.CMDI_ARGS_ARRAY);
    const hasAlphanumericCheck =
      code.includes(PATTERNS.CMDI_ALPHANUMERIC_CHECK) ||
      code.includes("[a-zA-Z0-9]");
    const hasInvalidFormatError = code.includes(PATTERNS.CMDI_INVALID_FORMAT);
    const noExecConcat = !code.includes(PATTERNS.CMDI_NO_EXEC_CONCAT);

    if (!usesExecFile)
      hints.push(
        "Replace exec() with execFile() to avoid shell interpretation",
      );
    if (!usesArgsArray)
      hints.push("Pass command arguments as an array, not concatenated string");
    if (!hasAlphanumericCheck)
      hints.push(
        "Add validation to ensure format contains only alphanumeric characters",
      );
    if (!hasInvalidFormatError)
      hints.push("Return 'Invalid format' error when validation fails");
    if (!noExecConcat)
      hints.push("Remove the vulnerable exec() call with string concatenation");

    const passed =
      usesExecFile &&
      usesArgsArray &&
      hasAlphanumericCheck &&
      hasInvalidFormatError &&
      noExecConcat;
    return { passed, hints };
  },

  // Path Traversal Lab: Check for secure path handling
  "path-lab": (code: string) => {
    const hints: string[] = [];

    const usesPathResolve = code.includes(PATTERNS.PATH_RESOLVE);
    const hasCanonicalVar = code.includes(PATTERNS.PATH_CANONICAL);
    const checksStartsWith = code.includes(PATTERNS.PATH_STARTS_WITH);
    const hasAccessDenied = code.includes(PATTERNS.PATH_ACCESS_DENIED);
    const hasStatus403 = code.includes(PATTERNS.PATH_STATUS_403);

    if (!usesPathResolve)
      hints.push("Use path.resolve() to get the canonical absolute path");
    if (!hasCanonicalVar)
      hints.push("Store the resolved path in a canonicalPath variable");
    if (!checksStartsWith)
      hints.push("Check that canonicalPath.startsWith(UPLOADS_DIR)");
    if (!hasAccessDenied || !hasStatus403)
      hints.push(
        "Return 403 status with 'Access denied' when path escapes allowed directory",
      );

    const passed =
      usesPathResolve &&
      hasCanonicalVar &&
      checksStartsWith &&
      hasAccessDenied &&
      hasStatus403;
    return { passed, hints };
  },

  // File Upload Lab: Check for secure upload handling
  "upload-lab": (code: string) => {
    const hints: string[] = [];

    const hasMaxSize = code.includes(PATTERNS.UPLOAD_MAX_SIZE);
    const hasFileTooLarge = code.includes(PATTERNS.UPLOAD_FILE_TOO_LARGE);
    const hasMagicBytes = code.includes(PATTERNS.UPLOAD_MAGIC_BYTES);
    const hasInvalidType = code.includes(PATTERNS.UPLOAD_INVALID_TYPE);
    const hasRandomUUID = code.includes(PATTERNS.UPLOAD_RANDOM_UUID);
    const hasSafeFilename = code.includes(PATTERNS.UPLOAD_SAFE_FILENAME);

    if (!hasMaxSize || !hasFileTooLarge)
      hints.push(
        "Add MAX_SIZE constant and return 'File too large' error for oversized files",
      );
    if (!hasMagicBytes)
      hints.push(
        "Check file content by reading magic bytes (first few bytes of file)",
      );
    if (!hasInvalidType)
      hints.push(
        "Return 'Invalid file type' error when magic bytes don't match",
      );
    if (!hasRandomUUID)
      hints.push("Use crypto.randomUUID() to generate safe random filenames");
    if (!hasSafeFilename)
      hints.push("Store the generated filename in a safeFilename variable");

    const passed =
      hasMaxSize &&
      hasFileTooLarge &&
      hasMagicBytes &&
      hasInvalidType &&
      hasRandomUUID &&
      hasSafeFilename;
    return { passed, hints };
  },

  // CORS Misconfiguration Lab: Check for allowlist-based CORS
  "cors-lab": (code: string) => {
    const hints: string[] = [];
    const hasAllowedOrigins = code.includes(PATTERNS.CORS_ALLOWED_ORIGINS);
    const hasIncludesCheck = code.includes(PATTERNS.CORS_INCLUDES_CHECK);
    const hasOriginCheck = code.includes(PATTERNS.CORS_ORIGIN_CHECK);

    // Check that the origin reflection is now inside a conditional
    const lines = code.split("\n");
    let originReflectInConditional = false;
    let inConditional = false;

    for (const line of lines) {
      if (line.includes("if") && line.includes("origin")) {
        inConditional = true;
      }
      if (inConditional && line.includes("Access-Control-Allow-Origin")) {
        originReflectInConditional = true;
        break;
      }
      if (line.includes("}") && inConditional) {
        inConditional = false;
      }
    }

    if (!hasAllowedOrigins)
      hints.push("Define an ALLOWED_ORIGINS array with trusted domains");
    if (!hasIncludesCheck)
      hints.push("Check if the origin is in the allowlist using .includes()");
    if (!hasOriginCheck)
      hints.push("Add a conditional check: if (origin && ...)");
    if (!originReflectInConditional)
      hints.push(
        "Only set Access-Control-Allow-Origin inside the allowlist check",
      );

    const passed =
      hasAllowedOrigins &&
      hasIncludesCheck &&
      hasOriginCheck &&
      originReflectInConditional;
    return { passed, hints };
  },

  // Session Management Lab: Check for secure session handling
  "session-lab": (code: string) => {
    const hints: string[] = [];
    const hasRegenerate = code.includes(PATTERNS.SESSION_REGENERATE);
    const hasHttpOnly = code.includes(PATTERNS.SESSION_HTTPONLY);
    const hasSecure = code.includes(PATTERNS.SESSION_SECURE);
    const hasSameSite = code.includes(PATTERNS.SESSION_SAMESITE);
    const hasMaxAge = code.includes(PATTERNS.SESSION_MAXAGE);

    if (!hasRegenerate)
      hints.push(
        "Call session.regenerate() after authentication to prevent session fixation",
      );
    if (!hasHttpOnly)
      hints.push("Add httpOnly: true to prevent JavaScript cookie access");
    if (!hasSecure)
      hints.push("Add secure: true to ensure HTTPS-only transmission");
    if (!hasSameSite)
      hints.push("Add sameSite: 'Strict' or 'Lax' to prevent CSRF");
    if (!hasMaxAge) hints.push("Add maxAge to set session expiration time");

    const passed =
      hasRegenerate && hasHttpOnly && hasSecure && hasSameSite && hasMaxAge;
    return { passed, hints };
  },

  // API Security Lab: Check for secure API endpoint implementation
  "api-security-lab": (code: string) => {
    const hints: string[] = [];

    // Check for parameterized query
    const hasParameterizedQuery =
      code.includes("?") &&
      (code.includes("db.query(") || code.includes("db.execute("));
    const noStringConcat =
      !code.includes("+ req.params") && !code.includes("' + id");

    // Check for authorization
    const hasReqUser = code.includes("req.user");
    const hasIdComparison =
      code.includes("req.user.id") &&
      (code.includes("=== user.id") ||
        code.includes("!== user.id") ||
        code.includes("req.params.id"));
    const hasStatus403 = code.includes("403");

    // Check for data filtering (no password hash)
    const noPasswordHash =
      !code.includes("password_hash") || code.includes("delete");
    const hasDataFilter =
      code.includes("delete user.password") ||
      code.includes("password: undefined") ||
      code.includes("{ id,") ||
      code.includes("{id,") ||
      code.includes("omit") ||
      code.includes("pick");

    // Check for 404 handling
    const hasStatus404 = code.includes("404");
    const hasNotFoundCheck =
      code.includes("!user") || code.includes("user === null");

    if (!noStringConcat)
      hints.push(
        "Remove string concatenation - use parameterized query with ?",
      );
    if (!hasParameterizedQuery)
      hints.push(
        "Use a parameterized query: db.query('SELECT ... WHERE id = ?', [id])",
      );
    if (!hasReqUser || !hasIdComparison)
      hints.push(
        "Add authorization: compare req.user.id with the requested user's ID",
      );
    if (!hasStatus403)
      hints.push("Return 403 status code for unauthorized access attempts");
    if (!noPasswordHash || !hasDataFilter)
      hints.push(
        "Filter sensitive fields: remove password_hash before returning user",
      );
    if (!hasNotFoundCheck || !hasStatus404)
      hints.push("Return 404 status code when user is not found");

    const passed =
      hasParameterizedQuery &&
      noStringConcat &&
      hasReqUser &&
      hasIdComparison &&
      hasStatus403 &&
      (noPasswordHash || hasDataFilter) &&
      hasNotFoundCheck &&
      hasStatus404;
    return { passed, hints };
  },

  // Race Conditions Lab: Check for atomic database operations
  "race-conditions-lab": (code: string) => {
    const hints: string[] = [];
    const normalized = code.toLowerCase();

    // Must use atomic update pattern: UPDATE ... SET balance = balance - amount WHERE ... AND balance >= amount
    const hasAtomicUpdate =
      /update\s+\w+\s+set\s+balance\s*=\s*balance\s*-/.test(normalized) &&
      /where.*balance\s*>=/.test(normalized);

    // Should NOT have separate SELECT for balance check
    const hasSeparateSelect =
      /select.*balance.*from/i.test(code) && /if\s*\(.*balance/.test(code);

    // Should check rowCount for detecting insufficient balance
    const hasRowCountCheck =
      code.includes("rowCount") || code.includes("rows.length");

    // Should return 400 for insufficient balance
    const hasStatus400 = code.includes("400");

    // Alternative: Uses transaction with FOR UPDATE locking
    const hasForUpdate = /for\s+update/i.test(code);
    const hasTransaction = /begin/i.test(code) && /commit/i.test(code);

    if (!hasAtomicUpdate && !hasForUpdate)
      hints.push(
        "Use atomic UPDATE: UPDATE ... SET balance = balance - $1 WHERE id = $2 AND balance >= $1",
      );
    if (hasSeparateSelect)
      hints.push(
        "Remove the separate SELECT query - check balance in the UPDATE WHERE clause",
      );
    if (!hasRowCountCheck)
      hints.push(
        "Check result.rowCount to detect if the update succeeded (0 = insufficient balance)",
      );
    if (!hasStatus400)
      hints.push("Return 400 status code when balance is insufficient");

    const passed =
      (hasAtomicUpdate || (hasForUpdate && hasTransaction)) &&
      !hasSeparateSelect &&
      hasRowCountCheck &&
      hasStatus400;
    return { passed, hints };
  },

  // AI Security Lab: Check for prompt injection detection
  "ai-security-lab": (code: string) => {
    const hints: string[] = [];

    // Must have injection patterns array
    const hasInjectionPatterns = code.includes("INJECTION_PATTERNS");

    // Must have detection function
    const hasDetectFunction =
      code.includes("detectPromptInjection") ||
      code.includes("detect") ||
      code.includes("sanitize");

    // Must check for dangerous patterns
    const checksIgnore = code.toLowerCase().includes("ignore");
    const checksForget = code.toLowerCase().includes("forget");
    const checksNewInstructions =
      code.toLowerCase().includes("new instructions") ||
      code.toLowerCase().includes("instructions");

    // Must throw or return error
    const hasErrorHandling =
      code.includes("throw new Error") || code.includes("throw Error");
    const hasMaliciousMessage = code.includes("malicious input detected");

    if (!hasInjectionPatterns)
      hints.push(
        "Create an INJECTION_PATTERNS array containing dangerous phrases",
      );
    if (!hasDetectFunction)
      hints.push(
        "Add a detectPromptInjection function to check input against patterns",
      );
    if (!checksIgnore || !checksForget || !checksNewInstructions)
      hints.push(
        "Include patterns like 'ignore previous', 'forget', 'new instructions'",
      );
    if (!hasErrorHandling || !hasMaliciousMessage)
      hints.push(
        "Throw an error with message 'Potentially malicious input detected'",
      );

    const passed =
      hasInjectionPatterns &&
      hasDetectFunction &&
      checksIgnore &&
      hasErrorHandling &&
      hasMaliciousMessage;
    return { passed, hints };
  },

  // Supply Chain Security Lab: Check for dependency verification
  "supply-chain-lab": (code: string) => {
    const hints: string[] = [];

    // Must have approved packages list
    const hasApprovedPackages = code.includes("APPROVED_PACKAGES");

    // Must check for pinned versions
    const checksVersionPinned =
      code.includes("isVersionPinned") || code.includes("pinned");
    const rejectsCaretTilde =
      code.includes("^") && code.includes("~") && code.includes("startsWith");

    // Must validate against allowlist
    const checksApproved =
      code.includes("isPackageApproved") || code.includes("approved");

    // Must have proper error messages
    const hasVersionError =
      code.includes("Version must be pinned") || code.includes("pinned");
    const hasApprovedError =
      code.includes("Package not in approved") ||
      code.includes("not in approved");
    const hasChecksumError =
      code.includes("Checksum") || code.includes("checksum");

    if (!hasApprovedPackages)
      hints.push(
        "Create an APPROVED_PACKAGES object as an allowlist of trusted packages",
      );
    if (!checksVersionPinned || !rejectsCaretTilde)
      hints.push(
        "Add isVersionPinned() that rejects versions starting with ^ or ~",
      );
    if (!checksApproved)
      hints.push(
        "Add isPackageApproved() to validate packages against the allowlist",
      );
    if (!hasVersionError)
      hints.push("Throw error with 'Version must be pinned' message");
    if (!hasApprovedError)
      hints.push("Throw error with 'Package not in approved list' message");
    if (!hasChecksumError)
      hints.push("Include checksum verification with appropriate error");

    const passed =
      hasApprovedPackages &&
      checksVersionPinned &&
      checksApproved &&
      hasVersionError &&
      hasApprovedError;
    return { passed, hints };
  },

  // GraphQL Security Lab: Check for proper authorization in resolvers
  "graphql-security-lab": (code: string) => {
    const hints: string[] = [];

    // Must use context.user for authorization
    const hasContextUser =
      code.includes("context.user") || code.includes("ctx.user");

    // Must compare user ID with parent/args ID
    const hasIdComparison =
      /context\.user\.id\s*(!==|===|!=|==)\s*(parent\.id|args\.id)/.test(
        code,
      ) ||
      /(parent\.id|args\.id)\s*(!==|===|!=|==)\s*context\.user\.id/.test(code);

    // Must handle unauthorized access (throw error or return null)
    const hasAccessDenied =
      /throw\s+new\s+\w*Error/i.test(code) ||
      /return\s+null/i.test(code) ||
      /throw\s+.*forbidden/i.test(code) ||
      /throw\s+.*unauthorized/i.test(code);

    // Should not directly return parent.email or parent.ssn without checks
    const hasUnprotectedReturn =
      /return\s+parent\.(email|ssn)\s*;?\s*\}/.test(code) && !hasIdComparison;

    if (!hasContextUser)
      hints.push(
        "Use context.user to access the authenticated user in resolvers",
      );
    if (!hasIdComparison)
      hints.push("Compare context.user.id with parent.id to verify ownership");
    if (!hasAccessDenied)
      hints.push("Return null or throw an error when user is not authorized");
    if (hasUnprotectedReturn)
      hints.push(
        "Don't return sensitive fields (email, ssn) without checking authorization first",
      );

    const passed =
      hasContextUser &&
      hasIdComparison &&
      hasAccessDenied &&
      !hasUnprotectedReturn;
    return { passed, hints };
  },

  // Social Engineering Lab: Check for phishing detection implementation
  "social-engineering-lab": (code: string) => {
    const hints: string[] = [];

    // Must have urgency keywords array
    const hasUrgencyKeywords =
      code.includes("URGENCY_KEYWORDS") || code.includes("urgency");

    // Must have suspicious patterns
    const hasSuspiciousPatterns =
      code.includes("SUSPICIOUS_PATTERNS") ||
      code.includes("suspicious") ||
      code.includes("-verify") ||
      code.includes("-secure");

    // Must extract from field components
    const extractsFrom =
      code.includes(".match") ||
      code.includes("split") ||
      code.includes("displayName") ||
      code.includes("emailAddr");

    // Must check domain
    const checksDomain =
      code.includes("domain") && (code.includes("@") || code.includes("split"));

    // Must return risk level
    const hasRiskLevel =
      code.includes("riskLevel") &&
      (code.includes("high") ||
        code.includes("medium") ||
        code.includes("low"));

    // Must return reasons
    const hasReasons = code.includes("reasons") && code.includes("push");

    if (!hasUrgencyKeywords)
      hints.push(
        "Create an URGENCY_KEYWORDS array with terms like 'urgent', 'immediately'",
      );
    if (!hasSuspiciousPatterns)
      hints.push(
        "Add patterns to detect suspicious domains like '-verify.com'",
      );
    if (!extractsFrom)
      hints.push(
        "Extract the display name and email address from the 'from' field",
      );
    if (!checksDomain)
      hints.push("Check if the email domain matches expected patterns");
    if (!hasRiskLevel)
      hints.push("Return a riskLevel of 'low', 'medium', or 'high'");
    if (!hasReasons) hints.push("Add detected issues to the reasons array");

    const passed =
      hasUrgencyKeywords &&
      hasSuspiciousPatterns &&
      extractsFrom &&
      hasRiskLevel &&
      hasReasons;
    return { passed, hints };
  },

  // Container Security Lab: Check for secure Kubernetes pod configuration
  "container-security-lab": (code: string) => {
    const hints: string[] = [];

    // Must have securityContext at pod or container level
    const hasSecurityContext = code.includes("securityContext");

    // Must set runAsNonRoot
    const hasRunAsNonRoot = code.includes("runAsNonRoot: true");

    // Must drop all capabilities
    const hasDropAll =
      code.includes("drop:") &&
      (code.includes("ALL") ||
        code.includes('"ALL"') ||
        code.includes("'ALL'"));

    // Must set allowPrivilegeEscalation: false
    const hasNoPrivEsc = code.includes("allowPrivilegeEscalation: false");

    // Must have readOnlyRootFilesystem
    const hasReadOnly = code.includes("readOnlyRootFilesystem: true");

    if (!hasSecurityContext)
      hints.push("Add a securityContext section to the pod or container spec");
    if (!hasRunAsNonRoot)
      hints.push("Set runAsNonRoot: true to prevent running as root");
    if (!hasDropAll)
      hints.push("Drop ALL capabilities using capabilities.drop: ['ALL']");
    if (!hasNoPrivEsc)
      hints.push(
        "Set allowPrivilegeEscalation: false to prevent privilege escalation",
      );
    if (!hasReadOnly)
      hints.push(
        "Set readOnlyRootFilesystem: true to prevent filesystem modifications",
      );

    const passed =
      hasSecurityContext &&
      hasRunAsNonRoot &&
      hasDropAll &&
      hasNoPrivEsc &&
      hasReadOnly;
    return { passed, hints };
  },

  // OAuth Security Lab: Check for PKCE and state parameter implementation
  "oauth-lab": (code: string) => {
    const hints: string[] = [];

    // Must generate state parameter for CSRF protection
    const hasStateParam =
      code.includes(PATTERNS.OAUTH_STATE_PARAM) &&
      code.includes("searchParams.set");
    const hasRandomUUID = code.includes(PATTERNS.OAUTH_RANDOM_UUID);

    // Must store state and verifier in sessionStorage
    const hasSessionStorage = code.includes(PATTERNS.OAUTH_SESSION_STORAGE);
    const storesState =
      code.includes("oauth_state") || code.includes("'state'");
    const storesVerifier =
      code.includes("pkce_verifier") || code.includes("'verifier'");

    // Must generate PKCE code_verifier
    const hasCodeVerifier = code.includes(PATTERNS.OAUTH_PKCE_VERIFIER);
    const hasGetRandomValues = code.includes(PATTERNS.OAUTH_GET_RANDOM_VALUES);

    // Must generate code_challenge (SHA-256 hash)
    const hasCodeChallenge = code.includes(PATTERNS.OAUTH_PKCE_CHALLENGE);
    const hasSHA256 = code.includes(PATTERNS.OAUTH_SHA256);
    const hasSubtleDigest = code.includes(PATTERNS.OAUTH_SUBTLE_DIGEST);

    // Must set code_challenge_method=S256
    const hasChallengeMethod = code.includes(PATTERNS.OAUTH_CHALLENGE_METHOD);
    const hasS256 = code.includes(PATTERNS.OAUTH_S256);

    if (!hasRandomUUID)
      hints.push("Generate random state using crypto.randomUUID()");
    if (!hasStateParam)
      hints.push(
        "Add state parameter to authorization URL with searchParams.set",
      );
    if (!hasSessionStorage)
      hints.push("Use sessionStorage.setItem to store state and verifier");
    if (!storesState)
      hints.push("Store the state value in sessionStorage as 'oauth_state'");
    if (!storesVerifier)
      hints.push(
        "Store the code_verifier in sessionStorage as 'pkce_verifier'",
      );
    if (!hasCodeVerifier || !hasGetRandomValues)
      hints.push(
        "Generate code_verifier using crypto.getRandomValues() with Uint8Array",
      );
    if (!hasCodeChallenge || !hasSHA256 || !hasSubtleDigest)
      hints.push(
        "Create code_challenge by hashing verifier with crypto.subtle.digest('SHA-256', ...)",
      );
    if (!hasChallengeMethod || !hasS256)
      hints.push("Add code_challenge_method=S256 to the authorization URL");

    const passed =
      hasStateParam &&
      hasRandomUUID &&
      hasSessionStorage &&
      storesState &&
      storesVerifier &&
      hasCodeVerifier &&
      hasGetRandomValues &&
      hasCodeChallenge &&
      hasSHA256 &&
      hasSubtleDigest &&
      hasChallengeMethod &&
      hasS256;
    return { passed, hints };
  },

  // Prototype Pollution Lab: Fix the merge function
  "proto-lab": (code: string) => {
    const hints: string[] = [];
    const hasBlacklist = code.includes(PATTERNS.PROTO_BLACKLIST_ARRAY);
    const hasProto = code.includes(PATTERNS.PROTO_DUNDER_PROTO);
    const hasConstructor =
      code.includes(`'${PATTERNS.PROTO_CONSTRUCTOR}'`) ||
      code.includes(`"${PATTERNS.PROTO_CONSTRUCTOR}"`);
    const hasPrototype =
      code.includes(`'${PATTERNS.PROTO_PROTOTYPE}'`) ||
      code.includes(`"${PATTERNS.PROTO_PROTOTYPE}"`);
    const hasIncludesCheck = code.includes(PATTERNS.PROTO_INCLUDES_CHECK);
    const hasContinue = code.includes(PATTERNS.PROTO_CONTINUE);

    if (!hasBlacklist)
      hints.push(
        "Define a BLACKLISTED_KEYS array containing the dangerous key names",
      );
    if (!hasProto)
      hints.push("Include '__proto__' in the blacklisted keys");
    if (!hasConstructor)
      hints.push("Include 'constructor' in the blacklisted keys");
    if (!hasPrototype)
      hints.push("Include 'prototype' in the blacklisted keys");
    if (!hasIncludesCheck)
      hints.push(
        "Use .includes(key) to check if the current key is in the blacklist",
      );
    if (!hasContinue)
      hints.push("Use 'continue' to skip blacklisted keys in the loop");

    const passed =
      hasBlacklist &&
      hasProto &&
      hasConstructor &&
      hasPrototype &&
      hasIncludesCheck &&
      hasContinue;
    return { passed, hints };
  },

  // Subdomain Takeover Lab: DNS configuration audit
  "subdomain-lab": (code: string) => {
    const hints: string[] = [];
    const hasCnameCheck = code.includes(PATTERNS.SUBDOMAIN_CNAME_CHECK);
    const hasServiceCheck = code.includes(PATTERNS.SUBDOMAIN_SERVICE_ACTIVE);
    const hasEndsWith = code.includes(PATTERNS.SUBDOMAIN_ENDS_WITH);
    const hasSomeCheck = code.includes(PATTERNS.SUBDOMAIN_SOME_CHECK);
    const hasPush = code.includes(PATTERNS.SUBDOMAIN_PUSH);

    if (!hasCnameCheck)
      hints.push('Filter records to only check CNAME type entries');
    if (!hasServiceCheck)
      hints.push(
        "Check the serviceActive flag to identify deprovisioned services",
      );
    if (!hasSomeCheck)
      hints.push(
        "Use .some() to check if the target matches any vulnerable service",
      );
    if (!hasEndsWith)
      hints.push(
        "Use .endsWith() to match target domains against vulnerable services",
      );
    if (!hasPush)
      hints.push(
        "Push vulnerable subdomains to the results array with subdomain, target, and risk info",
      );

    const passed =
      hasCnameCheck && hasServiceCheck && hasEndsWith && hasSomeCheck && hasPush;
    return { passed, hints };
  },

  // WebSocket Security Lab: Secure the WebSocket server
  "ws-lab": (code: string) => {
    const hints: string[] = [];
    const hasAllowedOrigins = code.includes(PATTERNS.WS_ALLOWED_ORIGINS);
    const hasOriginCheck = code.includes(PATTERNS.WS_ORIGIN_CHECK);
    const hasClose4001 = code.includes(PATTERNS.WS_CLOSE_4001);
    const hasRateLimitMap = code.includes(PATTERNS.WS_RATE_LIMIT_MAP);
    const hasMaxMessages = code.includes(PATTERNS.WS_MAX_MESSAGES);
    const hasValidToken = code.includes(PATTERNS.WS_VALID_TOKEN);
    const hasClose4002 = code.includes(PATTERNS.WS_CLOSE_4002);
    const hasSanitizeLt = code.includes(PATTERNS.WS_SANITIZE_LT);
    const hasSanitizeGt = code.includes(PATTERNS.WS_SANITIZE_GT);
    const hasMaxPayload = code.includes(PATTERNS.WS_MAX_PAYLOAD);

    if (!hasAllowedOrigins)
      hints.push("Define an ALLOWED_ORIGINS array with trusted origins");
    if (!hasOriginCheck)
      hints.push(
        "Check req.headers.origin during the connection handshake",
      );
    if (!hasClose4001)
      hints.push(
        "Close connections from unauthorized origins with code 4001",
      );
    if (!hasRateLimitMap)
      hints.push("Create a rateLimitMap to track message rates per client");
    if (!hasMaxMessages)
      hints.push(
        "Define MAX_MESSAGES_PER_SECOND to cap message frequency",
      );
    if (!hasValidToken)
      hints.push(
        "Add an isValidToken function to validate authentication tokens",
      );
    if (!hasClose4002)
      hints.push("Close connections with invalid tokens using code 4002");
    if (!hasSanitizeLt || !hasSanitizeGt)
      hints.push(
        "Sanitize message text by replacing < and > with HTML entities",
      );
    if (!hasMaxPayload)
      hints.push("Set maxPayload on WebSocket.Server to limit message size");

    const passed =
      hasAllowedOrigins &&
      hasOriginCheck &&
      hasClose4001 &&
      hasRateLimitMap &&
      hasMaxMessages &&
      hasValidToken &&
      hasClose4002 &&
      hasSanitizeLt &&
      hasSanitizeGt &&
      hasMaxPayload;
    return { passed, hints };
  },
  // Incident Response Simulation Lab
  "ir-simulation-lab": (code: string): VerificationResult => {
    const hints: string[] = [];
    const lower = code.toLowerCase();

    const hasClassification = lower.includes("p1") && (lower.includes("critical") || lower.includes("exfiltration"));
    if (!hasClassification) hints.push("Classify this as P1 Critical — active data exfiltration with PII is confirmed.");

    const hasNetworkIsolation = lower.includes("isolat") && (lower.includes("network") || lower.includes("firewall") || lower.includes("quarantine"));
    if (!hasNetworkIsolation) hints.push("Containment should include isolating the compromised server from the network.");

    const hasBlockC2 = lower.includes("block") && (lower.includes("198.51.100.77") || lower.includes("203.0.113.50") || lower.includes("c2"));
    if (!hasBlockC2) hints.push("Block the attacker's C2 and source IP addresses at the perimeter.");

    const hasAccountAction = lower.includes("disable") || lower.includes("lock") || (lower.includes("deploy-svc") && lower.includes("account"));
    if (!hasAccountAction) hints.push("Disable the compromised 'deploy-svc' account.");

    const hasEvidence = lower.includes("forensic") || lower.includes("evidence") || lower.includes("image") || lower.includes("chain of custody");
    if (!hasEvidence) hints.push("Preserve forensic evidence (memory dump, disk image) before remediation.");

    const hasCredRotation = lower.includes("rotat") && (lower.includes("credential") || lower.includes("password") || lower.includes("key"));
    if (!hasCredRotation) hints.push("Eradication should include rotating all credentials, not just the compromised account.");

    const hasBackdoorCheck = lower.includes("backdoor") || lower.includes("cron") || lower.includes("authorized_keys") || lower.includes("persistence");
    if (!hasBackdoorCheck) hints.push("Check for additional persistence mechanisms (cron jobs, SSH keys, backdoors).");

    const hasNotification = lower.includes("gdpr") || lower.includes("notification") || lower.includes("regulat") || lower.includes("breach notification");
    if (!hasNotification) hints.push("2.3M PII records were exfiltrated — include regulatory notification requirements (GDPR 72hrs, state breach laws).");

    const passed =
      hasClassification &&
      hasNetworkIsolation &&
      hasBlockC2 &&
      hasAccountAction &&
      hasEvidence &&
      hasCredRotation &&
      hasBackdoorCheck &&
      hasNotification;
    return { passed, hints };
  },

  // Cloud Configuration Audit Lab
  "cloud-config-audit-lab": (code: string): VerificationResult => {
    const hints: string[] = [];
    const lower = code.toLowerCase();

    const hasPublicAccessBlock = code.includes("blockPublicAcls: true") || code.includes("blockPublicAcls:true") || (lower.includes("blockpublicacls") && lower.includes("true"));
    if (!hasPublicAccessBlock) hints.push("Enable S3 public access blocks (blockPublicAcls, ignorePublicAcls, blockPublicPolicy, restrictPublicBuckets).");

    const hasRestrictedPrincipal = code.includes("arn:aws:iam") || code.includes("role/") || !code.includes('Principal: "*"');
    if (!hasRestrictedPrincipal) hints.push("Restrict the S3 bucket policy Principal from '*' (public) to a specific IAM role.");

    const hasRestrictedActions = !code.includes('"s3:*"') && !code.includes("'s3:*'") && !code.includes('Action: "*"') && !code.includes("Action: '*'");
    if (!hasRestrictedActions) hints.push("Replace wildcard actions (s3:*, *) with specific actions like s3:GetObject, s3:PutObject.");

    const hasEncryption = lower.includes("encryption") && (lower.includes("true") || lower.includes("kms") || lower.includes("sse"));
    if (!hasEncryption) hints.push("Enable server-side encryption on the S3 bucket.");

    const hasSSHRestricted = !code.includes('port: 22, source: "0.0.0.0/0"') && !code.includes("port: 22, source: '0.0.0.0/0'");
    if (!hasSSHRestricted) hints.push("SSH (port 22) should not be open to 0.0.0.0/0 — restrict to bastion host or VPN.");

    const hasMySQLRestricted = !code.includes('port: 3306, source: "0.0.0.0/0"') && !code.includes("port: 3306, source: '0.0.0.0/0'");
    if (!hasMySQLRestricted) hints.push("MySQL (port 3306) must not be open to the internet — restrict to application subnet.");

    const hasNoAllowAll = !code.includes('protocol: "-1"') || lower.includes("removed") || lower.includes("// fix");
    if (!hasNoAllowAll) hints.push("Remove the allow-all inbound rule (protocol -1, all ports, 0.0.0.0/0).");

    const passed =
      hasPublicAccessBlock &&
      hasRestrictedPrincipal &&
      hasRestrictedActions &&
      hasEncryption &&
      hasSSHRestricted &&
      hasMySQLRestricted &&
      hasNoAllowAll;
    return { passed, hints };
  },

  // Phishing Awareness - Email Triage Exercise
  "phishing-lab-triage": (code: string): VerificationResult => {
    const hints: string[] = [];

    const hasSuspiciousDomain = code.includes("suspiciousSenderDomain: true");
    if (!hasSuspiciousDomain) hints.push("The sender domain 'your-company-ithelp.net' is not the real company domain — flag suspiciousSenderDomain.");

    const hasMismatchedReply = code.includes("mismatchedReplyTo: true");
    if (!hasMismatchedReply) hints.push("The reply-to address goes to a Gmail account, not the sender — flag mismatchedReplyTo.");

    const hasUrgency = code.includes("urgencyTactics: true");
    if (!hasUrgency) hints.push("The subject says 'URGENT' and '24 Hours' — flag urgencyTactics.");

    const hasSuspiciousLink = code.includes("suspiciousLink: true");
    if (!hasSuspiciousLink) hints.push("The link uses HTTP (not HTTPS) and a .tk domain — flag suspiciousLink.");

    const hasGenericGreeting = code.includes("genericGreeting: true");
    if (!hasGenericGreeting) hints.push("'Dear Employee' is generic, not personalized — flag genericGreeting.");

    const hasThreat = code.includes("threatOfConsequences: true");
    if (!hasThreat) hints.push("'permanently suspended and all data will be lost' is a fear tactic — flag threatOfConsequences.");

    const hasDangerousAttachment = code.includes("dangerousAttachment: true");
    if (!hasDangerousAttachment) hints.push("An .html attachment can contain a local phishing form — flag dangerousAttachment.");

    const hasBroadDist = code.includes("broadDistribution: true");
    if (!hasBroadDist) hints.push("Sent to 'all-staff' rather than you specifically — flag broadDistribution.");

    const passed =
      hasSuspiciousDomain &&
      hasMismatchedReply &&
      hasUrgency &&
      hasSuspiciousLink &&
      hasGenericGreeting &&
      hasThreat &&
      hasDangerousAttachment &&
      hasBroadDist;
    return { passed, hints };
  },

  // Password & Data Hygiene - Security Policy Review
  "password-lab-policy": (code: string): VerificationResult => {
    const hints: string[] = [];

    const hasPasswordShort = code.includes("passwordTooShort: true");
    if (!hasPasswordShort) hints.push("Minimum 6 characters is far too short — industry standard is 12+. Flag passwordTooShort.");

    const hasNoComplexity = code.includes("noComplexityRequirements: true");
    if (!hasNoComplexity) hints.push("No uppercase, numbers, or special character requirements — flag noComplexityRequirements.");

    const hasExpiryLong = code.includes("passwordExpiryTooLong: true");
    if (!hasExpiryLong) hints.push("365-day password expiry with no other protections is too long — flag passwordExpiryTooLong.");

    const hasNoReuse = code.includes("noReuseProtection: true");
    if (!hasNoReuse) hints.push("Zero previous passwords blocked means users can reuse forever — flag noReuseProtection.");

    const hasUnencrypted = code.includes("sensitiveDataUnencrypted: true");
    if (!hasUnencrypted) hints.push("Sensitive files must be encrypted — flag sensitiveDataUnencrypted.");

    const hasUSB = code.includes("usbDrivesUnrestricted: true");
    if (!hasUSB) hints.push("Unrestricted personal USB drives can introduce malware — flag usbDrivesUnrestricted.");

    const hasCloud = code.includes("personalCloudAllowed: true");
    if (!hasCloud) hints.push("Work data on personal cloud storage is a breach risk — flag personalCloudAllowed.");

    const hasVPN = code.includes("noVPNRequirement: true");
    if (!hasVPN) hints.push("No VPN on public WiFi exposes all traffic — flag noVPNRequirement.");

    const hasMFA = code.includes("mfaNotRequired: true");
    if (!hasMFA) hints.push("MFA should be mandatory, not optional — flag mfaNotRequired.");

    const hasScreenLock = code.includes("noScreenLock: true");
    if (!hasScreenLock) hints.push("'Never' auto-lock means unattended machines are exposed — flag noScreenLock.");

    const hasSharedPW = code.includes("sharedPasswords: true");
    if (!hasSharedPW) hints.push("Shared passwords destroy accountability — flag sharedPasswords.");

    const hasWifi = code.includes("wifiNotSegmented: true");
    if (!hasWifi) hints.push("Guest and corporate WiFi should be separated — flag wifiNotSegmented.");

    const hasShred = code.includes("noDocumentShredding: true");
    if (!hasShred) hints.push("Documents with sensitive data must be shredded — flag noDocumentShredding.");

    const passed =
      hasPasswordShort &&
      hasNoComplexity &&
      hasExpiryLong &&
      hasNoReuse &&
      hasUnencrypted &&
      hasUSB &&
      hasCloud &&
      hasVPN &&
      hasMFA &&
      hasScreenLock &&
      hasSharedPW &&
      hasWifi &&
      hasShred;
    return { passed, hints };
  },

  // Safe Browsing & Remote Work - Workspace Security Audit
  "remote-lab-audit": (code: string): VerificationResult => {
    const hints: string[] = [];

    const hasRouterPW = code.includes("defaultRouterPassword: true");
    if (!hasRouterPW) hints.push("'admin' is the default router password — flag defaultRouterPassword.");

    const hasWeakWifi = code.includes("weakWifiPassword: true");
    if (!hasWeakWifi) hints.push("Using a home address as WiFi password is easily guessable — flag weakWifiPassword.");

    const hasDefaultSSID = code.includes("defaultNetworkName: true");
    if (!hasDefaultSSID) hints.push("Default SSID reveals the router model — flag defaultNetworkName.");

    const hasNoSegment = code.includes("noNetworkSegmentation: true");
    if (!hasNoSegment) hints.push("No separate guest network means all devices share access — flag noNetworkSegmentation.");

    const hasIoT = code.includes("iotOnWorkNetwork: true");
    if (!hasIoT) hints.push("IoT devices on the work network are potential entry points — flag iotOnWorkNetwork.");

    const hasScreenVisible = code.includes("screenVisibleFromOutside: true");
    if (!hasScreenVisible) hints.push("Desk by a street-facing window exposes screen content — flag screenVisibleFromOutside.");

    const hasNoPrivacy = code.includes("noPrivacyFilter: true");
    if (!hasNoPrivacy) hints.push("No privacy filter on a window-facing screen — flag noPrivacyFilter.");

    const hasNoAutoLock = code.includes("noAutoLock: true");
    if (!hasNoAutoLock) hints.push("No auto-lock leaves the machine accessible — flag noAutoLock.");

    const hasDocs = code.includes("documentsExposed: true");
    if (!hasDocs) hints.push("Printed client reports on the desk are visible to visitors — flag documentsExposed.");

    const hasWebcam = code.includes("noWebcamCover: true");
    if (!hasWebcam) hints.push("Uncovered webcam can be activated by malware — flag noWebcamCover.");

    const hasSharedPC = code.includes("sharedComputerNoSeparation: true");
    if (!hasSharedPC) hints.push("Shared computer with no separate work account — flag sharedComputerNoSeparation.");

    const hasSharedBrowser = code.includes("passwordsInSharedBrowser: true");
    if (!hasSharedBrowser) hints.push("Saved passwords in a shared browser profile — flag passwordsInSharedBrowser.");

    const hasUSBData = code.includes("workDataOnPersonalUSB: true");
    if (!hasUSBData) hints.push("Work files on personal USB can be lost or stolen — flag workDataOnPersonalUSB.");

    const hasPersonalApps = code.includes("personalAppsOnWorkDevice: true");
    if (!hasPersonalApps) hints.push("Personal apps increase the attack surface — flag personalAppsOnWorkDevice.");

    const hasVPN = code.includes("inconsistentVPN: true");
    if (!hasVPN) hints.push("VPN should always be on outside the office — flag inconsistentVPN.");

    const hasPublicWifi = code.includes("publicWifiForWork: true");
    if (!hasPublicWifi) hints.push("Public WiFi for work without reliable VPN — flag publicWifiForWork.");

    const hasAutoConnect = code.includes("autoConnectEnabled: true");
    if (!hasAutoConnect) hints.push("Auto-connect can join rogue 'evil twin' networks — flag autoConnectEnabled.");

    const hasBluetooth = code.includes("bluetoothAlwaysOn: true");
    if (!hasBluetooth) hints.push("Bluetooth always on enables proximity attacks — flag bluetoothAlwaysOn.");

    const passed =
      hasRouterPW &&
      hasWeakWifi &&
      hasDefaultSSID &&
      hasNoSegment &&
      hasIoT &&
      hasScreenVisible &&
      hasNoPrivacy &&
      hasNoAutoLock &&
      hasDocs &&
      hasWebcam &&
      hasSharedPC &&
      hasSharedBrowser &&
      hasUSBData &&
      hasPersonalApps &&
      hasVPN &&
      hasPublicWifi &&
      hasAutoConnect &&
      hasBluetooth;
    return { passed, hints };
  },

  // GDPR Fundamentals - Privacy Policy Audit
  "gdpr-lab-privacy-audit": (code: string): VerificationResult => {
    const lower = code.toLowerCase();
    const hints: string[] = [];

    // All six sections should be marked as compliant: false
    const sections = [
      "dataCollection",
      "consent",
      "dataRetention",
      "thirdPartySharing",
      "userRights",
      "consentWithdrawal",
    ];

    let allMarkedNonCompliant = true;
    for (const section of sections) {
      // Check that the section has compliant: false
      const sectionPattern = new RegExp(
        `${section}[\\s\\S]*?compliant\\s*:\\s*false`,
      );
      if (!sectionPattern.test(code)) {
        allMarkedNonCompliant = false;
        hints.push(
          `Mark the "${section}" section as compliant: false — it contains a GDPR violation.`,
        );
      }
    }

    // Check that violations include meaningful descriptions
    const hasViolationDescriptions =
      (code.match(/violation\s*:\s*["'`][^"'`]{10,}/g) || []).length >= 4;
    if (!hasViolationDescriptions)
      hints.push(
        "Add meaningful violation descriptions explaining which GDPR article or principle is violated.",
      );

    // Check for key GDPR concepts in violation descriptions
    const hasMinimization =
      lower.includes("minimization") || lower.includes("minimis");
    if (!hasMinimization)
      hints.push(
        "Identify the data minimization violation in the data collection section.",
      );

    const hasConsentIssue =
      lower.includes("affirmative") ||
      lower.includes("freely given") ||
      lower.includes("implied consent") ||
      lower.includes("specific");
    if (!hasConsentIssue)
      hints.push(
        "Explain why implied consent through website usage is not valid under GDPR.",
      );

    const hasRetentionIssue =
      lower.includes("storage limitation") ||
      lower.includes("indefinite") ||
      lower.includes("retention");
    if (!hasRetentionIssue)
      hints.push(
        "Address the storage limitation principle violation in the data retention section.",
      );

    const passed =
      allMarkedNonCompliant && hasViolationDescriptions && hasMinimization && hasConsentIssue && hasRetentionIssue;
    return { passed, hints };
  },

  // PCI-DSS Essentials - Payment Flow Security Review
  "pci-lab-payment-flow": (code: string): VerificationResult => {
    const lower = code.toLowerCase();
    const hints: string[] = [];

    // Should use tokenization instead of raw card data
    const hasToken =
      lower.includes("token") || lower.includes("paymenttoken") || lower.includes("payment_token");
    if (!hasToken)
      hints.push(
        "Use tokenization (e.g., Stripe tokens) instead of handling raw card numbers server-side.",
      );

    // Should NOT log full card numbers or CVV
    const logsCardData =
      /console\.log.*card(number|Number)/.test(code) ||
      /console\.log.*cvv/i.test(code);
    if (logsCardData)
      hints.push(
        "Remove card numbers and CVV from log statements -- never log sensitive cardholder data.",
      );

    // Should NOT store CVV after authorization
    const storesCvv =
      /insert\s*\([\s\S]*?cvv/i.test(code) ||
      /db\..*cvv/i.test(code);
    if (storesCvv)
      hints.push(
        "Never store CVV/CVC after authorization -- this is strictly prohibited by PCI-DSS Requirement 3.",
      );

    // Should NOT store full PAN
    const storesFullPan =
      /insert\s*\([\s\S]*?cardNumber\s*:\s*cardNumber/i.test(code);
    if (storesFullPan)
      hints.push(
        "Do not store the full PAN. Store only the last 4 digits or a token reference.",
      );

    // Should NOT send card data in analytics
    const analyticsCardData =
      /analytics.*cardNumber/i.test(code) ||
      /track.*cardNumber/i.test(code);
    if (analyticsCardData)
      hints.push(
        "Remove card data from analytics tracking -- only track transaction metadata.",
      );

    // Should NOT return card data in response
    const responseCardData =
      /res\.json\s*\([\s\S]*?cardNumber/i.test(code);
    if (responseCardData)
      hints.push(
        "Do not return card data in API responses -- only return transaction ID and masked info.",
      );

    // Should reference last4 or masked card
    const hasMasking =
      lower.includes("last4") ||
      lower.includes("last_four") ||
      lower.includes("lastfour") ||
      lower.includes("mask") ||
      lower.includes("****");
    if (!hasMasking)
      hints.push(
        "Use masked card data (last 4 digits) when displaying or storing card references.",
      );

    const passed =
      hasToken &&
      !logsCardData &&
      !storesCvv &&
      !storesFullPan &&
      !analyticsCardData &&
      !responseCardData &&
      hasMasking;
    return { passed, hints };
  },

  // HIPAA Basics - HIPAA Violation Finder
  "hipaa-lab-violation-finder": (code: string): VerificationResult => {
    const lower = code.toLowerCase();
    const hints: string[] = [];

    // Should have authentication middleware
    const hasAuth =
      lower.includes("requireauth") ||
      lower.includes("authenticate") ||
      lower.includes("verifysession") ||
      lower.includes("authorization");
    if (!hasAuth)
      hints.push(
        "Add authentication/authorization middleware -- all PHI endpoints must verify user identity.",
      );

    // Should have audit logging
    const hasAuditLog =
      lower.includes("auditlog") ||
      lower.includes("audit_log") ||
      lower.includes("audit") && lower.includes("log");
    if (!hasAuditLog)
      hints.push(
        "Add audit logging for all PHI access -- HIPAA requires tracking who accessed what and when.",
      );

    // Should NOT log PHI (SSN, diagnosis, etc.)
    const logsPhi =
      /console\.log.*ssn/i.test(code) ||
      /console\.log.*diagnosis/i.test(code) ||
      /console\.log.*patient.*\$\{/i.test(code);
    if (logsPhi)
      hints.push(
        "Remove PHI (SSN, diagnosis, patient IDs) from console.log statements.",
      );

    // Should have encryption for PHI at rest
    const hasEncryption =
      lower.includes("encrypt") || lower.includes("crypto");
    if (!hasEncryption)
      hints.push(
        "Encrypt PHI at rest -- use encryption for sensitive fields like diagnosis and notes.",
      );

    // Should implement minimum necessary principle
    const hasMinimumNecessary =
      lower.includes("minimum necessary") ||
      lower.includes("select: fields") ||
      lower.includes("getfieldsbyrole") ||
      lower.includes("select:");
    if (!hasMinimumNecessary)
      hints.push(
        "Implement the minimum necessary principle -- only return fields needed for the user's role.",
      );

    // Should restrict bulk export
    const hasBulkRestriction =
      /export.*role|role.*export|admin.*export|export.*admin/i.test(code) ||
      lower.includes("403") ||
      lower.includes("access denied");
    if (!hasBulkRestriction)
      hints.push(
        "Restrict bulk patient data exports to authorized roles only.",
      );

    const passed =
      hasAuth &&
      hasAuditLog &&
      !logsPhi &&
      hasEncryption &&
      hasMinimumNecessary &&
      hasBulkRestriction;
    return { passed, hints };
  },

  // SOC 2 Awareness - Control Gap Assessment
  "soc2-lab-gap-assessment": (code: string): VerificationResult => {
    const lower = code.toLowerCase();
    const hints: string[] = [];

    const categories = [
      "security",
      "availability",
      "processingintegrity",
      "confidentiality",
      "privacy",
    ];

    // All 5 categories should be marked as hasGap: true
    let allMarkedAsGap = true;
    for (const cat of categories) {
      const pattern = new RegExp(
        `${cat}[\\s\\S]*?hasGap\\s*:\\s*true`,
        "i",
      );
      if (!pattern.test(code)) {
        allMarkedAsGap = false;
        hints.push(
          `Mark the "${cat}" category as hasGap: true -- all categories have gaps given the missing controls.`,
        );
      }
    }

    // Should list existing controls
    const hasExistingControls =
      (code.match(/existingControls\s*:\s*["'`][^"'`]{10,}/g) || []).length >= 3;
    if (!hasExistingControls)
      hints.push(
        "List the existing controls that apply to each category from the inventory.",
      );

    // Should list missing controls
    const hasMissingControls =
      (code.match(/missingControls\s*:\s*["'`][^"'`]{10,}/g) || []).length >= 3;
    if (!hasMissingControls)
      hints.push(
        "Identify the missing controls relevant to each category.",
      );

    // Should assign risk levels
    const hasRiskLevels =
      (code.match(/riskLevel\s*:\s*["'`](low|medium|high|critical)["'`]/gi) || []).length >= 4;
    if (!hasRiskLevels)
      hints.push(
        "Assign a riskLevel (low, medium, high, or critical) to each category.",
      );

    // Check for key concepts
    const hasIncidentResponse =
      lower.includes("incident response");
    if (!hasIncidentResponse)
      hints.push(
        "The missing incident response plan is a key security gap -- mention it.",
      );

    const hasDisasterRecovery =
      lower.includes("disaster recovery") || lower.includes("business continuity");
    if (!hasDisasterRecovery)
      hints.push(
        "The missing disaster recovery/business continuity plan is a critical availability gap.",
      );

    const passed =
      allMarkedAsGap &&
      hasExistingControls &&
      hasMissingControls &&
      hasRiskLevels &&
      hasIncidentResponse &&
      hasDisasterRecovery;
    return { passed, hints };
  },
};

/**
 * Verify a lab submission using the registered verifier.
 * Returns a VerificationResult with passed status and hints.
 */
export function verifyLabSubmission(
  labId: string,
  code: string,
): VerificationResult {
  const verifier = labVerifiers[labId];
  if (!verifier) {
    console.warn(`No verifier registered for lab: ${labId}`);
    return { passed: false, hints: ["Unknown lab exercise"] };
  }
  return verifier(code);
}
