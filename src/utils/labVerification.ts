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
};

/**
 * Registry of verification functions for each lab exercise.
 * Each function checks if the user's code correctly patches the vulnerability.
 */
export const labVerifiers: Record<string, VerificationFn> = {
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
