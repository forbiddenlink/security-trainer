import type { Module } from '../../types';

import { owaspIntro } from './owasp-intro';
import { sqlInjection } from './sql-injection';
import { xssBasics } from './xss-basics';
import { idorBasics } from './idor-basics';
import { brokenAuth } from './broken-auth';
import { csrfAttacks } from './csrf-attacks';
import { securityMisconfig } from './security-misconfig';
import { ssrfAttacks } from './ssrf-attacks';
import { xxeAttacks } from './xxe-attacks';
import { insecureDeserialization } from './insecure-deserialization';
import { sensitiveDataExposure } from './sensitive-data-exposure';

export const MODULES: Module[] = [
    owaspIntro,
    sqlInjection,
    xssBasics,
    idorBasics,
    brokenAuth,
    csrfAttacks,
    securityMisconfig,
    ssrfAttacks,
    xxeAttacks,
    insecureDeserialization,
    sensitiveDataExposure,
];

// Re-export individual modules for direct imports
export {
    owaspIntro,
    sqlInjection,
    xssBasics,
    idorBasics,
    brokenAuth,
    csrfAttacks,
    securityMisconfig,
    ssrfAttacks,
    xxeAttacks,
    insecureDeserialization,
    sensitiveDataExposure,
};
