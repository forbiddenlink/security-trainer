import type { Module } from "../../types";

import { owaspIntro } from "./owasp-intro";
import { sqlInjection } from "./sql-injection";
import { xssBasics } from "./xss-basics";
import { idorBasics } from "./idor-basics";
import { brokenAuth } from "./broken-auth";
import { csrfAttacks } from "./csrf-attacks";
import { securityMisconfig } from "./security-misconfig";
import { ssrfAttacks } from "./ssrf-attacks";
import { xxeAttacks } from "./xxe-attacks";
import { insecureDeserialization } from "./insecure-deserialization";
import { sensitiveDataExposure } from "./sensitive-data-exposure";
import { clickjacking } from "./clickjacking";
import { jwtVulnerabilities } from "./jwt-vulnerabilities";
import { businessLogic } from "./business-logic";
import { vulnerableComponentsModule } from "./vulnerable-components";
import { loggingMonitoringModule } from "./logging-monitoring";
import { commandInjection } from "./command-injection";
import { pathTraversal } from "./path-traversal";
import { fileUpload } from "./file-upload";
import { corsMisconfig } from "./cors-misconfig";
import { sessionManagement } from "./session-management";
import { apiSecurity } from "./api-security";
import { raceConditions } from "./race-conditions";
import { graphqlSecurity } from "./graphql-security";
import { aiSecurity } from "./ai-security";
import { supplyChainSecurity } from "./supply-chain-security";
import { containerSecurity } from "./container-security";
import { socialEngineering } from "./social-engineering";

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
  clickjacking,
  jwtVulnerabilities,
  businessLogic,
  vulnerableComponentsModule,
  loggingMonitoringModule,
  commandInjection,
  pathTraversal,
  fileUpload,
  corsMisconfig,
  sessionManagement,
  apiSecurity,
  raceConditions,
  graphqlSecurity,
  aiSecurity,
  supplyChainSecurity,
  containerSecurity,
  socialEngineering,
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
  clickjacking,
  jwtVulnerabilities,
  businessLogic,
  vulnerableComponentsModule,
  loggingMonitoringModule,
  commandInjection,
  pathTraversal,
  fileUpload,
  corsMisconfig,
  sessionManagement,
  apiSecurity,
  raceConditions,
  graphqlSecurity,
  aiSecurity,
  supplyChainSecurity,
  containerSecurity,
  socialEngineering,
};
