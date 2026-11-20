import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
// Self-hosted fonts: no render-blocking third-party stylesheet.
import "@fontsource-variable/archivo/wdth.css";
import "@fontsource/ibm-plex-sans/latin-400.css";
import "@fontsource/ibm-plex-sans/latin-500.css";
import "@fontsource/ibm-plex-sans/latin-600.css";
import "@fontsource/ibm-plex-sans/latin-700.css";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "@fontsource/ibm-plex-mono/latin-500.css";
import "@fontsource/ibm-plex-mono/latin-600.css";
import "./index.css";
import App from "./App.tsx";
import { initPostHog } from "./lib/posthog";

import { isRecoveryLocation, observeRecovery } from "./lib/passwordRecovery";
import { PasswordRecovery } from "./pages/PasswordRecovery";

const entryUrl = new URL(window.location.href);
const recovering = isRecoveryLocation(entryUrl);
if (recovering) observeRecovery(entryUrl);
else initPostHog();

createRoot(document.getElementById("root")!).render(
  <StrictMode>{recovering ? <PasswordRecovery /> : <App />}</StrictMode>,
);
