/**
 * Authored scenario for the Cascading Failure incident game.
 * Everything here is fictional: "Brightcart" is an invented shop. No real
 * vendors, people or commands. The engine in `src/lib/cascadingFailure.ts`
 * reads this data; there is no runtime AI call.
 */

export type PostmortemCategory =
  "local_vs_global" | "blast_radius" | "non_technical";

export interface ConsequenceDef {
  id: string;
  /** What the player sees when it lands. */
  text: string;
  health: number;
  fatigue?: number;
  addSymptoms?: string[];
  removeSymptoms?: string[];
  addConstraints?: string[];
  setFlags?: string[];
  category: PostmortemCategory;
  /** Postmortem line. The engine prefixes the turn numbers. */
  lesson: string;
}

export interface ScheduleDef {
  delay: 1 | 2 | 3;
  consequence: string;
  /** Schedule only when the flag is set. */
  ifFlag?: string;
  /** Skip this consequence when the flag is already set. */
  unlessFlag?: string;
}

export interface ActionDef {
  id: string;
  label: string;
  kind: "action" | "question";
  /** What happens right away. */
  result: string;
  health: number;
  fatigue?: number;
  addSymptoms?: string[];
  removeSymptoms?: string[];
  addConstraints?: string[];
  setFlags?: string[];
  schedule?: ScheduleDef[];
  /** Postmortem credit when this move bought time. */
  smart?: string;
}

export const CASCADE_TITLE = "Brightcart checkout, on call";

export const CASCADE_SETUP =
  "You are on call for Brightcart, a small web shop: a web app on a managed host, a hosted database, and a payment provider. Nothing is on fire yet. Nobody has told you what is wrong.";

export const CASCADE_START_HEALTH = 45;
export const CASCADE_STABLE_HEALTH = 40;

export const CASCADE_START_SYMPTOMS = [
  "Page latency is up 35 percent over the last hour",
  "Error rate is low",
  "Alert noise is up",
  "Finance flags cost growth",
  "No recent deploys",
];

export const CASCADE_START_CONSTRAINTS = ["One engineer on call: you"];

export const CASCADE_CONSEQUENCES: ConsequenceDef[] = [
  {
    id: "c-cost-freeze",
    text: "Finance notices the bigger database bill and freezes new spend until a manager signs off.",
    health: -8,
    addConstraints: ["Budget freeze: no new spend without approval"],
    category: "non_technical",
    lesson:
      "A bigger database tier hid the symptom and grew the cost line that finance was already watching, so the budget froze.",
  },
  {
    id: "c-stale-prices",
    text: "Support reports prices on product pages that do not match checkout. The cache is serving old data.",
    health: -12,
    addSymptoms: ["Support tickets about prices not matching checkout"],
    category: "blast_radius",
    lesson:
      "The cache also served price data. Nobody asked what else read from that path.",
  },
  {
    id: "c-missed-webhook",
    text: "A customer email reveals payment webhooks have been failing for a while. No alert fired, because you muted them.",
    health: -18,
    addSymptoms: ["Orders paid but not marked as paid"],
    addConstraints: ["Payment provider has flagged repeated failed callbacks"],
    category: "local_vs_global",
    lesson:
      "Muting the noise made your own view calmer and removed the one alert that mattered.",
  },
  {
    id: "c-conversion-drop",
    text: "Checkout completions dip. The throttle is turning away real buyers along with the load.",
    health: -8,
    addSymptoms: ["Checkout completions are down"],
    category: "local_vs_global",
    lesson:
      "The throttle protected the database by turning away paying customers.",
  },
  {
    id: "c-retry-pile",
    text: "The payment provider retries the rejected calls. The retries land at once and add load.",
    health: -10,
    addConstraints: ["Payment provider rate limit notice"],
    category: "blast_radius",
    lesson:
      "Throttling checkout pushed work onto the payment provider's retry behaviour, which came back as a spike.",
  },
  {
    id: "c-finance-workaround",
    text: "The finance dashboard goes blank. A finance analyst, with month-end close in two days, starts running queries straight on the production database with a shared login.",
    health: -6,
    addSymptoms: ["Unfamiliar long queries from a shared login"],
    category: "non_technical",
    lesson:
      "Finance depended on the export job and was never told. They built a workaround: queries on production through a shared login.",
  },
  {
    id: "c-shared-login-exposed",
    text: "The shared login turns up in a team chat thread. It has write access.",
    health: -12,
    addConstraints: ["Shared database login must be rotated"],
    category: "non_technical",
    lesson:
      "The workaround spread a shared credential with write access, a security problem that began as a reporting problem.",
  },
  {
    id: "c-dashboard-paused",
    text: "Finance confirms the dashboard is paused. They are annoyed, but they know why and have a plan.",
    health: -2,
    addConstraints: ["Finance dashboard paused until a read replica exists"],
    category: "non_technical",
    lesson:
      "Pausing the export had a cost for finance, but because you asked first it became a plan and not a workaround.",
  },
  {
    id: "c-team-friction",
    text: "The platform team lead asks, politely, why their on-call was woken without a ticket.",
    health: -3,
    category: "non_technical",
    lesson:
      "Waking another team was reasonable, but it spent goodwill with no written handoff.",
  },
  {
    id: "c-update-cadence",
    text: "Customer service now expects an update every hour. That is one more thing on your plate.",
    health: -1,
    fatigue: 1,
    addConstraints: ["Hourly status updates promised"],
    category: "non_technical",
    lesson:
      "A status update calmed people and created a promise to keep up the cadence.",
  },
  {
    id: "c-connection-spike",
    text: "After the restart, every client reconnects at once. The connection pool spikes and a few requests fail.",
    health: -10,
    addSymptoms: ["Brief spike of connection errors"],
    category: "blast_radius",
    lesson:
      "The restart cleared the symptom and queued a thundering herd of reconnects.",
  },
];

export const CASCADE_ACTIONS: ActionDef[] = [
  {
    id: "inspect-queries",
    label: "Ask: which database queries are the slowest right now?",
    kind: "question",
    result:
      "The slowest queries are all from one source: an hourly reporting export that scans the orders table. It started about the time latency crept up.",
    health: 0,
    addSymptoms: ["Slowest queries come from an hourly reporting export"],
    setFlags: ["exportFound"],
    smart:
      "Looking at the data before changing anything found the real load source.",
  },
  {
    id: "ask-finance",
    label: "Ask: who uses the reporting export, and what for?",
    kind: "question",
    result:
      "Finance says the export feeds their revenue dashboard. Month-end close is in two days and they have no other source.",
    health: 0,
    addConstraints: ["Finance needs the revenue dashboard for month-end close"],
    setFlags: ["financeInformed"],
    smart:
      "Asking who depended on the export surfaced a human coupling before it could bite.",
  },
  {
    id: "ask-support",
    label: "Ask: what are customers reporting?",
    kind: "question",
    result:
      "Support says a few people mention slow checkout. No payment failures reported yet. Nothing else stands out.",
    health: 0,
    smart: "A cheap question confirmed customer impact was still small.",
  },
  {
    id: "scale-db",
    label: "Move the database to a bigger plan",
    kind: "action",
    result:
      "Latency drops. The dashboard looks healthier. The cause is still unknown.",
    health: 3,
    removeSymptoms: ["Page latency is up 35 percent over the last hour"],
    schedule: [{ delay: 2, consequence: "c-cost-freeze" }],
  },
  {
    id: "add-cache",
    label: "Put a cache in front of the busiest read endpoint",
    kind: "action",
    result: "Reads get faster and database load eases.",
    health: 3,
    schedule: [{ delay: 2, consequence: "c-stale-prices" }],
  },
  {
    id: "mute-alerts",
    label: "Silence the noisy alerts so you can think",
    kind: "action",
    result:
      "The pager goes quiet. Your head clears. You take a breath. (The alerts do not stop existing. They just stop talking to you.)",
    health: 1,
    fatigue: -1,
    removeSymptoms: ["Alert noise is up"],
    schedule: [{ delay: 3, consequence: "c-missed-webhook" }],
  },
  {
    id: "rate-limit-api",
    label: "Throttle the checkout API",
    kind: "action",
    result: "Database load falls. Some requests now get a slow-down response.",
    health: 2,
    schedule: [
      { delay: 1, consequence: "c-conversion-drop" },
      { delay: 3, consequence: "c-retry-pile" },
    ],
  },
  {
    id: "disable-export",
    label: "Pause the hourly reporting export",
    kind: "action",
    result:
      "Database load falls sharply and latency starts to recover. The export is off until someone turns it back on.",
    health: 10,
    removeSymptoms: ["Slowest queries come from an hourly reporting export"],
    setFlags: ["rootMitigated"],
    schedule: [
      {
        delay: 1,
        consequence: "c-dashboard-paused",
        ifFlag: "financeInformed",
      },
      {
        delay: 2,
        consequence: "c-finance-workaround",
        unlessFlag: "financeInformed",
      },
      {
        delay: 3,
        consequence: "c-shared-login-exposed",
        unlessFlag: "financeInformed",
      },
    ],
    smart:
      "Pausing the export removed the actual load source instead of absorbing it.",
  },
  {
    id: "restart-services",
    label: "Restart the app services",
    kind: "action",
    result: "Things feel snappier for a moment, as they do after a restart.",
    health: 2,
    schedule: [{ delay: 1, consequence: "c-connection-spike" }],
  },
  {
    id: "page-teammate",
    label: "Wake a second engineer on another team",
    kind: "action",
    result:
      "Someone joins the call, a little groggy. You can split the work now.",
    health: 1,
    fatigue: -2,
    schedule: [{ delay: 2, consequence: "c-team-friction" }],
    smart:
      "Sharing the load kept the on-call engineer from making tired mistakes.",
  },
  {
    id: "status-update",
    label: "Post a short status update to staff and customers",
    kind: "action",
    result:
      "People stop asking you in three different channels. Fewer interruptions.",
    health: 1,
    schedule: [{ delay: 1, consequence: "c-update-cadence" }],
    smart: "Communicating early cut interruptions and bought focus time.",
  },
];
