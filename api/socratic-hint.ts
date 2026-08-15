/**
 * POST /api/socratic-hint
 * Body: { category, level, title?, vulnerableCode?, learnerQuestion? }
 * Requires GROQ_API_KEY (server env) — never expose to the client.
 *
 * The Socratic prompt is constructed SERVER-SIDE from validated fields so the
 * endpoint cannot be used as a general-purpose Groq proxy (an attacker cannot
 * send arbitrary completion text).
 *
 * Abuse controls (all require Upstash to be configured; skipped in local dev):
 *   - Per-client rate limit: 20 req / 60s, keyed on a TRUSTED client IP.
 *   - Global daily budget: hard cap on total requests/day + env kill switch,
 *     bounding worst-case Groq spend even under a distributed attack.
 *
 * Compatible with Vercel Node serverless and local Vite middleware.
 */
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
import {
  buildSocraticPrompt,
  parseSocraticBody,
} from "../src/lib/socraticPrompt";

type ReqReq = {
  method?: string;
  body?: unknown;
  headers?: Record<string, string | string[] | undefined>;
};

// Default 2000 successful calls/day (~llama-3.1-8b, negligible cost) unless overridden.
const DAILY_BUDGET = Number(process.env.AI_DAILY_BUDGET ?? "2000");

let redis: Redis | null = null;
let ratelimit: Ratelimit | null = null;

function getRedis(): Redis | null {
  if (redis) return redis;
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return null;
  redis = new Redis({ url, token });
  return redis;
}

function getRatelimit(): Ratelimit | null {
  if (ratelimit) return ratelimit;
  const r = getRedis();
  if (!r) return null;
  ratelimit = new Ratelimit({
    redis: r,
    limiter: Ratelimit.slidingWindow(20, "60 s"),
    prefix: "rl:socratic-hint",
  });
  return ratelimit;
}

function headerValue(
  headers: ReqReq["headers"],
  name: string,
): string | undefined {
  const v = headers?.[name];
  return Array.isArray(v) ? v[0] : v;
}

/**
 * Resolve a TRUSTED client IP. On Vercel, `x-forwarded-for` is client-spoofable
 * at its LEFTMOST entry, so we prefer platform-set trusted headers and, failing
 * that, take the RIGHTMOST forwarded hop (closest to our edge). Exported for tests.
 */
export function clientIpFromHeaders(headers: ReqReq["headers"]): string {
  const trusted =
    headerValue(headers, "x-real-ip") ??
    headerValue(headers, "x-vercel-forwarded-for");
  if (trusted?.trim()) return trusted.trim();

  const fwd = headerValue(headers, "x-forwarded-for");
  if (fwd) {
    const hops = fwd
      .split(",")
      .map((h) => h.trim())
      .filter(Boolean);
    // Rightmost hop is added by infrastructure we control, not the client.
    if (hops.length) return hops[hops.length - 1];
  }
  return "unknown";
}

/** Increment today's global counter (TTL 24h). Fail-open (returns true) on Redis error. */
async function withinDailyBudget(): Promise<boolean> {
  const r = getRedis();
  if (!r) return true; // no Redis configured (local dev) → no global cap
  try {
    const key = `budget:socratic-hint:${new Date().toISOString().slice(0, 10)}`;
    const count = await r.incr(key);
    if (count === 1) await r.expire(key, 86400);
    return count <= DAILY_BUDGET;
  } catch (err) {
    console.error("[socratic-hint] budget check failed, allowing:", err);
    return true;
  }
}

type ResLike = {
  status: (code: number) => ResLike;
  setHeader: (k: string, v: string) => void;
  json: (body: unknown) => void;
  end?: (body?: string) => void;
};

export default async function handler(req: ReqReq, res: ResLike) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  if (process.env.AI_DISABLED === "1") {
    return res.status(503).json({ error: "AI unavailable" });
  }

  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) {
    return res.status(503).json({ error: "AI unavailable" });
  }

  // --- Validate input (server owns the prompt shape) ---
  const parsed = parseSocraticBody(req.body);
  if (!parsed.ok) {
    return res.status(400).json({ error: parsed.error });
  }
  const input = parsed.value;

  // --- Abuse controls (best-effort; degrade open on infra failure) ---
  const limiter = getRatelimit();
  if (limiter) {
    try {
      const { success } = await limiter.limit(clientIpFromHeaders(req.headers));
      if (!success) {
        res.setHeader("Retry-After", "60");
        return res.status(429).json({ error: "Too many requests" });
      }
    } catch (err) {
      console.error("[socratic-hint] rate limiter failed, allowing:", err);
    }
  } else if (
    process.env.VERCEL &&
    process.env.HINTS_ALLOW_NO_RATELIMIT !== "true"
  ) {
    // Fail closed on a real deployment: without a configured limiter this is an
    // open, unauthenticated proxy to a paid LLM. Refuse rather than expose it.
    // Set UPSTASH_REDIS_REST_URL/TOKEN to enable throttling, or
    // HINTS_ALLOW_NO_RATELIMIT=true to intentionally run unlimited.
    return res.status(503).json({ error: "AI unavailable" });
  }

  if (!(await withinDailyBudget())) {
    res.setHeader("Retry-After", "3600");
    return res.status(429).json({ error: "Daily AI limit reached" });
  }

  const prompt = buildSocraticPrompt(input);

  try {
    const response = await fetch(
      "https://api.groq.com/openai/v1/chat/completions",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: "llama-3.1-8b-instant",
          temperature: 0.4,
          response_format: { type: "json_object" },
          messages: [
            {
              role: "system",
              content:
                'You are a cybersecurity instructor using the Socratic method. Reply with JSON only: {"hint":"...","conceptPointer":"..."}',
            },
            { role: "user", content: prompt },
          ],
        }),
      },
    );

    if (!response.ok) {
      return res.status(502).json({ error: "AI unavailable" });
    }

    const data = (await response.json()) as {
      choices?: { message?: { content?: string } }[];
    };
    const content = data.choices?.[0]?.message?.content ?? "{}";
    let result: { hint?: string; conceptPointer?: string } = {};
    try {
      result = JSON.parse(content);
    } catch {
      return res.status(502).json({ error: "AI unavailable" });
    }

    return res.status(200).json({
      hint: (result.hint ?? "").slice(0, 500),
      conceptPointer: (result.conceptPointer ?? "").slice(0, 300),
      level: input.level,
    });
  } catch {
    return res.status(502).json({ error: "AI unavailable" });
  }
}
