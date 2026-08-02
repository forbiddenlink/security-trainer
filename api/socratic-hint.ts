/**
 * POST /api/socratic-hint
 * Body: { prompt, category, level }
 * Requires GROQ_API_KEY (server env) — never expose to the client.
 *
 * Rate-limited per-IP via Upstash when UPSTASH_REDIS_REST_URL/TOKEN are set
 * (skipped gracefully if not configured — e.g. local dev uses the Vite plugin).
 *
 * Compatible with Vercel Node serverless and local Vite middleware.
 */
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

type ReqReq = {
  method?: string;
  body?: { prompt?: string; category?: string; level?: number };
  headers?: Record<string, string | string[] | undefined>;
};

// Lazily build one limiter per warm instance: 20 requests / 60s per IP.
let ratelimit: Ratelimit | null = null;
function getRatelimit(): Ratelimit | null {
  if (ratelimit) return ratelimit;
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return null;
  ratelimit = new Ratelimit({
    redis: new Redis({ url, token }),
    limiter: Ratelimit.slidingWindow(20, "60 s"),
    prefix: "rl:socratic-hint",
  });
  return ratelimit;
}

function clientIp(req: ReqReq): string {
  const fwd = req.headers?.["x-forwarded-for"];
  const raw = Array.isArray(fwd) ? fwd[0] : fwd;
  return raw?.split(",")[0]?.trim() || "unknown";
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

  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) {
    return res.status(503).json({ error: "AI unavailable" });
  }

  const limiter = getRatelimit();
  if (limiter) {
    const { success } = await limiter.limit(clientIp(req));
    if (!success) {
      res.setHeader("Retry-After", "60");
      return res.status(429).json({ error: "Too many requests" });
    }
  }

  const { prompt, level } = req.body ?? {};
  if (!prompt || typeof prompt !== "string") {
    return res.status(400).json({ error: "Missing prompt" });
  }
  // Cap input — the client prompt is a bounded template; anything larger is abuse.
  if (prompt.length > 4000) {
    return res.status(413).json({ error: "Prompt too large" });
  }

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
    let parsed: { hint?: string; conceptPointer?: string } = {};
    try {
      parsed = JSON.parse(content);
    } catch {
      return res.status(502).json({ error: "AI unavailable" });
    }

    return res.status(200).json({
      hint: (parsed.hint ?? "").slice(0, 500),
      conceptPointer: (parsed.conceptPointer ?? "").slice(0, 300),
      level: level ?? 1,
    });
  } catch {
    return res.status(502).json({ error: "AI unavailable" });
  }
}
