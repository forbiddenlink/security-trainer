/**
 * Vite middleware for local /api/socratic-hint during `pnpm dev`.
 * Mirrors the Vercel serverless handler; uses GROQ_API_KEY from env.
 */
import type { Plugin, Connect } from "vite";

const MAX_BODY_BYTES = 16_384;

async function readBody(req: Connect.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c) => {
      const buf = Buffer.from(c);
      size += buf.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("Body too large"));
        req.destroy();
        return;
      }
      chunks.push(buf);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

export function socraticHintApiPlugin(): Plugin {
  return {
    name: "socratic-hint-api",
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        if (!req.url?.startsWith("/api/socratic-hint")) {
          next();
          return;
        }

        if (req.method !== "POST") {
          res.statusCode = 405;
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify({ error: "Method not allowed" }));
          return;
        }

        const apiKey = process.env.GROQ_API_KEY;
        if (!apiKey) {
          res.statusCode = 503;
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify({ error: "AI unavailable" }));
          return;
        }

        try {
          const raw = await readBody(req);
          const body = JSON.parse(raw || "{}") as {
            prompt?: string;
            level?: number;
          };

          if (!body.prompt) {
            res.statusCode = 400;
            res.setHeader("Content-Type", "application/json");
            res.end(JSON.stringify({ error: "Missing prompt" }));
            return;
          }
          if (body.prompt.length > 4000) {
            res.statusCode = 413;
            res.setHeader("Content-Type", "application/json");
            res.end(JSON.stringify({ error: "Prompt too large" }));
            return;
          }

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
                  { role: "user", content: body.prompt },
                ],
              }),
            },
          );

          if (!response.ok) {
            res.statusCode = 502;
            res.setHeader("Content-Type", "application/json");
            res.end(JSON.stringify({ error: "AI unavailable" }));
            return;
          }

          const data = (await response.json()) as {
            choices?: { message?: { content?: string } }[];
          };
          const content = data.choices?.[0]?.message?.content ?? "{}";
          let parsed: { hint?: string; conceptPointer?: string } = {};
          try {
            parsed = JSON.parse(content);
          } catch {
            res.statusCode = 502;
            res.setHeader("Content-Type", "application/json");
            res.end(JSON.stringify({ error: "AI unavailable" }));
            return;
          }

          res.statusCode = 200;
          res.setHeader("Content-Type", "application/json");
          res.end(
            JSON.stringify({
              hint: (parsed.hint ?? "").slice(0, 500),
              conceptPointer: (parsed.conceptPointer ?? "").slice(0, 300),
              level: body.level ?? 1,
            }),
          );
        } catch {
          res.statusCode = 502;
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify({ error: "AI unavailable" }));
        }
      });
    },
  };
}
