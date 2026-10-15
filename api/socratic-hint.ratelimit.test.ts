import { beforeEach, describe, expect, it, vi } from "vitest";

const limit = vi.hoisted(() => vi.fn());

vi.mock("@upstash/redis", () => ({ Redis: class {} }));
vi.mock("@upstash/ratelimit", () => {
  class Ratelimit {
    static slidingWindow() {
      return {};
    }
    limit = limit;
  }
  return { Ratelimit };
});

function fakeRes() {
  const res = {
    code: 0,
    headers: {} as Record<string, string>,
    body: undefined as unknown,
    status(c: number) {
      res.code = c;
      return res;
    },
    setHeader(k: string, v: string) {
      res.headers[k] = v;
    },
    json(b: unknown) {
      res.body = b;
    },
  };
  return res;
}

async function call() {
  vi.resetModules();
  process.env.GROQ_API_KEY = "test";
  process.env.UPSTASH_REDIS_REST_URL = "https://example.invalid";
  process.env.UPSTASH_REDIS_REST_TOKEN = "x";
  const { default: handler } = await import("./socratic-hint");
  const res = fakeRes();
  await handler(
    { method: "POST", body: { category: "xss", level: 1 }, headers: {} },
    res,
  );
  return res;
}

describe("socratic-hint rate limit", () => {
  beforeEach(() => {
    limit.mockReset();
    vi.stubGlobal("fetch", vi.fn());
  });

  it("fails closed with 503 and never calls the LLM when the limiter times out", async () => {
    limit.mockResolvedValue({ success: true, reason: "timeout" });
    const res = await call();
    expect(res.code).toBe(503);
    expect(res.headers["Retry-After"]).toBe("5");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("returns 429 when over the limit", async () => {
    limit.mockResolvedValue({ success: false });
    expect((await call()).code).toBe(429);
  });
});
