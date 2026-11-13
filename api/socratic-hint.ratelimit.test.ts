import { beforeEach, describe, expect, it, vi } from "vitest";

const limit = vi.hoisted(() => vi.fn());

const redisOps = vi.hoisted(() => ({
  incr: vi.fn(),
  expire: vi.fn(),
}));
vi.mock("@upstash/redis", () => ({
  Redis: class {
    incr = redisOps.incr;
    expire = redisOps.expire;
  },
}));
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
    redisOps.incr.mockReset();
    redisOps.expire.mockReset();
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

  it("fails closed with 503 and never calls the LLM when the limiter throws", async () => {
    const logged = vi.spyOn(console, "error").mockImplementation(() => {});
    limit.mockImplementation(() => {
      throw new Error("ECONNREFUSED");
    });
    const res = await call();
    expect(res.code).toBe(503);
    expect(fetch).not.toHaveBeenCalled();
    logged.mockRestore();
  });

  it("fails closed with 503 and never calls the LLM when the daily budget check throws", async () => {
    const logged = vi.spyOn(console, "error").mockImplementation(() => {});
    limit.mockResolvedValue({ success: true });
    redisOps.incr.mockImplementation(() => {
      throw new Error("ECONNREFUSED");
    });
    const res = await call();
    expect(res.code).toBe(503);
    expect(fetch).not.toHaveBeenCalled();
    logged.mockRestore();
  });

  it("returns 429 once the daily budget is exceeded", async () => {
    limit.mockResolvedValue({ success: true });
    redisOps.incr.mockResolvedValue(2001);
    const res = await call();
    expect(res.code).toBe(429);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("caps max_tokens on the model call and uses a repo-prefixed budget key", async () => {
    limit.mockResolvedValue({ success: true });
    redisOps.incr.mockResolvedValue(5);
    const f = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        choices: [{ message: { content: '{"hint":"h","conceptPointer":"c"}' } }],
      }),
    });
    vi.stubGlobal("fetch", f);
    const res = await call();
    expect(res.code).toBe(200);
    const body = JSON.parse(f.mock.calls[0][1].body as string);
    expect(body.max_tokens).toBe(600);
    expect(redisOps.incr.mock.calls[0][0]).toMatch(/^security-trainer:budget:/);
  });
});
