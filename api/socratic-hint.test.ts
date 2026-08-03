import { describe, it, expect } from "vitest";
import { clientIpFromHeaders } from "./socratic-hint";

describe("clientIpFromHeaders", () => {
  it("prefers the trusted x-real-ip header", () => {
    expect(
      clientIpFromHeaders({
        "x-real-ip": "203.0.113.7",
        "x-forwarded-for": "1.2.3.4, 203.0.113.7",
      }),
    ).toBe("203.0.113.7");
  });

  it("does NOT trust the client-spoofable leftmost x-forwarded-for entry", () => {
    // Attacker prepends a fake IP; we must use the rightmost (infra) hop.
    const ip = clientIpFromHeaders({
      "x-forwarded-for": "6.6.6.6, 10.0.0.1, 203.0.113.7",
    });
    expect(ip).not.toBe("6.6.6.6");
    expect(ip).toBe("203.0.113.7");
  });

  it("uses the single forwarded value when there is one hop", () => {
    expect(clientIpFromHeaders({ "x-forwarded-for": "203.0.113.7" })).toBe(
      "203.0.113.7",
    );
  });

  it("handles array-valued headers", () => {
    expect(clientIpFromHeaders({ "x-real-ip": ["203.0.113.7", "x"] })).toBe(
      "203.0.113.7",
    );
  });

  it("falls back to 'unknown' when no address is present", () => {
    expect(clientIpFromHeaders({})).toBe("unknown");
    expect(clientIpFromHeaders(undefined)).toBe("unknown");
  });
});
