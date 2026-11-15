import { describe, expect, it } from "vitest";
import indexHtml from "../../index.html?raw";
import manifestJson from "../../public/manifest.json?raw";
import vercelJson from "../../vercel.json?raw";
import appSource from "../App.tsx?raw";

describe("index.html head", () => {
  const html = indexHtml;

  it("names the product Security Trainer, not SecTrainer", () => {
    expect(html).toMatch(/<title>Security Trainer \|/);
    expect(html).not.toMatch(/<title>SecTrainer/);
    expect(manifestJson).toMatch(/"name": "Security Trainer \|/);
  });

  it("has a canonical link on the production host", () => {
    expect(html).toContain(
      '<link rel="canonical" href="https://security-trainer.vercel.app/" />',
    );
  });

  it("uses absolute og:image and twitter:image URLs", () => {
    expect(html).toMatch(
      /property="og:image" content="https:\/\/security-trainer\.vercel\.app\/og-image\.png"/,
    );
    expect(html).toMatch(
      /property="twitter:image" content="https:\/\/security-trainer\.vercel\.app\/og-image\.png"/,
    );
  });
});

describe("vercel.json routing", () => {
  const config = JSON.parse(vercelJson) as {
    rewrites: { source: string; destination: string }[];
  };
  const sources = config.rewrites.map((r) => r.source);

  it("has no catch-all rewrite, so unknown paths return a real 404", () => {
    expect(sources).not.toContain("/(.*)");
    expect(sources.some((s) => /\(\.\*\)|:path\*|\*/.test(s))).toBe(false);
  });

  it("rewrites every route declared in App.tsx to the SPA shell", () => {
    const paths = [...appSource.matchAll(/path="(\/[^"]*)"/g)].map((m) => m[1]);
    expect(paths.length).toBeGreaterThanOrEqual(10);
    for (const p of paths) expect(sources).toContain(p);
    for (const r of config.rewrites) expect(r.destination).toBe("/index.html");
  });
});
