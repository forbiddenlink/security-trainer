// Screenshot helper: node design-research/tools/shoot.mjs <outDir> <name>=<url> [<name>=<url> ...]
// Captures desktop (1440x900, above-the-fold + full page) and mobile (390x844) PNGs per URL.
// Prints one line per shot: OK|FAIL name variant detail
import { chromium } from "@playwright/test";
import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const [outDir, ...pairs] = process.argv.slice(2);
if (!outDir || pairs.length === 0) {
  console.error("usage: shoot.mjs <outDir> name=url ...");
  process.exit(2);
}
mkdirSync(outDir, { recursive: true });
const fullPage = process.env.FULL !== "0";
// STORAGE=<json file>: {"key": <value>} seeded into localStorage before load
const storage = process.env.STORAGE ? JSON.parse(readFileSync(process.env.STORAGE, "utf8")) : null;
const browser = await chromium.launch({ channel: process.env.PW_CHANNEL ?? "chrome" });
const variants = [
  { key: "desktop", viewport: { width: 1440, height: 900 }, isMobile: false },
  { key: "mobile", viewport: { width: 390, height: 844 }, isMobile: true, deviceScaleFactor: 2 },
];
for (const pair of pairs) {
  const i = pair.indexOf("=");
  const name = pair.slice(0, i);
  const url = pair.slice(i + 1);
  for (const v of variants) {
    const ctx = await browser.newContext({
      viewport: v.viewport,
      isMobile: v.isMobile,
      deviceScaleFactor: v.deviceScaleFactor ?? 1,
      colorScheme: process.env.SCHEME ?? "light",
      userAgent: v.isMobile
        ? "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
        : undefined,
    });
    if (storage) {
      await ctx.addInitScript((entries) => {
        for (const [k, v] of Object.entries(entries)) {
          if (!localStorage.getItem("__seeded_" + k)) {
            localStorage.setItem(k, typeof v === "string" ? v : JSON.stringify(v));
            localStorage.setItem("__seeded_" + k, "1");
          }
        }
      }, storage);
    }
    const page = await ctx.newPage();
    try {
      const res = await page.goto(url, { waitUntil: "domcontentloaded", timeout: 30000 });
      await page.waitForTimeout(Number(process.env.WAIT ?? 2500));
      const status = res ? res.status() : 0;
      const sfx = (process.env.SCHEME === "dark" ? "-dark" : "") + (process.env.SUFFIX ?? "");
      const file = join(outDir, `${name}-${v.key}${sfx}.png`);
      await page.screenshot({ path: file, fullPage: fullPage && v.key === "desktop" ? false : false });
      if (fullPage && v.key === "desktop") {
        await page.screenshot({ path: join(outDir, `${name}-${v.key}-full.png`), fullPage: true, timeout: 30000 }).catch(() => {});
      }
      const title = (await page.title()).slice(0, 80);
      console.log(`OK ${name} ${v.key} status=${status} title="${title}"`);
    } catch (e) {
      console.log(`FAIL ${name} ${v.key} ${String(e.message).split("\n")[0]}`);
    }
    await ctx.close();
  }
}
await browser.close();
