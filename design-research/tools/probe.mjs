import { chromium } from "@playwright/test";
const [url, js] = process.argv.slice(2);
const b = await chromium.launch({ channel: "chrome" });
const p = await b.newPage({ viewport: { width: 1440, height: 900 } });
await p.goto(url); await p.waitForTimeout(Number(process.env.WAIT ?? 2000));
console.log(JSON.stringify(await p.evaluate(js), null, 1));
await b.close();
