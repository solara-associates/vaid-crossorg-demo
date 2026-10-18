// Records a Playwright walkthrough of all 5 scenarios for the crossing view.
// Usage: ORG_A_URL=https://... node record-demo.mjs
// Keeps the recorded cache window short (set via the slider) so scenario 4's
// wait does not blow the under-4-minutes budget.
import { chromium } from 'playwright';
import fs from 'node:fs';

const ORG_A_URL = process.env.ORG_A_URL;
if (!ORG_A_URL) { console.error('set ORG_A_URL'); process.exit(1); }

const OUT_DIR = process.env.OUT_DIR || '.';
const CACHE_WINDOW_SECONDS = 8; // short, so scenario 4's wait stays small

const browser = await chromium.launch();
const context = await browser.newContext({
  viewport: { width: 1440, height: 900 },
  recordVideo: { dir: OUT_DIR, size: { width: 1440, height: 900 } },
});
const page = await context.newPage();
page.setDefaultTimeout(30000);

await page.goto(ORG_A_URL, { waitUntil: 'networkidle' });
await page.waitForTimeout(800);

// Set the cache window slider to a short value up front.
await page.evaluate((v) => {
  const el = document.getElementById('cacheWindow');
  el.value = v;
  el.dispatchEvent(new Event('input'));
}, CACHE_WINDOW_SECONDS);
await page.waitForTimeout(500);

async function runScenario(name, waitMs) {
  await page.click(`.scenario-btn[data-scenario="${name}"]`);
  await page.waitForTimeout(waitMs);
}

await runScenario('allowed', 2500);
await runScenario('outside_scope', 2500);
await runScenario('delegation', 4000);
await runScenario('revocation', (CACHE_WINDOW_SECONDS + 4) * 1000);
await runScenario('tamper', 1500);

// Click through the tamper-and-verify flow explicitly: verify clean first,
// then tamper, then verify again to show the one detected failure.
await page.click('button.action:not(.secondary)'); // verify bundle (clean)
await page.waitForTimeout(2000);
await page.click('button.action.secondary'); // flip one byte
await page.waitForTimeout(500);
await page.click('button.action:not(.secondary)'); // verify bundle (tampered)
await page.waitForTimeout(2500);

await context.close();
await browser.close();

const videoPath = fs.readdirSync(OUT_DIR).filter(f => f.endsWith('.webm')).map(f => `${OUT_DIR}/${f}`).sort((a,b)=>fs.statSync(b).mtimeMs-fs.statSync(a).mtimeMs)[0];
fs.renameSync(videoPath, `${OUT_DIR}/s351-demo.webm`);
console.log('saved', `${OUT_DIR}/s351-demo.webm`);
