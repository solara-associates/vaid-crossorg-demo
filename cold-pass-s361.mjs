// Cold vs warm timing pass, session 361. Headed Chromium, fresh profile,
// 1440x900. Measures time to first paint and time to the first decision,
// for all six scenarios, on whichever pass this is (the caller decides
// cold vs warm by when it invokes this relative to demo-wake.sh / idle time).
//
// Usage: ORG_A_URL=https://... LABEL=cold node cold-pass-s361.mjs
import { chromium } from 'playwright';
import fs from 'node:fs';

const ORG_A_URL = process.env.ORG_A_URL;
if (!ORG_A_URL) { console.error('set ORG_A_URL'); process.exit(1); }
const LABEL = process.env.LABEL || 'pass';
const OUT_DIR = process.env.OUT_DIR || '.';
fs.mkdirSync(OUT_DIR, { recursive: true });
const SIZE = { width: 1440, height: 900 };

const browser = await chromium.launch({ headless: false });
const context = await browser.newContext({ viewport: SIZE });
const page = await context.newPage();
page.setDefaultTimeout(60000);

const timings = [];
function record(k, v) { timings.push(`${k}=${v}`); console.log(`${k}=${v}`); }

const tNavStart = Date.now();
await page.goto(ORG_A_URL, { waitUntil: 'load' });
const tLoad = Date.now();
record('nav_to_load_ms', tLoad - tNavStart);

const paint = await page.evaluate(() => {
  const entries = performance.getEntriesByType('paint');
  const fp = entries.find(e => e.name === 'first-paint');
  const fcp = entries.find(e => e.name === 'first-contentful-paint');
  return { fp: fp ? fp.startTime : null, fcp: fcp ? fcp.startTime : null };
});
record('time_to_first_paint_ms', Math.round(paint.fp ?? -1));
record('time_to_first_contentful_paint_ms', Math.round(paint.fcp ?? -1));

await page.waitForSelector('.scenario-btn[data-scenario="allowed"]');
await page.screenshot({ path: `${OUT_DIR}/${LABEL}-00-loaded.png`, fullPage: true });

// Lower the cache window so scenarios 4/6 don't dominate this pass's wall time.
await page.evaluate(() => {
  const el = document.getElementById('cacheWindow');
  el.value = '8';
  el.dispatchEvent(new Event('input'));
});
await page.waitForTimeout(200);
await page.locator('#techDetails summary').click();
await page.waitForTimeout(200);

async function waitForDecisions(n, timeout = 60000) {
  await page.waitForFunction(
    (count) => document.querySelectorAll('#crossingBody .decision-banner').length >= count,
    n, { timeout }
  );
}

// First decision overall (scenario 1): the headline cold-start number.
const tFirstClick = Date.now();
await page.click('.scenario-btn[data-scenario="allowed"]');
await waitForDecisions(1);
record('time_to_first_decision_ms', Date.now() - tFirstClick);
await page.screenshot({ path: `${OUT_DIR}/${LABEL}-01-allowed.png`, fullPage: true });

async function runScenario(key, n, timeout = 30000) {
  const t0 = Date.now();
  await page.click(`.scenario-btn[data-scenario="${key}"]`);
  await waitForDecisions(n, timeout);
  record(`${key}_ms`, Date.now() - t0);
}

await runScenario('outside_scope', 1);
await runScenario('delegation', 2);
await runScenario('revocation', 3, 40000);
record('note', 'revocation and reissue each include an explicit ~8s visible wait for the (lowered) cache window, included in their timing above');

await page.click('.scenario-btn[data-scenario="tamper"]');
await page.waitForSelector('#crossingBody button:has-text("Verify bundle")');
await page.click('#crossingBody button:has-text("Verify bundle")');
await page.waitForFunction(() => document.querySelectorAll('.decision-banner').length >= 1);

await runScenario('reissue', 2, 40000);
await page.screenshot({ path: `${OUT_DIR}/${LABEL}-02-final.png`, fullPage: true });

await context.close();
await browser.close();

fs.writeFileSync(`${OUT_DIR}/${LABEL}-timings.log`, timings.join('\n') + '\n');
console.log('saved:', `${OUT_DIR}/${LABEL}-timings.log`);
