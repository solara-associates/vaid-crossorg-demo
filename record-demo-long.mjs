// Records a single, continuous human-paced walkthrough (2.5-3.5 min target):
// title card -> all 5 scenarios with captions -> end card -> s351-demo.webm.
//
// Title/end cards are shown on about:blank, not injected into the live page
// right after navigation: doing it there first (an earlier attempt) produced
// several seconds of blank video with the card never appearing at all —
// landing a DOM injection too close to a real page's own load/paint burst
// seems to race with Playwright's video capture. about:blank has no network
// load and no later repaint burst to race against, so the card is captured
// reliably, and navigating away from it to the real page just after is a
// normal mid-recording navigation (same as between any two real pages).
//
// Usage: ORG_A_URL=https://... node record-demo-long.mjs
import { chromium } from 'playwright';
import fs from 'node:fs';

const ORG_A_URL = process.env.ORG_A_URL;
if (!ORG_A_URL) { console.error('set ORG_A_URL'); process.exit(1); }

const OUT_DIR = process.env.OUT_DIR || '.';
const CACHE_WINDOW_SECONDS = 8;
const STEP_MS = 2300;
const DECISION_MS = 3000;
const SIZE = { width: 1440, height: 900 };

const browser = await chromium.launch();
const context = await browser.newContext({ viewport: SIZE, recordVideo: { dir: OUT_DIR, size: SIZE } });
const page = await context.newPage();
page.setDefaultTimeout(30000);

async function showCard(text) {
  const html = `<!doctype html><html><head><style>
    html,body{margin:0;height:100%;background:#14130F;}
    .card{height:100%;display:flex;align-items:center;justify-content:center;
      font-family:'Space Grotesk',Arial,sans-serif;font-size:34px;font-weight:700;
      color:#C9A227;text-align:center;padding:60px;line-height:1.3;box-sizing:border-box;}
  </style></head><body><div class="card">${text.replace(/\n/g, '<br>')}</div></body></html>`;
  await page.setContent(html);
  await page.waitForTimeout(5000);
}

async function caption(text) {
  await page.evaluate((t) => {
    let cap = document.getElementById('__rec_caption');
    if (!cap) {
      cap = document.createElement('div');
      cap.id = '__rec_caption';
      cap.style.cssText = 'position:fixed;left:0;right:0;bottom:0;' +
        'background:rgba(20,19,15,0.92);color:#C9A227;' +
        'font-family:"Space Grotesk",sans-serif;font-size:19px;font-weight:500;' +
        'padding:14px 28px;z-index:9999;border-top:2px solid #C9A227;text-align:center;';
      document.body.appendChild(cap);
    }
    cap.textContent = t;
  }, text);
}

async function clearCaption() {
  await page.evaluate(() => document.getElementById('__rec_caption')?.remove());
}

async function stepThroughFrom(prevCount) {
  const rows = page.locator('#crossingBody .step-row');
  const total = await rows.count();
  for (let i = prevCount; i < total; i++) {
    await rows.nth(i).scrollIntoViewIfNeeded();
    await page.waitForTimeout(STEP_MS);
  }
  return total;
}

async function holdLatestDecision(ms = DECISION_MS) {
  const banners = page.locator('#crossingBody .decision-banner');
  const n = await banners.count();
  if (n > 0) await banners.nth(n - 1).scrollIntoViewIfNeeded();
  await page.waitForTimeout(ms);
}

async function waitForDecisionCount(n, timeout = 20000) {
  await page.waitForFunction(
    (count) => document.querySelectorAll('#crossingBody .decision-banner').length >= count,
    n,
    { timeout }
  );
}

console.log('title card...');
await showCard('Agent identity across clouds:\nGoogle Cloud to AWS, no shared IAM');

console.log('main content...');
await page.goto(ORG_A_URL, { waitUntil: 'networkidle' });
await page.waitForSelector('.scenario-btn[data-scenario="allowed"]');
await page.waitForTimeout(500);

await page.evaluate((v) => {
  const el = document.getElementById('cacheWindow');
  el.value = v;
  el.dispatchEvent(new Event('input'));
}, CACHE_WINDOW_SECONDS);
await page.waitForTimeout(600);

// ---- Scenario 1: Allowed ----
await caption('Testing: an in-scope request from Org A’s infra agent. Proves: Org B verifies and accepts without ever talking to Google Cloud.');
await page.click('.scenario-btn[data-scenario="allowed"]');
await waitForDecisionCount(1);
await page.waitForTimeout(600);
let n = await stepThroughFrom(0);
await holdLatestDecision();
await clearCaption();

// ---- Scenario 2: Out of scope ----
await caption('Testing: the same agent, a resource outside Harbor Ops’ own granted scope. Proves: Org B’s own policy gates the request, not Org A’s claim.');
await page.click('.scenario-btn[data-scenario="outside_scope"]');
await waitForDecisionCount(1);
await page.waitForTimeout(600);
n = await stepThroughFrom(0);
await holdLatestDecision();
await clearCaption();

// ---- Scenario 3: Delegation ----
await caption('Testing: Org A delegates to a sub-agent, depth 1. Proves: the full delegation chain is independently verifiable by Org B.');
await page.click('.scenario-btn[data-scenario="delegation"]');
await waitForDecisionCount(1);
await page.waitForTimeout(600);
n = await stepThroughFrom(0);
await holdLatestDecision();
await caption('Testing: a second hop, depth 2. Proves: the chain still verifies, but Org B’s own depth policy draws the line.');
await waitForDecisionCount(2);
n = await stepThroughFrom(n);
await holdLatestDecision();
await clearCaption();

// ---- Scenario 4: Revocation ----
await caption('Testing: a first request, before revocation. Warms Org B’s cache.');
await page.click('.scenario-btn[data-scenario="revocation"]');
await waitForDecisionCount(1);
await page.waitForTimeout(600);
n = await stepThroughFrom(0);
await holdLatestDecision(2000);

await caption('Revoking on Org A, then retrying immediately. Still accepted, inside the cache window.');
await waitForDecisionCount(2);
n = await stepThroughFrom(n);
await holdLatestDecision(2500);

await caption(`Waiting ${CACHE_WINDOW_SECONDS}s for Org B’s cache window to elapse. This is the real, deliberate trade-off.`);
const waitRowLocator = page.locator('#crossingBody .step-row').last();
await waitRowLocator.scrollIntoViewIfNeeded();
await page.waitForTimeout((CACHE_WINDOW_SECONDS + 2) * 1000);

await caption('Retrying after the window: refused. Proves: revocation reaches Org B, bounded by a visible, configurable cache window.');
await waitForDecisionCount(3);
n = await stepThroughFrom(n);
await holdLatestDecision();
await clearCaption();

// ---- Scenario 5: Tamper and verify ----
await caption('Exporting both orgs’ signed audit trails into one evidence bundle.');
await page.click('.scenario-btn[data-scenario="tamper"]');
await page.waitForSelector('button.action:not(.secondary)');
await page.waitForTimeout(1800);

await caption('Verifying the clean bundle using only the two orgs’ published public keys.');
await page.click('button.action:not(.secondary)');
await page.waitForSelector('.decision-banner');
await page.waitForTimeout(600);
await page.locator('.decision-banner').last().scrollIntoViewIfNeeded();
await page.waitForTimeout(3000);

await caption('Flipping one character in one signature, on purpose.');
await page.click('button.action.secondary');
await page.waitForTimeout(700);

await caption('Verifying again. Proves: exactly the one altered record fails. Everything else still checks out.');
await page.click('button.action:not(.secondary)');
await page.waitForTimeout(1200);
await page.locator('.decision-banner').last().scrollIntoViewIfNeeded();
await page.waitForTimeout(4000);
await clearCaption();

console.log('end card...');
await showCard('VAID: open source, Apache-2.0');

await context.close();
await browser.close();

await new Promise((r) => setTimeout(r, 300));
const videoPath = fs.readdirSync(OUT_DIR).filter(f => f.endsWith('.webm') && !f.startsWith('s351'))
  .map(f => `${OUT_DIR}/${f}`).sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs)[0];
fs.renameSync(videoPath, `${OUT_DIR}/s351-demo.webm`);
console.log('saved', `${OUT_DIR}/s351-demo.webm`);
