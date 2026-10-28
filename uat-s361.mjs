// Demo readiness gate (per ~/.claude/CLAUDE.md), session 361.
// Headed Chromium, fresh profile, 1440x900. Exercises the live page exactly as
// a presenter would: all 6 scenarios (5 scripted + the new "same agent, new
// badge" proof), the job picker (every option), and Cancel the badge. Both
// simple and technical views are screenshotted for each scenario. Console
// messages and failed network requests are recorded; any error is a fail.
//
// Usage: ORG_A_URL=https://... node uat-s361.mjs
import { chromium } from 'playwright';
import fs from 'node:fs';

const ORG_A_URL = process.env.ORG_A_URL;
if (!ORG_A_URL) { console.error('set ORG_A_URL'); process.exit(1); }

const OUT_DIR = process.env.OUT_DIR || '.';
fs.mkdirSync(OUT_DIR, { recursive: true });
const SIZE = { width: 1440, height: 900 };

const consoleLog = [];
const networkFailures = [];

const browser = await chromium.launch({ headless: false });
const context = await browser.newContext({ viewport: SIZE, recordVideo: { dir: OUT_DIR, size: SIZE } });
const page = await context.newPage();
page.setDefaultTimeout(30000);

page.on('console', (msg) => consoleLog.push(`[${msg.type()}] ${msg.text()}`));
page.on('pageerror', (err) => consoleLog.push(`[pageerror] ${err}`));
page.on('requestfailed', (req) => networkFailures.push(`${req.method()} ${req.url()} :: ${req.failure()?.errorText}`));
page.on('response', (res) => {
  if (res.status() >= 400) networkFailures.push(`${res.status()} ${res.request().method()} ${res.url()}`);
});

let shot = 0;
async function screenshot(name) {
  shot += 1;
  const path = `${OUT_DIR}/${String(shot).padStart(2, '0')}-${name}.png`;
  await page.screenshot({ path, fullPage: true });
  console.log('screenshot:', path);
}

async function openTechDetail() {
  const details = page.locator('#techDetails');
  const isOpen = await details.evaluate((el) => el.open);
  if (!isOpen) await page.click('#techDetails summary');
  await page.waitForTimeout(300);
}

async function closeTechDetail() {
  const details = page.locator('#techDetails');
  const isOpen = await details.evaluate((el) => el.open);
  if (isOpen) await page.click('#techDetails summary');
  await page.waitForTimeout(200);
}

async function waitForDecisions(n, timeout = 25000) {
  await page.waitForFunction(
    (count) => document.querySelectorAll('#crossingBody .decision-banner').length >= count,
    n,
    { timeout }
  );
}

console.log('navigating (cold-ish: first request after an idle period)...');
const t0 = Date.now();
await page.goto(ORG_A_URL, { waitUntil: 'networkidle' });
const navMs = Date.now() - t0;
console.log('nav took', navMs, 'ms');
await page.waitForSelector('.scenario-btn[data-scenario="allowed"]');
await screenshot('page-loaded');

// Lower the cache window so scenario 4 completes in a reasonable time.
await page.evaluate(() => {
  const el = document.getElementById('cacheWindow');
  el.value = '8';
  el.dispatchEvent(new Event('input'));
});
await page.waitForTimeout(300);

// Everything the crossing view draws (credential boxes, trace, decision
// banners, and scenario 5's own buttons) renders inside the technical
// <details>, closed by default. It must stay OPEN for any interaction;
// only the simple-view screenshot briefly closes it.
await openTechDetail();

async function runScenario(key, label, decisionCount) {
  console.log('scenario:', key);
  await openTechDetail();
  await page.click(`.scenario-btn[data-scenario="${key}"]`);
  await waitForDecisions(decisionCount, (key === 'revocation' || key === 'reissue') ? 40000 : 25000);
  await page.waitForTimeout(500);
  await closeTechDetail();
  await screenshot(`${key}-simple`);
  await openTechDetail();
  await screenshot(`${key}-technical`);
}

await runScenario('allowed', '1. Allowed job', 1);
await runScenario('outside_scope', '2. Job outside its badge', 1);
await runScenario('delegation', '3. Agent hands work to a helper', 2);
await runScenario('revocation', '4. Badge cancelled', 3);

// Scenario 5: tamper. Its buttons live inside the technical <details> too
// (there is no simple-view-only interaction for this one), so tech detail
// must stay open for every click; only the screenshots toggle it.
console.log('scenario: tamper');
await openTechDetail();
await page.click('.scenario-btn[data-scenario="tamper"]');
const verifyBtn = page.locator('#crossingBody button:has-text("Verify bundle")');
const flipBtn = page.locator('#crossingBody button:has-text("Flip one byte for me")');
await verifyBtn.waitFor();
await closeTechDetail();
await screenshot('tamper-bundle-simple');
await openTechDetail();
await verifyBtn.click(); // Verify bundle (clean)
await page.waitForFunction(() => document.querySelectorAll('.decision-banner').length >= 1);
await page.waitForTimeout(400);
await screenshot('tamper-verified-clean');
await flipBtn.click(); // Flip one byte
await page.waitForTimeout(300);
await verifyBtn.click(); // Verify again
await page.waitForTimeout(600);
await screenshot('tamper-verified-tampered');

// Scenario 6: same agent, new badge.
await runScenario('reissue', '6. Same agent, new badge', 2);

// Job picker: every option.
console.log('job picker: every option');
const jobPicker = page.locator('#jobPicker');
const optionValues = await jobPicker.locator('option').evaluateAll((opts) => opts.map((o) => o.value));
for (const value of optionValues) {
  await openTechDetail();
  await jobPicker.selectOption(value);
  await page.click('#sendJobBtn');
  await page.waitForFunction(() => document.querySelectorAll('.decision-banner').length >= 1, { timeout: 25000 });
  await page.waitForTimeout(500);
  const safeName = value.replace(/\//g, '_');
  await closeTechDetail();
  await screenshot(`picker-${safeName}-simple`);
  await openTechDetail();
  await screenshot(`picker-${safeName}-technical`);
}

// Cancel the badge, then retry the same (now cancelled) driver credential.
console.log('cancel the badge');
await closeTechDetail();
await page.click('#cancelBadgeBtn');
await page.waitForTimeout(300);
await screenshot('driver-cancelled-status');
await openTechDetail();
await page.click('#sendJobBtn');
await page.waitForFunction(() => document.querySelectorAll('.decision-banner').length >= 1, { timeout: 25000 });
await page.waitForTimeout(500);
await closeTechDetail();
await screenshot('driver-after-cancel-simple');
await openTechDetail();
await screenshot('driver-after-cancel-technical');

// ---- off-script detours ----
console.log('detour: refresh mid-flow');
await page.click('.scenario-btn[data-scenario="allowed"]');
await page.waitForTimeout(300); // reload before the decision lands
await page.reload({ waitUntil: 'networkidle' });
await page.waitForSelector('.scenario-btn[data-scenario="allowed"]');
await screenshot('detour-refresh-mid-flow');

console.log('detour: back button after a scenario');
await page.click('.scenario-btn[data-scenario="allowed"]');
await waitForDecisions(1);
await page.goBack();
await page.waitForTimeout(500);
await screenshot('detour-back-button');
// goBack on a same-page SPA-ish app with no history entries just stays put or
// goes to about:blank depending on navigation history; recover either way.
if (page.url() === 'about:blank') {
  await page.goto(ORG_A_URL, { waitUntil: 'networkidle' });
  await page.waitForSelector('.scenario-btn[data-scenario="allowed"]');
}

console.log('detour: click a scenario, then immediately click another (wrong click)');
await page.click('.scenario-btn[data-scenario="allowed"]');
await page.waitForTimeout(150);
await page.click('.scenario-btn[data-scenario="tamper"]').catch((e) => consoleLog.push(`[detour] second click during busy state: ${e}`));
await page.waitForTimeout(1500);
await screenshot('detour-rapid-reclick');

await context.close();
await browser.close();

fs.writeFileSync(`${OUT_DIR}/console.log`, consoleLog.join('\n') + '\n');
fs.writeFileSync(`${OUT_DIR}/network-failures.log`, networkFailures.join('\n') + '\n');
console.log('console messages:', consoleLog.length, '-> console.log');
console.log('network failures:', networkFailures.length, '-> network-failures.log');

await new Promise((r) => setTimeout(r, 300));
const videoPath = fs.readdirSync(OUT_DIR).filter(f => f.endsWith('.webm'))
  .map(f => `${OUT_DIR}/${f}`).sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs)[0];
if (videoPath) {
  fs.renameSync(videoPath, `${OUT_DIR}/s361-uat.webm`);
  console.log('video saved:', `${OUT_DIR}/s361-uat.webm`);
}
console.log('nav_ms_first_load=', navMs);
