// s370 demo readiness gate run. Headed Chromium (Playwright's own browser),
// fresh profile, 1440x900. Exact live URL, presenter click order.
// Usage: LABEL=warm|cold node s370-gate-run.mjs
import { chromium } from 'playwright';
import fs from 'node:fs';

const URL = 'https://northwind-vaid-4gdx3hbasa-ew.a.run.app/';
const LABEL = process.env.LABEL || 'warm';
const OUT_DIR = `/Users/allansmeyatsky/solara/lz2026/s370-uat`;
fs.mkdirSync(OUT_DIR, { recursive: true });
const SIZE = { width: 1440, height: 900 };

const consoleMsgs = [];
const netFailures = [];

const context = await chromium.launchPersistentContext(`/tmp/s370-${LABEL}-profile-${Date.now()}`, {
  headless: false,
  viewport: SIZE,
  recordVideo: { dir: OUT_DIR, size: SIZE },
});
const page = await context.newPage();
page.setDefaultTimeout(60000);
page.on('console', msg => {
  if (msg.type() === 'error' || msg.type() === 'warning') consoleMsgs.push(`[${msg.type()}] ${msg.text()}`);
});
page.on('requestfailed', req => netFailures.push(`FAILED ${req.method()} ${req.url()} :: ${req.failure()?.errorText}`));
page.on('response', res => {
  if (res.status() >= 400) netFailures.push(`HTTP ${res.status()} ${res.request().method()} ${res.url()}`);
});

let shot = 0;
async function snap(name) {
  shot++;
  const n = String(shot).padStart(2, '0');
  await page.screenshot({ path: `${OUT_DIR}/${LABEL}-${n}-${name}.png`, fullPage: true });
}

console.log(`[${LABEL}] navigating to ${URL}`);
await page.goto(URL, { waitUntil: 'load' });
await page.waitForSelector('.scenario-btn[data-scenario="allowed"]');
const buildMarker = await page.locator('#buildMarker').textContent().catch(() => 'MISSING');
console.log(`[${LABEL}] build marker: ${buildMarker}`);
await snap('page-loaded');

// Scenario 1: allowed job
await page.click('.scenario-btn[data-scenario="allowed"]');
await page.waitForTimeout(1200);
await snap('scenario1-allowed');

// Scenario 2: outside scope
await page.click('.scenario-btn[data-scenario="outside_scope"]');
await page.waitForTimeout(1200);
await snap('scenario2-outside-scope');

// Scenario 3: delegation (the changed scenario) - simple view
await page.click('.scenario-btn[data-scenario="delegation"]');
await page.waitForTimeout(1800);
await snap('scenario3-delegation-simple');

// Scenario 3 technical detail: this is the key evidence for the s370 change
await page.locator('#techDetails summary').click();
await page.waitForTimeout(400);
await snap('scenario3-delegation-technical-full');

const structuredBoxes = await page.locator('.credential-box').evaluateAll(nodes => nodes.map(n => {
  const title = n.querySelector('div > b')?.textContent || '';
  const dts = [...n.querySelectorAll('dt')].map(d => d.textContent);
  const dds = [...n.querySelectorAll('dd')].map(d => d.textContent);
  const fields = {};
  dts.forEach((k, i) => { fields[k] = dds[i]; });
  return { title, fields };
}));
const rootBox = structuredBoxes.find(b => b.title.includes('Depth-0 root credential'));
const d1Box = structuredBoxes.find(b => b.title.includes('Depth-1 delegate credential'));
const rootIdx = structuredBoxes.indexOf(rootBox);
const d1Idx = structuredBoxes.indexOf(d1Box);
const rootBoxPresent = !!rootBox && !('Handed off from' in rootBox.fields);
const depth1ChainsToRoot = !!(rootBox && d1Box && rootIdx < d1Idx
  && d1Box.fields['Handed off from'] && rootBox.fields['Credential (this badge)']
  && d1Box.fields['Handed off from'].includes(rootBox.fields['Credential (this badge)']));
console.log(`[${LABEL}] root box fields:`, JSON.stringify(rootBox?.fields));
console.log(`[${LABEL}] depth-1 box fields:`, JSON.stringify(d1Box?.fields));
const bannerTexts = await page.locator('.decision-banner').allTextContents();
const bodyHtml = await page.content();
const wrongAttribution = bodyHtml.includes("Northwind's rules only allow one hand-off") || bodyHtml.includes('Harbor only accepts one hand-off');
const rightAttribution = bodyHtml.includes("Harbor's own rules only allow one hand-off") && bodyHtml.includes("Harbor's own policy only accepts one hand-off");
const emdash = bodyHtml.includes('—');

console.log(`[${LABEL}] rootBoxPresent=${rootBoxPresent} depth1ChainsToRoot=${depth1ChainsToRoot}`);
console.log(`[${LABEL}] banners: ${bannerTexts.join(' | ')}`);
console.log(`[${LABEL}] wrongAttributionStillPresent=${wrongAttribution} rightAttributionPresent=${rightAttribution} emdash=${emdash}`);

// Scenario 4: revocation (lower cache window first so it completes quickly)
await page.evaluate(() => {
  const el = document.getElementById('cacheWindow');
  el.value = '1';
  el.dispatchEvent(new Event('input'));
});
await page.waitForTimeout(200);
await snap('cache-window-set-1s');
await page.click('.scenario-btn[data-scenario="revocation"]');
await page.waitForTimeout(1500);
await snap('scenario4-revocation-before-recheck');
await page.waitForTimeout(2500);
await snap('scenario4-revocation-after-recheck');

// Scenario 5: tamper
await page.click('.scenario-btn[data-scenario="tamper"]');
await page.waitForTimeout(1500);
await snap('scenario5-tamper');

// Scenario 6: same agent, new badge
await page.click('.scenario-btn[data-scenario="reissue"]');
await page.waitForTimeout(1500);
await snap('scenario6-same-agent-new-badge');

// Off-script: reload mid-flow
await page.click('.scenario-btn[data-scenario="delegation"]');
await page.waitForTimeout(300);
await page.reload({ waitUntil: 'load' });
await page.waitForTimeout(800);
await snap('offscript-reload-mid-flow');
const buildMarkerAfterReload = await page.locator('#buildMarker').textContent().catch(() => 'MISSING');
console.log(`[${LABEL}] build marker after normal reload: ${buildMarkerAfterReload}`);

// Off-script: back button
await page.click('.scenario-btn[data-scenario="allowed"]');
await page.waitForTimeout(800);
await page.goBack().catch(() => {});
await page.waitForTimeout(800);
const urlAfterBack = page.url();
const landedBlank = urlAfterBack === 'about:blank' || !(await page.locator('.scenario-btn').first().isVisible().catch(() => false));
console.log(`[${LABEL}] url after back button: ${urlAfterBack}, landed on blank/broken state: ${landedBlank}`);
await snap('offscript-back-button');

// Off-script: wrong click (click cancel badge with no badge issued)
if (landedBlank) {
  await page.goto(URL, { waitUntil: 'load' });
  await page.waitForSelector('.scenario-btn[data-scenario="allowed"]');
}
const cancelDisabled = await page.locator('#cancelBadgeBtn').isDisabled();
console.log(`[${LABEL}] cancel-badge-button disabled when no badge issued: ${cancelDisabled}`);
await snap('offscript-wrong-click-state');

await page.waitForTimeout(500);
await context.close();

fs.writeFileSync(`${OUT_DIR}/${LABEL}-console.log`, consoleMsgs.join('\n') || '(no console errors/warnings)');
fs.writeFileSync(`${OUT_DIR}/${LABEL}-network-failures.log`, netFailures.join('\n') || '(no failed requests)');
console.log(`[${LABEL}] console issues: ${consoleMsgs.length}, network failures/4xx/5xx: ${netFailures.length}`);
console.log(`[${LABEL}] DONE`);
