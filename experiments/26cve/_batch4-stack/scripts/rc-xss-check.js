#!/usr/bin/env node
/* Roundcube stored-XSS harness: login, open the newest INBOX message, look for execution. */
const path = require('path');
const PW = require(path.join(process.env.NODE_ROOT, 'playwright-core'));
const CHROME = process.env.CHROME;

async function check(port, label) {
  const res = { label, port, logged_in: false, executed: false, marker: null, console: [] };
  const browser = await PW.chromium.launch({ headless: true, executablePath: CHROME, args: ['--no-sandbox'] });
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  page.on('console', m => res.console.push(m.text()));
  const base = `http://127.0.0.1:${port}`;
  await page.goto(`${base}/?_task=login`, { waitUntil: 'domcontentloaded' }).catch(()=>{});
  await page.fill('input[name="_user"]', 'test').catch(()=>{});
  await page.fill('input[name="_pass"]', 'test').catch(()=>{});
  await page.click('#rcmloginsubmit').catch(()=>{});
  await page.waitForLoadState('networkidle').catch(()=>{});
  res.logged_in = !page.url().includes('_task=login');
  // open newest message
  await page.goto(`${base}/?_task=mail&_mbox=INBOX`, { waitUntil: 'load' }).catch(()=>{});
  const rows = await page.$$('tr.message');
  if (rows.length) { await rows[0].click().catch(()=>{}); await page.waitForTimeout(3000); }
  // scan frames for the marker / executing elements
  for (const f of page.frames()) {
    try { const m = await f.evaluate(() => (typeof window.__rq !== 'undefined') ? window.__rq : null); if (m === 1) { res.executed = true; res.marker = m; } } catch(e){}
  }
  try { const m = await page.evaluate(() => (typeof window.__rq !== 'undefined') ? window.__rq : null); if (m === 1) { res.executed = true; res.marker = m; } } catch(e){}
  await browser.close();
  return res;
}
(async () => {
  console.log(JSON.stringify(await check(process.env.P, process.env.LBL || 'rc'), null, 2));
})();
