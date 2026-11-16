// Browser evidence (headless Chromium via Playwright, lab CA trusted in the NSS store like a user would import it).
// Produces screenshots + the same data DevTools shows (Security tab: protocol/cipher/group; Application > Cookies).
const { chromium } = require('playwright');
const fs = require('fs');
const OUT = process.argv[2] || 'evidence/screenshots';
const B = 'https://localhost';
(async () => {
  const browser = await chromium.launch({ args: ['--no-proxy-server'] });   // trusts the NSS store, no ignoreHTTPSErrors
  const ctx = await browser.newContext({ viewport: { width: 1100, height: 760 }, deviceScaleFactor: 2 });
  const page = await ctx.newPage();
  const cdp = await ctx.newCDPSession(page);
  await cdp.send('Network.enable');
  const sec = [];
  cdp.on('Network.responseReceived', e => { if (e.type === 'Document') sec.push({ url: e.response.url, status: e.response.status, protocol: e.response.protocol, security: e.response.securityDetails, hsts: (e.response.headers['strict-transport-security'] || e.response.headers['Strict-Transport-Security']) }); });
  const log = [];
  const cookies = async (label) => {
    const all = (await cdp.send('Network.getAllCookies')).cookies.filter(c => ['PHPSESSID', 'security'].includes(c.name));
    log.push(`\n[${label}] Application > Cookies (Network.getAllCookies):`);
    for (const c of all) log.push(`  ${c.name.padEnd(10)} value=${c.value}  Secure=${c.secure}  HttpOnly=${c.httpOnly}  SameSite=${c.sameSite || '(none)'}  Session=${c.session}`);
    log.push(`  document.cookie in the page = ${JSON.stringify(await page.evaluate(() => document.cookie))}`);
    return Object.fromEntries(all.map(c => [c.name, c.value]));
  };

  const r0 = await page.goto(`${B}/login.php`);
  await page.screenshot({ path: `${OUT}/C1_browser_login_https.png` });
  const before = await cookies('before login');
  await page.fill('input[name=username]', 'admin');
  await page.fill('input[name=password]', 'password');
  await Promise.all([page.waitForNavigation(), page.click('input[type=submit]')]);
  const after = await cookies('after login');
  log.push(`\nPHPSESSID changed at login: ${before.PHPSESSID !== after.PHPSESSID} (${before.PHPSESSID} -> ${after.PHPSESSID})`);
  await page.screenshot({ path: `${OUT}/E1_browser_logged_in.png` });

  await page.goto(`${B}/security.php`);
  await page.selectOption('select[name=security]', 'low');
  await Promise.all([page.waitForNavigation(), page.click('input[name=seclev_submit]')]);
  await cookies('after choosing Low on security.php');

  await page.goto(`${B}/vulnerabilities/cryptography/`);
  await page.fill('#message', 'Your new password is: Olifant');
  await Promise.all([page.waitForNavigation(), page.click('form[name=xor] input[type=submit]')]);
  const ct = await page.inputValue('textarea#encoded >> nth=0');
  await page.screenshot({ path: `${OUT}/A1_browser_encode.png`, fullPage: true });
  const raw = Buffer.from(ct, 'base64'); const pos = 13 + 'Your new password is: '.length;
  const a = Buffer.from('Olifant'), h = Buffer.from('Hackers');
  for (let i = 0; i < 7; i++) raw[pos + i] ^= a[i] ^ h[i];
  await page.fill('#message', raw.toString('base64'));
  await page.check('#direction_decode');
  await Promise.all([page.waitForNavigation(), page.click('form[name=xor] input[type=submit]')]);
  const warn = await page.textContent('div.warning').catch(() => null);
  log.push(`\nA1 in the browser: Encode -> ${ct}\n  bit-flipped (Olifant->Hackers) and submitted to Decode -> page warning: ${JSON.stringify(warn)}`);
  await page.screenshot({ path: `${OUT}/A1_browser_bitflip_rejected.png`, fullPage: true });

  const s = sec.find(x => x.security) || {};
  const d = s.security || {};
  const head = [
    '### Browser evidence (headless Chromium ' + browser.version() + ', lab CA imported into the NSS trust store, certificate errors NOT ignored)',
    `\nDevTools Security panel equivalent (Network.responseReceived.securityDetails) for ${s.url}:`,
    `  protocol=${d.protocol}  keyExchange=${d.keyExchange || '(TLS 1.3: in group)'}  keyExchangeGroup=${d.keyExchangeGroup}  cipher=${d.cipher}`,
    `  certificate subject=${d.subjectName}  issuer=${d.issuer}  SAN=${JSON.stringify(d.sanList)}`,
    `  validFrom=${new Date(d.validFrom * 1000).toISOString()}  validTo=${new Date(d.validTo * 1000).toISOString()}  certificateTransparencyCompliance=${d.certificateTransparencyCompliance}`,
    `  Strict-Transport-Security: ${s.hsts}`,
    `  main document HTTP status ${r0.status()} (no certificate interstitial)`,
  ];
  fs.writeFileSync(`${OUT}/../E1_C1_browser_devtools.txt`, head.concat(log).join('\n') + '\n');
  console.log(head.concat(log).join('\n'));
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
