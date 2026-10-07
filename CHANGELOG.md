# Changelog

All notable changes to this project are documented here.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-10-07

### Added
- **6 new attack families**: `ssrf` (loopback, private ranges, cloud metadata,
  encoded IPs, `gopher://`/`file://`), `xxe`, `prototype-pollution`,
  `log4shell` (JNDI lookups, including obfuscated ones, CVE-2021-44228),
  `xpath-injection` and `unicode-evasion` (null bytes, Trojan Source bidi
  overrides).
- **Evasion resistance**: input is also scanned after URL decoding (up to 3
  rounds), HTML entity decoding, `\uXXXX`/`\xXX` unescaping, NFKC Unicode
  normalization, SQL inline-comment stripping (`UN/**/ION`) and whitespace
  collapsing. Threats found only in a decoded view carry `evasion: true`.
  Disable with `createScanner({ decode: false })`.
- `scanDeep(obj)` to scan nested objects/arrays, including keys, with the
  offending `path` for each threat.
- `middleware()` for Express/Connect/Fastify-style servers (blocks with 400).
- TypeScript definitions (`index.d.ts`).
- Many new patterns in existing families: error-based and fingerprinting SQLi
  (`extractvalue`, `@@version`, `ORDER BY n--`, hex/`CHAR()` payloads, stacked
  `EXEC`), shell obfuscation (`${IFS}`, `/bin/sh`, download-and-execute,
  reverse shells), `....//` and `..;/` traversal, `/proc/self`, null-byte
  truncation, MongoDB `$function`/`user[$ne]=`, LDAP wildcard filters,
  Jinja2/SpEL sandbox escapes, HTTP response splitting and email header
  injection, `javascript:`/`vbscript:`/`srcdoc` and more XSS vectors.
- README redesign with generated SVG examples (`npm run assets`).
- CI workflow testing Node 20, 22 and 24.

### Changed
- Minimum Node.js version is now 20 (Node 18 is end-of-life).
- Publish workflow runs on Node 24.

## [1.0.0] - 2026-09-17

Initial public release as `sqli-guard`.

### Added
- Multi-threat scanner: `sql-injection`, `xss`, `command-injection`,
  `path-traversal`, `nosql-injection`, `ldap-injection`, `template-injection`
  (SSTI) and `crlf-injection`.
- `scan(value)` returns detail `{ safe, value, threats[] }` with `type`,
  `severity` and `match` per threat.
- `isSafe(value)` as the inverse of `hasSql`.
- Custom sub-functions / validators: `addValidator`, `removeValidator`,
  `listValidators` (accept a RegExp, `{ pattern, patterns, severity, message }`,
  or a `test` function).
- `createScanner(options)` with isolated instances and `lang` (`en`/`es`),
  `categories` and `minSeverity` options.
- Bilingual messages (English / Spanish), English by default.
- Test suite with `node --test` (`npm test`).
- `LICENSE`, `CHANGELOG.md` files and packaging fields (`files`, `engines`).

### Notes
- Detection matches **attack syntax** instead of bare words, drastically
  reducing false positives.
- This library was previously developed and released under the names
  `sql-injections` and `injectguard`; those npm names became unusable due to
  registry restrictions on previously unpublished names, so the project
  continues here as `sqli-guard` with the same codebase and behavior.
