# Changelog

All notable changes to this project are documented here.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/).

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
