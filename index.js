'use strict';

/**
 * sqli-guard
 * ------------------------------------------------------------------
 * Zero-dependency library to detect text-based injections /
 * vulnerabilities (SQL, XSS, command, path traversal, NoSQL, LDAP,
 * template/SSTI, CRLF) with a single call, extensible with your own
 * custom sub-functions.
 *
 * Quick use:
 *   const sqliGuard = require('sqli-guard');
 *   sqliGuard.hasSql("SELECT * FROM users");   // true
 *   sqliGuard.hasSql("Your name");             // false
 *   sqliGuard.scan("' OR 1=1 --");             // { safe:false, threats:[...] }
 *   sqliGuard.addValidator('no-emoji', { pattern: /\p{Emoji}/u });
 */

const { Scanner } = require('./lib/scanner');
const detectors = require('./lib/detectors');

// Shared default instance.
const defaultScanner = new Scanner();

/**
 * Create an isolated scanner with its own config and validators.
 * @param {object} [options] See Scanner.
 * @returns {Scanner}
 */
function createScanner(options) {
  return new Scanner(options);
}

module.exports = defaultScanner;

// Extra API on the default instance.
module.exports.createScanner = createScanner;
module.exports.Scanner = Scanner;
module.exports.detectors = detectors;
