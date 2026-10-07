'use strict';

const builtInDetectors = require('./detectors');

const SEVERITY_RANK = { low: 1, medium: 2, high: 3 };

/**
 * Returns the first match of `value` against a list of regex patterns.
 */
function firstMatch(value, patterns) {
  for (const pattern of patterns) {
    // Clone without the global flag to avoid shared lastIndex state.
    const re = new RegExp(pattern.source, pattern.flags.replace('g', ''));
    const m = re.exec(value);
    if (m) {
      return m[0];
    }
  }
  return null;
}

/**
 * Normalizes a custom validator into the internal detector shape.
 *
 * Accepted forms:
 *   addValidator('name', /regex/)
 *   addValidator('name', { pattern: /regex/, severity, message, type })
 *   addValidator('name', { patterns: [/a/, /b/], ... })
 *   addValidator('name', { test: (value) => boolean | string, ... })
 */
function normalizeValidator(name, spec) {
  if (spec instanceof RegExp) {
    spec = { pattern: spec };
  }
  if (typeof spec === 'function') {
    spec = { test: spec };
  }
  if (!spec || typeof spec !== 'object') {
    throw new TypeError(
      `addValidator("${name}"): expected a RegExp, a function, or a config object.`
    );
  }

  const patterns = spec.patterns || (spec.pattern ? [spec.pattern] : []);
  const hasTest = typeof spec.test === 'function';

  if (patterns.length === 0 && !hasTest) {
    throw new TypeError(
      `addValidator("${name}"): must include "pattern", "patterns", or "test".`
    );
  }

  const severity = spec.severity || 'medium';
  if (!SEVERITY_RANK[severity]) {
    throw new TypeError(
      `addValidator("${name}"): invalid severity "${severity}" (use low|medium|high).`
    );
  }

  let message = spec.message || { en: `Pattern "${name}" matched.`, es: `Patrón "${name}" detectado.` };
  if (typeof message === 'string') {
    message = { en: message, es: message };
  }

  return {
    type: spec.type || name,
    name,
    severity,
    message,
    patterns,
    test: hasTest ? spec.test : null,
    custom: true
  };
}

const NAMED_ENTITIES = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'", colon: ':', tab: '\t', newline: '\n', lpar: '(', rpar: ')', sol: '/', bsol: '\\' };

/**
 * Builds the extra "decoded" views of a value so encoded attacks
 * (%27%20OR%201%3D1, &#x3C;script&#x3E;, UN/**\/ION, fullwidth ＳＥＬＥＣＴ)
 * are caught by the same detectors as their plain-text form.
 */
function decodeVariants(value) {
  let decoded = value;
  // Up to 3 rounds handles double/triple URL encoding.
  for (let i = 0; i < 3; i++) {
    let next = decoded;
    try {
      next = decodeURIComponent(next.replace(/%(?![0-9a-f]{2})/gi, '%25'));
    } catch (_) {
      next = next.replace(/%([0-9a-f]{2})/gi, (m, h) => String.fromCharCode(parseInt(h, 16)));
    }
    next = next
      .replace(/&#x([0-9a-f]+);?/gi, (m, h) => safeFromCodePoint(parseInt(h, 16), m))
      .replace(/&#(\d+);?/g, (m, d) => safeFromCodePoint(parseInt(d, 10), m))
      .replace(/&([a-z]+);/gi, (m, n) => NAMED_ENTITIES[n.toLowerCase()] || m)
      .replace(/\\u([0-9a-f]{4})/gi, (m, h) => String.fromCharCode(parseInt(h, 16)))
      .replace(/\\x([0-9a-f]{2})/gi, (m, h) => String.fromCharCode(parseInt(h, 16)));
    if (next === decoded) break;
    decoded = next;
  }
  decoded = decoded.normalize('NFKC');

  const views = new Set();
  if (decoded !== value) views.add(decoded);

  // Inline-comment obfuscation: UN/**/ION SEL/**/ECT  (MySQL /*!50000 ... */ too)
  const noComments = decoded.replace(/\/\*!?\d*[\s\S]*?\*\//g, ' ');
  const glued = decoded.replace(/\/\*[\s\S]*?\*\//g, '');
  if (noComments !== decoded) views.add(noComments);
  if (glued !== decoded) views.add(glued);

  // Collapse whitespace tricks: tabs, newlines, vertical tab, NBSP, '+' as space
  const spaced = decoded.replace(/[\t\n\r\f\v\u00a0+]+/g, ' ');
  if (spaced !== decoded) views.add(spaced);

  return [...views].filter((v) => v !== value);
}

function safeFromCodePoint(cp, fallback) {
  try {
    return String.fromCodePoint(cp);
  } catch (_) {
    return fallback;
  }
}

class Scanner {
  /**
   * @param {object} [options]
   * @param {'en'|'es'} [options.lang='en']   Message language.
   * @param {string[]}  [options.categories]  Limit built-in detectors to these types.
   * @param {'low'|'medium'|'high'} [options.minSeverity='low'] Minimum reported severity.
   * @param {boolean}   [options.decode=true] Also scan URL/HTML-entity/Unicode/comment-decoded
   *                                          views of the input to catch evasion.
   */
  constructor(options = {}) {
    this.lang = options.lang === 'es' ? 'es' : 'en';
    this.minSeverity = options.minSeverity || 'low';
    this.decode = options.decode !== false;
    this.customValidators = new Map();

    const categories = options.categories;
    this.detectors = Array.isArray(categories)
      ? builtInDetectors.filter((d) => categories.includes(d.type))
      : builtInDetectors;
  }

  /**
   * Register a custom sub-function / validator.
   * @returns {Scanner} this (chainable)
   */
  addValidator(name, spec) {
    if (typeof name !== 'string' || !name.trim()) {
      throw new TypeError('addValidator: name must be a non-empty string.');
    }
    this.customValidators.set(name, normalizeValidator(name, spec));
    return this;
  }

  /** Remove a custom validator. */
  removeValidator(name) {
    return this.customValidators.delete(name);
  }

  /** List custom validator names. */
  listValidators() {
    return [...this.customValidators.keys()];
  }

  _runDetector(detector, value, variants) {
    const threat = this._runDetectorOn(detector, value);
    if (threat) return threat;
    for (const view of variants) {
      const t = this._runDetectorOn(detector, view);
      if (t) {
        t.evasion = true; // only visible after decoding
        return t;
      }
    }
    return null;
  }

  _runDetectorOn(detector, value) {
    let match = null;

    if (detector.patterns && detector.patterns.length) {
      match = firstMatch(value, detector.patterns);
    }
    if (!match && typeof detector.test === 'function') {
      const result = detector.test(value);
      if (result) {
        match = typeof result === 'string' ? result : value;
      }
    }
    if (!match) {
      return null;
    }

    return {
      type: detector.type,
      severity: detector.severity,
      message: detector.message[this.lang] || detector.message.en,
      match
    };
  }

  /**
   * Scan a value and return the details of any threats found.
   * @returns {{ safe: boolean, value: any, threats: Array }}
   */
  scan(value) {
    // Non-string values (numbers, booleans, null, undefined) cannot inject.
    if (typeof value !== 'string') {
      return { safe: true, value, threats: [] };
    }

    const minRank = SEVERITY_RANK[this.minSeverity] || 1;
    const threats = [];
    const variants = this.decode ? decodeVariants(value) : [];
    const allDetectors = [...this.detectors, ...this.customValidators.values()];

    for (const detector of allDetectors) {
      if (SEVERITY_RANK[detector.severity] < minRank) {
        continue;
      }
      const threat = this._runDetector(detector, value, variants);
      if (threat) {
        threats.push(threat);
      }
    }

    // Sorted by severity, highest first.
    threats.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);

    return { safe: threats.length === 0, value, threats };
  }

  /**
   * Recursively scan objects/arrays (e.g. `req.body`, `req.query`).
   * Keys are scanned too (prototype pollution, NoSQL operators).
   * @returns {{ safe: boolean, threats: Array<{path: string, key?: boolean}>}}
   */
  scanDeep(input, maxDepth = 20) {
    const threats = [];
    const seen = new WeakSet();
    const walk = (node, path, depth) => {
      if (node && typeof node === 'object') {
        if (seen.has(node) || depth > maxDepth) return;
        seen.add(node);
        for (const key of Object.keys(node)) {
          const childPath = path ? `${path}.${key}` : key;
          const keyScan = this.scan(key);
          for (const t of keyScan.threats) threats.push({ ...t, path: childPath, key: true });
          walk(node[key], childPath, depth + 1);
        }
      } else if (typeof node === 'string') {
        for (const t of this.scan(node).threats) threats.push({ ...t, path });
      }
    };
    walk(input, '', 0);
    return { safe: threats.length === 0, threats };
  }

  /**
   * Express/Connect/Fastify-style middleware. Rejects the request with
   * HTTP 400 when body, query or params contain a threat.
   * @param {object} [opts]
   * @param {string[]} [opts.sources=['body','query','params']]
   * @param {number}   [opts.status=400]
   * @param {Function} [opts.onThreat] (req, res, threats) => void, replaces the default response.
   */
  middleware(opts = {}) {
    const sources = opts.sources || ['body', 'query', 'params'];
    const status = opts.status || 400;
    return (req, res, next) => {
      const threats = [];
      for (const source of sources) {
        if (req[source] == null) continue;
        for (const t of this.scanDeep(req[source]).threats) {
          threats.push({ ...t, path: `${source}.${t.path}`.replace(/\.$/, '') });
        }
      }
      if (threats.length === 0) return next();
      if (typeof opts.onThreat === 'function') return opts.onThreat(req, res, threats);
      const body = {
        error: 'Malicious input detected',
        threats: threats.map(({ type, severity, path }) => ({ type, severity, path }))
      };
      if (typeof res.status === 'function' && typeof res.json === 'function') {
        return res.status(status).json(body);
      }
      res.statusCode = status;
      res.setHeader('Content-Type', 'application/json');
      return res.end(JSON.stringify(body));
    };
  }

  /** true if the value is safe. */
  isSafe(value) {
    return this.scan(value).safe;
  }

  /**
   * Backward compatible: true if ANY threat is detected.
   * (Originally SQL only; now covers every category + custom validators.)
   */
  hasSql(value) {
    return !this.isSafe(value);
  }
}

module.exports = { Scanner, normalizeValidator };
