'use strict';

/**
 * Built-in detectors for injection / text-based vulnerability patterns.
 *
 * Each detector:
 *   type:      category id
 *   severity:  'low' | 'medium' | 'high'
 *   message:   { en, es } human-readable description
 *   patterns:  RegExp[] — attack *syntax*, NOT bare words
 *              (matching real syntax keeps false positives low)
 */

const detectors = [
  {
    type: 'sql-injection',
    severity: 'high',
    message: {
      en: 'Possible SQL injection detected.',
      es: 'Posible inyección SQL detectada.'
    },
    patterns: [
      // Tautologies: ' OR 1=1 , OR '1'='1'
      /(['"`]?\s*)\b(or|and)\b(\s*['"`]?\s*)\d+\s*=\s*\d+/i,
      /['"`]\s*\b(or|and)\b\s*['"`]?\s*['"`\d]/i,
      // UNION SELECT
      /\bunion\b\s+(all\s+)?\bselect\b/i,
      // SELECT ... FROM
      /\bselect\b[\s\S]{1,200}?\bfrom\b/i,
      // Stacked queries / dangerous DDL-DML: ; DROP, ; DELETE ...
      /(^|;)\s*\b(drop|truncate|alter|create|insert|update|delete)\b\s+(table|into|from|database)?/i,
      /\b(drop|truncate)\s+table\b/i,
      // SQL comments after a quote / closing token: '--  ';#  '/*
      /['"`)\s];?\s*(--|#|\/\*)/,
      // Time-based blind
      /\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(/i,
      // Sensitive functions and objects
      /\b(load_file|into\s+(out|dump)file|information_schema|xp_cmdshell|sysobjects|sqlite_master|pg_catalog|pg_read_file|utl_inaddr|utl_http|dbms_\w+)\b/i,
      // Error-based and fingerprinting: extractvalue(), updatexml(), @@version
      /\b(extractvalue|updatexml|group_concat|string_agg|json_extract)\s*\(/i,
      /@@(version|datadir|hostname|servername|basedir)\b/i,
      // Boolean / operator-based tautologies: ' || 1=1, ' && 'a'='a
      /['"`)]\s*(\|\||&&)\s*['"`\d(]/,
      /\b(or|and)\b\s+\d+\s*(like|between|<>|!=|<=|>=)/i,
      // Column enumeration: ORDER BY 7--, HAVING 1=1, GROUP BY x HAVING
      /\b(order|group)\s+by\s+\d+\s*(--|#|\/\*|;|$)/i,
      /\bhaving\b\s+\d+\s*=\s*\d+/i,
      // Hex / CHAR() encoded payloads
      /\b0x[0-9a-f]{8,}\b/i,
      /\bchar\s*\(\s*\d+\s*(,\s*\d+\s*){2,}\)/i,
      // Stacked EXEC / second-order helpers
      /;\s*(exec|execute|declare|shutdown|grant|revoke)\b/i,
      // Conditional blind: IF(1=1,SLEEP(5),0), CASE WHEN ... THEN
      /\b(case\s+when\b|if\s*\()[^)]{1,80}?(=|<|>)[^)]{1,80}?\b(then|,)/i
    ]
  },
  {
    type: 'xss',
    severity: 'high',
    message: {
      en: 'Possible XSS (malicious script/HTML) detected.',
      es: 'Posible XSS (script/HTML malicioso) detectado.'
    },
    patterns: [
      /<\s*script[\s>]/i,
      /<\s*\/\s*script\s*>/i,
      /javascript\s*:/i,
      /\bon\w+\s*=\s*['"]?[^'">\s]/i, // onerror= onload= onclick=
      /<\s*(iframe|img|svg|body|object|embed|video|audio)[^>]*\b(on\w+|src)\s*=/i,
      /\b(document\.cookie|document\.write|window\.location|eval\s*\()/i,
      /data\s*:\s*text\/html/i,
      /\b(vbscript|livescript)\s*:/i,
      /\b(alert|prompt|confirm)(\(|`)/i,
      /\b(srcdoc|formaction|xlink:href)\s*=/i,
      /<\s*(meta[^>]+http-equiv|base\s+href|link[^>]+rel\s*=\s*['"]?import)/i,
      /<\s*(svg|math|details|marquee|style|form|input|button|a|div)\b[^>]*[\/\s'"]on\w+\s*=/i,
      /\bexpression\s*\(|-moz-binding|behavior\s*:/i,
      /<\s*(iframe|object|embed|applet|frame)\b/i
    ]
  },
  {
    type: 'command-injection',
    severity: 'high',
    message: {
      en: 'Possible OS command injection detected.',
      es: 'Posible inyección de comandos del sistema detectada.'
    },
    patterns: [
      /[;&|]\s*\b(ls|cat|rm|mv|cp|wget|curl|nc|bash|sh|zsh|powershell|whoami|id|uname|ping|chmod|chown|kill)\b/i,
      /\$\([^)]{1,200}\)/,          // $(command)
      /`[^`]{1,200}`/,              // `command`
      /\|\|\s*\S/,                  // || cmd
      /&&\s*\S/,                    // && cmd
      />\s*\/dev\/(tcp|null)/i,
      // Newline-separated commands (also URL-encoded) and IFS tricks
      /(\n|\r|%0a|%0d)\s*\b(ls|cat|rm|wget|curl|nc|bash|sh|whoami|id|uname|ping)\b/i,
      /\$\{?IFS\}?/,
      // Interpreters / shells / download-and-exec
      /\b(\/bin\/(ba|z|da|k)?sh|cmd(\.exe)?\s+\/c|powershell(\.exe)?\s+(-\w+\s+)*-(e|enc|encodedcommand|c|command)\b)/i,
      /\b(python[23]?|perl|ruby|php|node|lua)\s+-[a-z]*[ec]\b/i,
      /\b(curl|wget)\b[^|;&]{1,200}\|\s*(ba|z)?sh\b/i,
      /\b(nc|ncat|netcat)\b\s+(-\w+\s+)*\S+\s+\d{2,5}\b/i,
      /\bbase64\s+(-d|--decode)\b/i,
      // Shell quoting/escape obfuscation: w'h'oami, who\ami
      /\b(w['"\\]*h['"\\]*o['"\\]*a['"\\]*m['"\\]*i|c['"\\]*a['"\\]*t\s+\/etc)/i
    ]
  },
  {
    type: 'path-traversal',
    severity: 'medium',
    message: {
      en: 'Possible path traversal (unauthorized path access).',
      es: 'Posible path traversal (acceso a rutas no permitidas).'
    },
    patterns: [
      /\.\.[\/\\]/,                 // ../ or ..\
      /%2e%2e(%2f|%5c)/i,           // encoded ../
      /\/etc\/(passwd|shadow|hosts)/i,
      /(^|[\s"'=])[a-z]:\\(windows|users|boot)/i,
      /\.\.%2f/i,
      /\.\.\.\.[\/\\]{1,2}/,        // ....// filter bypass
      /\.\.;[\/\\]/,                // ..;/ (Tomcat/Spring)
      /%c0%af|%c1%9c|%252e%252e/i,   // overlong UTF-8 / double encoding
      /\/proc\/self\/(environ|cmdline|fd|cwd)/i,
      /\b(boot\.ini|win\.ini|web-inf\/web\.xml|\.git\/config|\.ssh\/id_rsa|\.aws\/credentials)/i,
      /(^|[\/\\])\.env(\.\w+)?($|[?#\s])/i,
      /\.\w{2,5}(%00|\0)/,            // null-byte extension truncation
      /\bfile:\/\/\//i
    ]
  },
  {
    type: 'nosql-injection',
    severity: 'high',
    message: {
      en: 'Possible NoSQL (MongoDB) injection detected.',
      es: 'Posible inyección NoSQL (MongoDB) detectada.'
    },
    patterns: [
      /[$]\b(where|ne|gt|gte|lt|lte|in|nin|or|and|not|regex|exists|expr)\b/i,
      /\{\s*['"]?\s*[$]\w+/,        // { "$gt": ... }
      /\.\s*(find|findOne|aggregate)\s*\(\s*\{/i,
      /[$](function|accumulator|lookup|merge|out|graphLookup|unionWith)\b/,
      /\[\s*[$]\w+\s*\]\s*=/,       // user[$ne]=x  (query-string operator injection)
      /['"];?\s*return\s+(true|1|false)\b/i,
      /\bthis\.\w+\s*(==|!=|\.match|\.indexOf|\.length)/,
      /\|\|\s*['"]?1['"]?\s*==\s*['"]?1/
    ]
  },
  {
    type: 'ldap-injection',
    severity: 'medium',
    message: {
      en: 'Possible LDAP injection detected.',
      es: 'Posible inyección LDAP detectada.'
    },
    patterns: [
      /\*\s*\)\s*\(/,               // *)(
      /\)\s*[|&]\s*\(/,             // )(|( or )(&(
      /\(\s*[|&!]\s*\(/,
      /\(\s*(objectclass|cn|uid|sn|mail|samaccountname|userpassword)\s*=\s*\*\s*\)/i,
      /\*\)\(\w+=\*/,
      /\)\s*\(\s*\w+\s*=\s*\*/
    ]
  },
  {
    type: 'template-injection',
    severity: 'medium',
    message: {
      en: 'Possible Server-Side Template Injection (SSTI) detected.',
      es: 'Posible inyección de plantillas (SSTI) detectada.'
    },
    patterns: [
      /\{\{[\s\S]{1,200}?\}\}/,     // {{ 7*7 }}
      /\{%[\s\S]{1,200}?%\}/,       // {% ... %}
      /<%[\s\S]{1,200}?%>/,         // <% ... %>
      /[#$]\{[\s\S]{1,200}?\}/,     // ${...} #{...}
      /__(class|mro|subclasses|globals|builtins|import|bases|init)__/,  // Jinja2 / Python sandbox escape
      /\bT\s*\(\s*java\.lang\.\w+\s*\)/i,   // Spring SpEL
      /\.constructor\s*\.\s*constructor\s*\(/,   // JS sandbox escape
      /\b(freemarker\.template\.utility\.Execute|java\.lang\.Runtime|ProcessBuilder)\b/,
      /\b(lipsum|cycler|joiner|namespace)\s*\.\s*__/i
    ]
  },
  {
    type: 'crlf-injection',
    severity: 'medium',
    message: {
      en: 'Possible CRLF / HTTP header injection detected.',
      es: 'Posible inyección CRLF / de cabeceras HTTP detectada.'
    },
    patterns: [
      /(\r\n|\r|\n|%0d%0a|%0a|%0d)\s*(set-cookie|location|content-length|content-type|x-forwarded-\w+|host|refresh)\s*:/i,
      // HTTP response splitting
      /(\r\n|\n|%0d%0a|%0a)\s*HTTP\/\d(\.\d)?\s+\d{3}/i,
      // SMTP / email header injection
      /(\r\n|\r|\n|%0d%0a|%0a|%0d)\s*(bcc|cc|to|from|subject|mime-version)\s*:/i
    ]
  },
  {
    type: 'ssrf',
    severity: 'high',
    message: {
      en: 'Possible SSRF (request to internal or cloud-metadata address) detected.',
      es: 'Posible SSRF (petición a dirección interna o de metadatos cloud) detectada.'
    },
    patterns: [
      // Loopback, private ranges, link-local and cloud metadata endpoints
      /\b(https?|ftp):\/\/([^\/\s@]*@)?(localhost|127(\.\d{1,3}){3}|0\.0\.0\.0|0(\.0){0,2}|10(\.\d{1,3}){3}|192\.168(\.\d{1,3}){2}|172\.(1[6-9]|2\d|3[01])(\.\d{1,3}){2}|169\.254(\.\d{1,3}){2}|\[(::1?|::ffff:[^\]]*|f[cd][0-9a-f:]*)\]|metadata\.google\.internal|[^\/\s]*\.internal)(?![\w.-])/i,
      // Decimal / hex / octal encoded IPs: http://2130706433, http://0x7f000001
      /\bhttps?:\/\/(0x[0-9a-f]{6,8}|\d{8,10})(?![\w.])/i,
      // Non-HTTP schemes used to reach internals
      /\b(gopher|dict|ldap|tftp|sftp|jar|netdoc|php|expect|phar|ogg):\/\/\S/i,
      /\bfile:\/\/\//i
    ]
  },
  {
    type: 'xxe',
    severity: 'high',
    message: {
      en: 'Possible XXE (XML External Entity) injection detected.',
      es: 'Posible inyección XXE (entidad externa XML) detectada.'
    },
    patterns: [
      /<!ENTITY\b/i,
      /<!DOCTYPE\b[^>]*\[/i,
      /\bSYSTEM\s+['"](file|https?|ftp|php|expect):/i,
      /<\?xml-stylesheet\b/i,
      /<xi:include\b/i
    ]
  },
  {
    type: 'prototype-pollution',
    severity: 'high',
    message: {
      en: 'Possible prototype pollution payload detected.',
      es: 'Posible payload de contaminación de prototipos detectado.'
    },
    patterns: [
      /__proto__/i,
      /\bconstructor\s*(\.|\[\s*['"]?)\s*prototype\b/i,
      /\[\s*['"]?(__proto__|constructor|prototype)['"]?\s*\]/i
    ]
  },
  {
    type: 'log4shell',
    severity: 'high',
    message: {
      en: 'Possible JNDI / Log4Shell lookup (CVE-2021-44228) detected.',
      es: 'Posible lookup JNDI / Log4Shell (CVE-2021-44228) detectado.'
    },
    patterns: [
      /\$\{\s*jndi\s*:/i,
      // Obfuscated: ${${lower:j}ndi:...}, ${${::-j}${::-n}di:...}
      /\$\{(?:[^{}]|\$\{[^{}]*\})*?(?:j|\$\{[^{}]*\})(?:[^{}]|\$\{[^{}]*\}){0,40}?n(?:[^{}]|\$\{[^{}]*\}){0,40}?d(?:[^{}]|\$\{[^{}]*\}){0,40}?i(?:[^{}]|\$\{[^{}]*\}){0,20}?:\s*(ldaps?|rmi|dns|iiop|https?|corba|nis)/i,
      /\$\{\s*(env|sys|java|ctx|main|bundle|k8s|docker|log4j|date)\s*:/i,
      /\$\{\s*(lower|upper)\s*:[^}]*\}/i
    ]
  },
  {
    type: 'xpath-injection',
    severity: 'medium',
    message: {
      en: 'Possible XPath injection detected.',
      es: 'Posible inyección XPath detectada.'
    },
    patterns: [
      /['"]\s*\]\s*\/\/?\s*(\*|\w+)/,
      /\/\/\*\s*(\[|$|\/)/,
      /\b(count|string-length|substring|name|local-name|namespace-uri|normalize-space|starts-with|contains)\s*\(\s*(\/|\.\/|\.\.|name\s*\()/i,
      /\btext\s*\(\s*\)\s*=/i,
      /['"]\s*or\s+['"]?\w*['"]?\s*=\s*['"]?\w*['"]?\s*or\s+['"]/i
    ]
  },
  {
    type: 'unicode-evasion',
    severity: 'medium',
    message: {
      en: 'Suspicious invisible/control characters (null byte, bidi override) detected.',
      es: 'Caracteres invisibles/de control sospechosos (byte nulo, bidi) detectados.'
    },
    // Null bytes, bidirectional overrides (Trojan Source, CVE-2021-42574)
    patterns: [/[\u0000\u202A-\u202E\u2066-\u2069]/]
  }
];

module.exports = detectors;
