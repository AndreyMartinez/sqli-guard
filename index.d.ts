declare namespace PayloadGuard {
  type Severity = 'low' | 'medium' | 'high';

  type ThreatType =
    | 'sql-injection' | 'xss' | 'command-injection' | 'path-traversal'
    | 'nosql-injection' | 'ldap-injection' | 'template-injection' | 'crlf-injection'
    | 'ssrf' | 'xxe' | 'prototype-pollution' | 'log4shell' | 'xpath-injection'
    | 'unicode-evasion' | (string & {});

  interface Threat {
    type: ThreatType;
    severity: Severity;
    message: string;
    /** Text that triggered the detector. */
    match: string;
    /** true when the threat was only visible after decoding (URL/entities/Unicode/comments). */
    evasion?: boolean;
  }

  interface ScanResult {
    safe: boolean;
    value: unknown;
    threats: Threat[];
  }

  interface DeepThreat extends Threat {
    path: string;
    /** true when the offending text is an object key rather than a value. */
    key?: boolean;
  }

  interface DeepScanResult {
    safe: boolean;
    threats: DeepThreat[];
  }

  interface ScannerOptions {
    lang?: 'en' | 'es';
    categories?: ThreatType[];
    minSeverity?: Severity;
    /** Scan decoded views of the input to catch evasion. Default: true. */
    decode?: boolean;
  }

  interface ValidatorSpec {
    pattern?: RegExp;
    patterns?: RegExp[];
    test?: (value: string) => boolean | string | null | undefined;
    severity?: Severity;
    type?: string;
    message?: string | { en: string; es: string };
  }

  interface MiddlewareOptions {
    sources?: string[];
    status?: number;
    onThreat?: (req: any, res: any, threats: DeepThreat[]) => void;
  }

  class Scanner {
    constructor(options?: ScannerOptions);
    scan(value: unknown): ScanResult;
    scanDeep(value: unknown, maxDepth?: number): DeepScanResult;
    isSafe(value: unknown): boolean;
    hasSql(value: unknown): boolean;
    addValidator(name: string, spec: RegExp | ((value: string) => boolean | string) | ValidatorSpec): this;
    removeValidator(name: string): boolean;
    listValidators(): string[];
    middleware(options?: MiddlewareOptions): (req: any, res: any, next: (err?: unknown) => void) => unknown;
  }

  function createScanner(options?: ScannerOptions): Scanner;
  const detectors: ReadonlyArray<{ type: string; severity: Severity; message: { en: string; es: string }; patterns: RegExp[] }>;
}

declare const payloadGuard: PayloadGuard.Scanner & {
  createScanner: typeof PayloadGuard.createScanner;
  Scanner: typeof PayloadGuard.Scanner;
  detectors: typeof PayloadGuard.detectors;
};

export = payloadGuard;
