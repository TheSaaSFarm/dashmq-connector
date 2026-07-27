import { createHash } from "crypto";
import type { JobData } from "./scanner";
import {
  CWD_CONFIG_FILENAME,
  DetectorName,
  HOME_CONFIG_RELATIVE,
  NormalizedRule,
  RedactionConfigError,
  RedactionMode,
  ResolveOptions,
  defaultSaltPath,
  loadRedactionConfig,
  readOrCreateLocalSalt,
} from "./redaction-config";

/**
 * The redaction engine.
 *
 * Everything a job carries out of this process passes through here, and it is
 * the only place that turns a raw Redis value into something transmittable.
 * Three surfaces matter, and all three are covered:
 *
 *   1. job payloads on list reads  (the 5s push loop and `job.list`)
 *   2. payloads, opts and returnValue on detail reads  (`job.get`)
 *   3. FREE TEXT — job logs, `failedReason`, stack traces. A processor that
 *      does `console.log(user)` leaks as much as any payload. Free text is
 *      addressed as `logs` / `failedReason` / `stackTrace`, so `deny` and
 *      `allow` reach it, and it follows the mode like everything else: under
 *      `none` it is type-tagged, because the detectors recognise an email and
 *      a card number but not a name, an address or a date of birth, and
 *      "values are never transmitted" has to be true of this surface too.
 *
 * Shape is preserved everywhere. A key is never dropped, only its value is
 * replaced. That is not cosmetic: shown `{"email": "<redacted:email>"}` a model
 * reasons about a present-but-hidden field; shown `{}` it concludes the field
 * was missing and misdiagnoses the bug.
 *
 * Cost per job is one tree walk. Policies are resolved per queue exactly once
 * and compiled into closures holding precompiled path matchers and regexes;
 * nothing re-reads or re-resolves configuration while jobs are flowing.
 */

// ---------------------------------------------------------------------------
// Path patterns
//
// Dot/bracket syntax with two wildcards:
//   *      exactly one segment       e.g. user.*.token
//   **     any number of segments    e.g. **.password
//   [n]    a specific array index    e.g. items[0].sku
//   [*]    any array index           e.g. items[*].serialNumber
//   ["k"]  a literal key             e.g. ["user.email"], customer[".."].id
//
// The quoted form exists because `.` and `[` are structural here but perfectly
// ordinary in a JSON key: flattened form data, i18n keys, metric names and
// Stripe-style metadata maps all produce keys like "user.email". Without a
// quoting form `deny: ["user.email"]` would validate cleanly, match nothing,
// and protect nothing — a silent failure of exactly the kind the config
// validator's unknown-key rejection exists to prevent. Reported paths use the
// same form (see formatPath), so `["a.b"].password` and `a.b.password` are
// distinguishable in the sidecar instead of collapsing onto one string.
// ---------------------------------------------------------------------------

export type PathSegment =
  | { kind: "key"; name: string }
  | { kind: "index"; index: number }
  | { kind: "any" }
  | { kind: "anyIndex" }
  | { kind: "anyDepth" };

/**
 * Matching runs as a tiny NFA whose state set is a bitmask, one bit per pattern
 * segment plus one accept bit. That is what makes the walk cheap: the state for
 * a child node is derived from its parent's in O(pattern length) with no
 * allocation and no path strings built along the way.
 *
 * The bitmask is a JS number, so a pattern may not exceed 30 segments.
 */
const MAX_PATTERN_SEGMENTS = 30;

export interface CompiledPattern {
  readonly source: string;
  readonly segments: PathSegment[];
  /** Closed start state. */
  readonly start: number;
}

function invalidPattern(source: string, reason: string): never {
  throw new RedactionConfigError(`invalid path pattern "${source}": ${reason}`);
}

export function parsePathPattern(source: string): PathSegment[] {
  const text = source.trim();
  if (text.length === 0) invalidPattern(source, "pattern is empty");

  const segments: PathSegment[] = [];
  let i = 0;
  let expectSegment = true;

  while (i < text.length) {
    const char = text[i];

    if (char === "[") {
      const quote = text[i + 1];
      if (quote === '"' || quote === "'") {
        let cursor = i + 2;
        let name = "";
        let closed = false;

        while (cursor < text.length) {
          const current = text[cursor];
          if (current === "\\") {
            if (cursor + 1 >= text.length) {
              invalidPattern(source, "escape at the end of a quoted key");
            }
            name += text[cursor + 1];
            cursor += 2;
            continue;
          }
          if (current === quote) {
            closed = true;
            cursor += 1;
            break;
          }
          name += current;
          cursor += 1;
        }

        if (!closed) invalidPattern(source, "unterminated quoted key");
        if (text[cursor] !== "]") invalidPattern(source, 'expected "]" after a quoted key');
        if (name.length === 0) invalidPattern(source, "quoted key is empty");

        // A quoted key is always literal — no wildcard, no separator. That is
        // what makes ["*"] the way to address a key actually named "*".
        segments.push({ kind: "key", name });
        i = cursor + 1;
        expectSegment = false;
        if (i < text.length && text[i] !== "." && text[i] !== "[") {
          invalidPattern(source, `unexpected "${text[i]}" after "]"`);
        }
        continue;
      }

      const end = text.indexOf("]", i + 1);
      if (end === -1) invalidPattern(source, 'unclosed "["');
      const inner = text.slice(i + 1, end);
      if (inner === "*") {
        segments.push({ kind: "anyIndex" });
      } else if (/^\d+$/.test(inner)) {
        segments.push({ kind: "index", index: Number(inner) });
      } else {
        invalidPattern(
          source,
          `"[${inner}]" is not an index, "[*]", or a quoted key like ["${inner}"]`
        );
      }
      i = end + 1;
      expectSegment = false;
      if (i < text.length && text[i] !== "." && text[i] !== "[") {
        invalidPattern(source, `unexpected "${text[i]}" after "]"`);
      }
      continue;
    }

    if (char === ".") {
      if (expectSegment) invalidPattern(source, "empty segment");
      i += 1;
      expectSegment = true;
      if (i >= text.length) invalidPattern(source, 'trailing "."');
      continue;
    }

    if (char === "]") invalidPattern(source, 'unexpected "]"');

    let end = i;
    while (end < text.length && text[end] !== "." && text[end] !== "[") end += 1;
    const name = text.slice(i, end);

    if (name.includes("]")) invalidPattern(source, 'unexpected "]"');
    if (name === "*") {
      segments.push({ kind: "any" });
    } else if (name === "**") {
      segments.push({ kind: "anyDepth" });
    } else if (name.includes("*")) {
      invalidPattern(source, '"*" must be a whole segment');
    } else {
      segments.push({ kind: "key", name });
    }

    i = end;
    expectSegment = false;
  }

  if (segments.length === 0) invalidPattern(source, "pattern is empty");
  if (segments.length > MAX_PATTERN_SEGMENTS) {
    invalidPattern(source, `more than ${MAX_PATTERN_SEGMENTS} segments`);
  }

  return segments;
}

/** Expand `**` states forward: it may also match zero segments. */
function closeMask(mask: number, segments: PathSegment[]): number {
  let result = mask;
  let changed = true;
  while (changed) {
    changed = false;
    for (let i = 0; i < segments.length; i++) {
      if ((result & (1 << i)) === 0) continue;
      if (segments[i].kind !== "anyDepth") continue;
      const next = 1 << (i + 1);
      if ((result & next) === 0) {
        result |= next;
        changed = true;
      }
    }
  }
  return result;
}

function segmentMatches(segment: PathSegment, element: string | number): boolean {
  switch (segment.kind) {
    case "key":
      return typeof element === "string" && element === segment.name;
    case "index":
      return typeof element === "number" && element === segment.index;
    case "any":
      return true;
    case "anyIndex":
      return typeof element === "number";
    case "anyDepth":
      // Handled by advanceMask/closeMask, never by a direct comparison.
      return false;
  }
}

export function compilePattern(source: string): CompiledPattern {
  const segments = parsePathPattern(source);
  return { source, segments, start: closeMask(1, segments) };
}

function advanceMask(
  mask: number,
  segments: PathSegment[],
  element: string | number
): number {
  let next = 0;
  for (let i = 0; i < segments.length; i++) {
    if ((mask & (1 << i)) === 0) continue;
    const segment = segments[i];
    if (segment.kind === "anyDepth") {
      // Consume this element and stay; the "skip me" case is already in the
      // mask because every mask is kept closed.
      next |= 1 << i;
      continue;
    }
    if (segmentMatches(segment, element)) next |= 1 << (i + 1);
  }
  return closeMask(next, segments);
}

function isAccepting(mask: number, segments: PathSegment[]): boolean {
  return (mask & (1 << segments.length)) !== 0;
}

/**
 * Match a whole concrete path against one pattern.
 *
 * The walk never calls this — it advances masks incrementally instead — but a
 * path matcher that can only be observed through a tree walk is a path matcher
 * nobody checks. This is the same automaton, exposed so the pattern language
 * can be tested and audited on its own.
 *
 * `canDescend` reports whether a longer path could still match, which is what
 * "traverse into this container" means for an allowlist.
 */
export function matchPath(
  pattern: CompiledPattern,
  path: Array<string | number>
): { matches: boolean; canDescend: boolean } {
  let mask = pattern.start;
  for (const element of path) {
    mask = advanceMask(mask, pattern.segments, element);
    if (mask === 0) return { matches: false, canDescend: false };
  }
  const accept = 1 << pattern.segments.length;
  return {
    matches: (mask & accept) !== 0,
    canDescend: (mask & ~accept) !== 0,
  };
}

const NO_MASKS: number[] = [];

function startMasks(patterns: CompiledPattern[]): number[] {
  if (patterns.length === 0) return NO_MASKS;
  return patterns.map((pattern) => pattern.start);
}

function advanceMasks(
  masks: number[],
  patterns: CompiledPattern[],
  element: string | number
): number[] {
  if (patterns.length === 0) return NO_MASKS;
  const next = new Array<number>(patterns.length);
  for (let i = 0; i < patterns.length; i++) {
    next[i] = advanceMask(masks[i], patterns[i].segments, element);
  }
  return next;
}

function anyAccepting(masks: number[], patterns: CompiledPattern[]): boolean {
  for (let i = 0; i < patterns.length; i++) {
    if (isAccepting(masks[i], patterns[i].segments)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Value detectors
//
// These run over free text as well as over payload leaves, so they are tuned to
// over-redact rather than under-redact: a false positive costs a support
// question, a false negative ships somebody's card number to a third party.
// The two exceptions are card and phone numbers, where an unqualified run of
// digits would swallow every 13-digit millisecond timestamp and every ISO date
// in every log line — those carry a shape or checksum requirement.
// ---------------------------------------------------------------------------

interface Detector {
  readonly name: DetectorName;
  readonly pattern: RegExp;
  readonly verify?: (match: string) => boolean;
  /**
   * When set, only this capture group is replaced and the rest of the match is
   * kept. `password: hunter2` becomes `password: <redacted:secret>` rather than
   * `<redacted:secret>`: the key name is what makes the log line readable, and
   * it is not the part that needed removing.
   */
  readonly valueGroup?: number;
}

function digitsOf(text: string): string {
  return text.replace(/\D/g, "");
}

function luhnValid(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let value = digits.charCodeAt(i) - 48;
    if (value < 0 || value > 9) return false;
    if (double) {
      value *= 2;
      if (value > 9) value -= 9;
    }
    sum += value;
    double = !double;
  }
  return digits.length > 0 && sum % 10 === 0;
}

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * Values that follow a secret-shaped key but are not secrets. Without this,
 * `authorization: Bearer <redacted:jwt>` re-redacts its own marker and
 * `retry: true` reads as a credential.
 */
const NON_SECRET_VALUES = new Set([
  "true",
  "false",
  "null",
  "none",
  "nil",
  "undefined",
  "empty",
  "unset",
  "bearer",
  "basic",
  "token",
  "required",
  "missing",
  "invalid",
  "expired",
  "redacted",
  "hidden",
]);

/** The tail of a secret-shaped match, unquoted. */
function secretValueOf(match: string): string | null {
  const tail = /(?:[:=]\s*|\s+)("[^"\n]*"|'[^'\n]*'|[^\s,;}\])]+)$/.exec(match);
  if (!tail) return null;
  const raw = tail[1];
  const quoted =
    (raw.startsWith('"') && raw.endsWith('"')) ||
    (raw.startsWith("'") && raw.endsWith("'"));
  return quoted ? raw.slice(1, -1) : raw;
}

/** Anything the engine itself already wrote. Never redacted a second time. */
function isMarker(value: string): boolean {
  return /^<(?:redacted|type|hash|circular|truncated):?[^>]*>$/.test(value);
}

const DETECTORS: Record<DetectorName, Detector> = {
  // A JWT header is base64 of `{"...`, which always starts "eyJ". Three
  // base64url parts, the last possibly empty (unsigned tokens).
  jwt: {
    name: "jwt",
    pattern: /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/g,
  },
  // Vendor-prefixed credentials. These are the ones that appear verbatim in log
  // lines and error messages, where no path exists to deny.
  apiKey: {
    name: "apiKey",
    pattern:
      /\b(?:(?:sk|pk|rk|whsec)_(?:live|test)_[A-Za-z0-9]{8,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[abopsr]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,}|dashmq_[A-Za-z0-9_-]{16,})/g,
  },
  // Credentials that only a key name identifies: `password: hunter2`,
  // `api_key="…"`, `Authorization: Bearer …`. Only the value is replaced.
  secret: {
    name: "secret",
    pattern:
      /(?:\b(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|authorization)\b["']?\s*[:=]\s*|\bBearer\s+|\bBasic\s+)("[^"\n]{4,512}"|'[^'\n]{4,512}'|[^\s,;}\])]{4,512})/gi,
    valueGroup: 1,
    verify: (match) => {
      const value = secretValueOf(match);
      if (value === null || value.length < 4) return false;
      if (isMarker(value)) return false;
      return !NON_SECRET_VALUES.has(value.toLowerCase());
    },
  },
  // Unicode on BOTH sides of the "@". An ASCII-only address class silently
  // exempts every accented local part and every internationalised domain, which
  // for a European product is not an edge case — and free text (logs,
  // failedReason, stack traces) has no path denylist to fall back on.
  email: {
    name: "email",
    pattern:
      /[\p{L}\p{N}._%+'-]+@(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?\.)+[\p{L}\p{N}-]{2,}/gu,
  },
  // Shape only, deliberately without the mod-97 checksum: a mistyped IBAN is
  // still a bank account, and refusing to redact it because it fails a
  // checksum would be the wrong way round.
  iban: {
    name: "iban",
    pattern: /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b/g,
    verify: (match) => {
      const compact = match.replace(/ /g, "");
      return /^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(compact) && compact.length >= 15;
    },
  },
  creditCard: {
    name: "creditCard",
    pattern: /\b(?:\d[ -]?){12,18}\d\b/g,
    verify: (match) => {
      const digits = digitsOf(match);
      if (digits.length < 13 || digits.length > 19) return false;
      // Grouped digits are a strong enough signal on their own; a bare run has
      // to pass Luhn, or every millisecond timestamp becomes a card number.
      const grouped = /^\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,7}$/.test(match.trim());
      return grouped || luhnValid(digits);
    },
  },
  phone: {
    name: "phone",
    pattern:
      /\+\d[\d ().-]{5,18}\d|\(\d{2,4}\)[ .-]?\d{2,4}(?:[ .-]?\d{2,4}){1,4}|\b\d{2,4}(?:[ .-]\d{2,4}){2,5}\b/g,
    verify: (match) => {
      const trimmed = match.trim();
      if (ISO_DATE.test(trimmed)) return false;
      const digits = digitsOf(trimmed);
      return digits.length >= 7 && digits.length <= 15;
    },
  },
};

function selectDetectors(names: DetectorName[]): Detector[] {
  return names.map((name) => DETECTORS[name]);
}

/** The first detector that claims any part of `text`, in canonical order. */
function firstDetectorHit(text: string, detectors: Detector[]): DetectorName | null {
  for (const detector of detectors) {
    const { pattern } = detector;
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(text)) !== null) {
      if (match[0].length === 0) {
        pattern.lastIndex += 1;
        continue;
      }
      if (!detector.verify || detector.verify(match[0])) return detector.name;
    }
  }
  return null;
}

/** Replace every detector match inside `text`, leaving the rest readable. */
function scrubText(
  text: string,
  detectors: Detector[],
  replace: (name: DetectorName, match: string) => string
): { text: string; hits: DetectorName[] } {
  let result = text;
  const hits: DetectorName[] = [];

  for (const detector of detectors) {
    const { pattern } = detector;
    pattern.lastIndex = 0;
    result = result.replace(pattern, (...args: unknown[]) => {
      const match = args[0] as string;
      if (detector.verify && !detector.verify(match)) return match;
      if (!hits.includes(detector.name)) hits.push(detector.name);

      if (detector.valueGroup !== undefined) {
        const captured = args[detector.valueGroup];
        if (typeof captured === "string" && captured.length > 0) {
          // The value is the tail of the match by construction, so the last
          // occurrence is the right one even when the key repeats it.
          const at = match.lastIndexOf(captured);
          if (at >= 0) {
            return match.slice(0, at) + replace(detector.name, captured);
          }
        }
      }

      return replace(detector.name, match);
    });
  }

  return { text: result, hits };
}

// ---------------------------------------------------------------------------
// Markers
// ---------------------------------------------------------------------------

export const CIRCULAR_MARKER = "<circular>";
export const DEPTH_MARKER = "<redacted:depth>";
export const UNSUPPORTED_MARKER = "<redacted:unsupported>";

function typeTag(value: unknown): string {
  switch (typeof value) {
    case "string":
      return "<type:string>";
    case "number":
      return "<type:number>";
    case "boolean":
      return "<type:boolean>";
    case "bigint":
      return "<type:number>";
    default:
      return UNSUPPORTED_MARKER;
  }
}

function truncationSuffix(originalLength: number): string {
  return `…<truncated:${originalLength}>`;
}

/** JSON with sorted keys and cycles collapsed — only ever fed to sha256. */
function stableStringify(value: unknown, seen: Set<object> = new Set()): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (seen.has(value as object)) return '"<circular>"';
  seen.add(value as object);
  try {
    if (Array.isArray(value)) {
      return `[${value.map((entry) => stableStringify(entry, seen)).join(",")}]`;
    }
    const source = value as Record<string, unknown>;
    const keys = Object.keys(source).sort();
    return `{${keys
      .map((key) => `${JSON.stringify(key)}:${stableStringify(source[key], seen)}`)
      .join(",")}}`;
  } finally {
    seen.delete(value as object);
  }
}

// ---------------------------------------------------------------------------
// Compiled policy
// ---------------------------------------------------------------------------

export interface PayloadRedactionResult {
  value: unknown;
  /** Concrete paths whose value was changed before transmission. */
  redacted: string[];
}

export interface CompiledPolicy {
  readonly rule: NormalizedRule;
  /**
   * Redact one payload tree. `root` labels the tree in reported paths: `""`
   * for `data` (so a payload field reads `user.email`), `"opts"` and
   * `"returnValue"` for the others.
   */
  redactPayload(value: unknown, root: string): PayloadRedactionResult;
  /**
   * Free text: `failedReason`, a stack trace, one log line. Null in, null out.
   *
   * `field` is the single-segment path the text is addressed by —
   * `"failedReason"`, `"stackTrace"`, `"logs"` — so that `deny` and `allow`
   * reach it too. Without that, free text is the one surface a policy cannot
   * talk about, which is precisely the surface that carries names, addresses
   * and order references that no detector can recognise.
   */
  redactText(text: string | null | undefined, field?: string): string | null;
  /** Same treatment, line by line, addressed as `logs`. */
  redactLogLines(lines: string[]): string[];
}

/** Beyond this the list stops being information and starts being payload. */
const MAX_REPORTED_PATHS = 200;

/**
 * A key that can be written bare: no separator, no bracket, no quote, and not
 * empty. Anything else is reported in the quoted form so the reported path
 * round-trips back through `parsePathPattern` and means exactly one thing.
 */
const BARE_KEY = /^[^.[\]"'\\]+$/;

function formatPath(root: string, segments: Array<string | number>): string {
  let path = root;
  for (const segment of segments) {
    if (typeof segment === "number") {
      path += `[${segment}]`;
    } else if (!BARE_KEY.test(segment)) {
      // `{"a.b": {password}}` reports ["a.b"].password, `{a:{b:{password}}}`
      // reports a.b.password. Without this they are the same string and the
      // sidecar cannot say which field actually went.
      path += `[${JSON.stringify(segment)}]`;
    } else if (path.length === 0) {
      path = segment;
    } else {
      path += `.${segment}`;
    }
  }
  return path.length > 0 ? path : root || "data";
}

/**
 * Resolve a rule into a closure over precompiled matchers.
 *
 * Called once per distinct queue policy. Everything expensive — parsing path
 * patterns, selecting detector regexes, reading the local salt — happens here,
 * so the per-job cost is a single tree walk.
 */
export function compilePolicy(rule: NormalizedRule, salt: () => string): CompiledPolicy {
  const deny = rule.deny.map(compilePattern);
  const allow = rule.allow.map(compilePattern);
  const detectors = selectDetectors(rule.detectors);
  const usesHash = rule.strategy === "hash";

  // Resolved eagerly when the strategy needs it, so a missing or unwritable
  // salt file stops the connector at startup rather than mid-transmission.
  const saltValue = usesHash ? salt() : "";

  const hashOf = (value: unknown): string => {
    const text = typeof value === "string" ? value : stableStringify(value);
    const digest = createHash("sha256").update(text + saltValue, "utf8").digest("hex");
    return `<hash:${digest.slice(0, 12)}>`;
  };

  const label = (reason: string): string => `<redacted:${reason}>`;

  /** How a value that must not be transmitted is represented. */
  const replaceValue = (value: unknown, reason: string): string =>
    usesHash ? hashOf(value) : label(reason);

  const replaceMatch = (name: DetectorName, match: string): string =>
    usesHash ? hashOf(match) : label(name);

  const guardString = (text: string, record: () => void): string => {
    if (text.length <= rule.maxStringLength) return text;
    record();
    // Truncate before anything else looks at the string: the tail is dropped on
    // this machine, so nothing in it can leak however it is processed later.
    return text.slice(0, rule.maxStringLength) + truncationSuffix(text.length);
  };

  const matchesAny = (
    patterns: CompiledPattern[],
    path: Array<string | number>
  ): boolean => {
    for (const pattern of patterns) {
      if (matchPath(pattern, path).matches) return true;
    }
    return false;
  };

  const redactPayload = (root_: unknown, root: string): PayloadRedactionResult => {
    const redacted: string[] = [];
    const seen = new Set<string>();
    // Under "none" every leaf is replaced, so enumerating paths would just
    // restate the mode at the size of the payload.
    const reportPaths = rule.mode !== "none";
    const ancestors = new Set<object>();
    const segments: Array<string | number> = [];

    const record = (): void => {
      if (!reportPaths || redacted.length >= MAX_REPORTED_PATHS) return;
      const path = formatPath(root, segments);
      if (seen.has(path)) return;
      seen.add(path);
      redacted.push(path);
    };

    /** A transmitted leaf: no detectors, still inside the transport guards. */
    const verbatimLeaf = (node: unknown): unknown => {
      if (typeof node === "string") return guardString(node, record);
      if (typeof node === "number" || typeof node === "boolean") return node;
      record();
      return UNSUPPORTED_MARKER;
    };

    /** A transmitted leaf with the value detectors applied. */
    const detectorLeaf = (node: unknown): unknown => {
      if (typeof node === "string") {
        const guarded = guardString(node, record);
        const hit = detectors.length > 0 ? firstDetectorHit(guarded, detectors) : null;
        if (hit) {
          record();
          return replaceValue(guarded, hit);
        }
        return guarded;
      }
      if (typeof node === "number" || typeof node === "boolean") return node;
      record();
      return UNSUPPORTED_MARKER;
    };

    /**
     * One node of the tree.
     *
     * `verbatim` says an ANCESTOR matched `allow`, which is a weaker statement
     * than this node matching it. Precedence, in this order and for this
     * reason:
     *
     *   1. `deny` wins, in every mode that transmits anything. It is the only
     *      construct in the language whose entire purpose is "never transmit
     *      this", so a mode — including `all` — does not get to void it. An
     *      author who writes both an allowlist and a denylist means the deny;
     *      accepting the key and discarding it at runtime is the failure this
     *      ordering exists to remove.
     *   2. A path that `allow` matches EXACTLY beats the detectors:
     *      `allow: ["contact.email"]` names one field, and second-guessing that
     *      with a value-shape heuristic would make the allowlist mean nothing.
     *      Matching only an ancestor does not: `allow: ["user"]` says the
     *      subtree may travel, not that every value in it is safe, so the
     *      detectors still run on `user.email`. A container allow is a scope,
     *      not a blanket exemption.
     *   3. the mode decides everything not named either way.
     *
     * The consequence worth stating: a rule element is only ever ignored when
     * ignoring it transmits LESS (`allow` under `none`, which sends nothing;
     * `allow` under `all`, which already sends everything). Nothing is ever
     * ignored in the direction that would transmit more than the author asked.
     */
    const walk = (
      node: unknown,
      depth: number,
      denyMasks: number[],
      allowMasks: number[],
      verbatim: boolean
    ): unknown => {
      if (depth > rule.maxDepth) {
        record();
        return DEPTH_MARKER;
      }

      if (node === null || node === undefined) return null;

      const isContainer = typeof node === "object";

      if (isContainer && ancestors.has(node as object)) return CIRCULAR_MARKER;

      // 1. deny, whatever the mode. Under "none" nothing travels anyway.
      if (rule.mode !== "none" && deny.length > 0 && anyAccepting(denyMasks, deny)) {
        record();
        return replaceValue(node, "path");
      }

      // 2. allow. Under "all" everything is already transmitted and under
      // "none" nothing is, so the question only arises for the other two.
      const selfAllowed =
        allow.length > 0 && (rule.mode === "allowlist" || rule.mode === "redact")
          ? anyAccepting(allowMasks, allow)
          : false;
      // "May travel" — this node or an ancestor was named.
      const inAllowed = verbatim || selfAllowed;

      // Under "allowlist" a leaf nothing allowed does not travel. Containers
      // are still descended into: an allowed path may live below them.
      if (rule.mode === "allowlist" && !inAllowed && !isContainer) {
        record();
        return replaceValue(node, "path");
      }

      if (isContainer) {
        ancestors.add(node as object);
        try {
          if (Array.isArray(node)) {
            const out = new Array<unknown>(node.length);
            for (let i = 0; i < node.length; i++) {
              segments.push(i);
              out[i] = walk(
                node[i],
                depth + 1,
                advanceMasks(denyMasks, deny, i),
                advanceMasks(allowMasks, allow, i),
                inAllowed
              );
              segments.pop();
            }
            return out;
          }

          const source = node as Record<string, unknown>;
          const out: Record<string, unknown> = {};
          // Own enumerable keys only: a polluted prototype contributes nothing,
          // and a payload whose own key really is "__proto__" is copied with
          // defineProperty so it stays data instead of becoming a prototype.
          for (const key of Object.keys(source)) {
            segments.push(key);
            const value = walk(
              source[key],
              depth + 1,
              advanceMasks(denyMasks, deny, key),
              advanceMasks(allowMasks, allow, key),
              inAllowed
            );
            segments.pop();
            defineDataProperty(out, key, value);
          }
          return out;
        } finally {
          ancestors.delete(node as object);
        }
      }

      // Leaves.
      switch (rule.mode) {
        case "none": {
          if (typeof node === "string" || typeof node === "number" || typeof node === "boolean") {
            return typeTag(node);
          }
          return UNSUPPORTED_MARKER;
        }
        case "all":
          // The one mode that is an explicit opt-in to verbatim transmission.
          return verbatimLeaf(node);
        case "allowlist":
        case "redact":
        default:
          // A leaf named exactly by `allow` travels as written; one that merely
          // sits under an allowed container still faces the detectors. Leaves
          // that nothing allowed were handled above under "allowlist", and get
          // the detectors under "redact".
          return selfAllowed ? verbatimLeaf(node) : detectorLeaf(node);
      }
    };

    const value = walk(root_, 0, startMasks(deny), startMasks(allow), false);
    return { value, redacted };
  };

  const redactText = (text: string | null | undefined, field = ""): string | null => {
    if (typeof text !== "string") return null;
    if (text.length === 0) return "";

    const path: Array<string | number> | null = field ? [field] : null;

    // deny reaches free text as well, so `deny: ["stackTrace"]` is something an
    // operator can write and have honoured.
    if (
      rule.mode !== "none" &&
      path !== null &&
      deny.length > 0 &&
      matchesAny(deny, path)
    ) {
      return replaceValue(text, "path");
    }

    // "none" transmits types, not values — and free text is a value. The
    // detectors recognise an email or a card number; they do not recognise a
    // person's name, a postal address, a date of birth or an order reference,
    // all of which sit in `failedReason` and log lines constantly. Letting free
    // text through here is what would make the documented promise ("key names
    // and value types are transmitted, values never are") false.
    if (rule.mode === "none") return typeTag(text);

    const guarded =
      text.length > rule.maxStringLength
        ? text.slice(0, rule.maxStringLength) + truncationSuffix(text.length)
        : text;

    const allowed = path !== null && allow.length > 0 && matchesAny(allow, path);

    // Under "allowlist" only what was named travels, and free text is not named
    // unless the operator named it: `allow: ["failedReason", "stackTrace"]`.
    if (rule.mode === "allowlist" && !allowed) return replaceValue(text, "path");

    // `all` is an explicit opt-in to verbatim transmission, and so is naming a
    // text field in `allow`; the length guard stays because it is a transport
    // bound, not a privacy one.
    if (rule.mode === "all" || allowed || detectors.length === 0) return guarded;

    return scrubText(guarded, detectors, replaceMatch).text;
  };

  return {
    rule,
    redactPayload,
    redactText,
    redactLogLines(lines: string[]): string[] {
      const out: string[] = [];
      for (const line of lines) {
        const scrubbed = redactText(
          typeof line === "string" ? line : String(line),
          "logs"
        );
        if (scrubbed !== null) out.push(scrubbed);
      }
      return out;
    },
  };
}

/**
 * Copy a key onto a fresh object without letting the key itself do anything.
 * `out.__proto__ = x` would silently reparent the object instead of storing
 * data, which is both a lost key (shape) and a prototype-pollution primitive.
 */
function defineDataProperty(
  target: Record<string, unknown>,
  key: string,
  value: unknown
): void {
  if (key === "__proto__") {
    Object.defineProperty(target, key, {
      value,
      writable: true,
      enumerable: true,
      configurable: true,
    });
    return;
  }
  target[key] = value;
}

// ---------------------------------------------------------------------------
// Sidecar
// ---------------------------------------------------------------------------

export interface RedactionSidecar {
  /** Paths whose value was replaced. Empty under "none": everything was. */
  redacted: string[];
  /** `sha256:<hex>` of the live policy. */
  policy: string;
  mode: RedactionMode;
}

/**
 * A job that has been through the engine.
 *
 * `_dashmq` is the self-describing sidecar: both the UI and a model reading the
 * payload can tell what was removed and under which policy. The three flat
 * fields carry the same facts in the shape the dashboard's ingest already
 * reads (`JobFailure.redactionMode` / `redactionPolicy` / `payloadRedacted`).
 */
export interface RedactedJob extends JobData {
  _dashmq: RedactionSidecar;
  redactionMode: RedactionMode;
  redactionPolicy: string;
  payloadRedacted: string[];
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

export interface RedactionEngineOptions extends ResolveOptions {
  /** Overridable for tests; defaults to ~/.dashmq/salt. */
  saltPath?: string;
}

export class RedactionEngine {
  /** `sha256:<hex>` over the normalised policy. */
  readonly policyId: string;
  /** Absolute path the policy came from, or null when none exists. */
  readonly configPath: string | null;
  readonly defaultMode: RedactionMode;

  private readonly defaultPolicy: CompiledPolicy;
  /** Compiled once per key as written in the config file. */
  private readonly declared = new Map<string, CompiledPolicy>();
  /** Effective policy per `${prefix}:${name}`, resolved once. */
  private readonly resolved = new Map<string, CompiledPolicy>();
  private readonly source: string;

  constructor(options: RedactionEngineOptions = {}) {
    const loaded = loadRedactionConfig(options);
    const saltPath = options.saltPath ?? defaultSaltPath(options.homeDir);

    let cachedSalt: string | null = null;
    const salt = (): string => {
      if (cachedSalt === null) cachedSalt = readOrCreateLocalSalt(saltPath);
      return cachedSalt;
    };

    this.policyId = loaded.policyId;
    this.configPath = loaded.path;
    this.source = loaded.source;
    this.defaultMode = loaded.config.default.mode;
    this.defaultPolicy = compilePolicy(loaded.config.default, salt);

    for (const key of Object.keys(loaded.config.queues)) {
      this.declared.set(key, compilePolicy(loaded.config.queues[key], salt));
    }
  }

  /**
   * The effective policy for a queue.
   *
   * Overrides are keyed the same way the registry keys queues — `prefix:name`
   * — with a bare queue name accepted as the common shorthand. Resolution is
   * memoised, so a queue costs one lookup for the life of the process.
   */
  policyFor(prefix: string, name: string): CompiledPolicy {
    const key = `${prefix}:${name}`;
    const cached = this.resolved.get(key);
    if (cached) return cached;

    const policy =
      this.declared.get(key) ?? this.declared.get(name) ?? this.defaultPolicy;
    this.resolved.set(key, policy);
    return policy;
  }

  /** Resolve policies for a discovery pass up front, so no job read pays for it. */
  prime(queues: Array<{ name: string; prefix: string }>): void {
    for (const queue of queues) this.policyFor(queue.prefix, queue.name);
  }

  /**
   * The choke point. Every job that leaves this process comes through here.
   *
   * `data`, `opts` and `returnValue` are walked under the queue's mode;
   * `failedReason` and the stack trace get the value detectors, because error
   * messages routinely embed the offending email or id.
   */
  redactJob(prefix: string, name: string, job: JobData): RedactedJob {
    const policy = this.policyFor(prefix, name);

    const data = policy.redactPayload(job.data, "");
    const opts = policy.redactPayload(job.opts, "opts");
    const returnValue = policy.redactPayload(job.returnValue, "returnValue");

    const failedReason = policy.redactText(job.failedReason, "failedReason");
    const stacktrace = policy.redactText(job.stacktrace, "stackTrace");

    // Under "none" everything went, so listing paths would restate the mode —
    // the same reason redactPayload reports nothing in that mode.
    const reportPaths = policy.rule.mode !== "none";

    const redacted = reportPaths
      ? dedupe([
          ...data.redacted,
          ...opts.redacted,
          ...returnValue.redacted,
          ...(failedReason !== job.failedReason ? ["failedReason"] : []),
          ...(stacktrace !== job.stacktrace ? ["stackTrace"] : []),
        ])
      : [];

    return {
      ...job,
      data: data.value,
      opts: opts.value,
      returnValue: returnValue.value,
      failedReason,
      stacktrace,
      _dashmq: {
        redacted,
        policy: this.policyId,
        mode: policy.rule.mode,
      },
      redactionMode: policy.rule.mode,
      redactionPolicy: this.policyId,
      payloadRedacted: redacted,
    };
  }

  /**
   * Job logs. A path denylist means nothing against free text, so every line
   * gets the value detectors and the length guard.
   */
  redactLogs(prefix: string, name: string, lines: string[]): string[] {
    return this.policyFor(prefix, name).redactLogLines(lines);
  }

  /** True when no policy file exists and the built-in default is in force. */
  get isDefaultPolicy(): boolean {
    return this.source === "absent";
  }

  /** One line for the startup banner: what is live, and where it came from. */
  describe(): string {
    if (this.source === "absent") {
      return (
        `no policy file found — running the built-in default, mode "${this.defaultMode}": ` +
        `values are transmitted except those a detector recognises ` +
        `(${this.policyId})`
      );
    }
    return `mode ${this.defaultMode} from ${this.configPath} (${this.policyId})`;
  }

  /**
   * The startup warning that goes with a missing policy file.
   *
   * Empty when a policy exists. A default that transmits values must not be
   * something a customer can be running without having been told, in the same
   * session, in plain words.
   */
  warnings(): string[] {
    if (this.source !== "absent") return [];
    return [
      `No redaction policy found. Running the built-in default: mode "${this.defaultMode}".`,
      "Job payloads ARE transmitted, minus every value the detectors recognise",
      "(emails, cards, IBANs, phone numbers, JWTs, API keys, password/token assignments).",
      `Write ${CWD_CONFIG_FILENAME} (or ~/${HOME_CONFIG_RELATIVE}) to change this.`,
      'For shape only and no values at all, set { "redaction": { "default": { "mode": "none" } } }.',
    ];
  }
}

function dedupe(values: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of values) {
    if (seen.has(value)) continue;
    seen.add(value);
    out.push(value);
    if (out.length >= MAX_REPORTED_PATHS) break;
  }
  return out;
}

export {
  RedactionConfigError,
  RedactionMode,
  RedactionStrategy,
  DetectorName,
  NormalizedRule,
} from "./redaction-config";
