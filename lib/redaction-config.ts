import { createHash, randomBytes } from "crypto";
import { mkdirSync, readFileSync, writeFileSync } from "fs";
import { homedir } from "os";
import { dirname, join, resolve as resolvePath } from "path";

/**
 * Redaction policy: where it comes from, and what it is allowed to say.
 *
 * Three properties make "you control what leaves your network" a fact rather
 * than a slogan, and all three live in this file:
 *
 *  (a) The policy is a LOCAL FILE. It is read from disk on this machine and
 *      from nowhere else. Nothing in the connector accepts a policy — or any
 *      part of one — over the network, and the server is never told its
 *      contents, only its hash.
 *
 *  (b) It FAILS CLOSED. An unparseable policy throws, and the CLI turns that
 *      into a non-zero exit: a connector that cannot read its policy does not
 *      run. An ABSENT policy is not "no redaction" either: it is mode
 *      "redact", which strips every value the detectors recognise as personal
 *      or secret before anything is transmitted, and says so loudly at startup.
 *
 *  (c) Its hash is reported. `policyId` is a sha256 over the *normalised*
 *      policy, so it changes if and only if behaviour changes, and it travels
 *      with every sync and every RPC poll so the dashboard can show which
 *      policy is live.
 */

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

export const REDACTION_MODES = ["none", "redact", "allowlist", "all"] as const;
export type RedactionMode = (typeof REDACTION_MODES)[number];

export const REDACTION_STRATEGIES = ["label", "hash"] as const;
export type RedactionStrategy = (typeof REDACTION_STRATEGIES)[number];

/**
 * Detector order is fixed here, not taken from the config. Detectors run in
 * sequence over the same text, so the order decides which one claims an
 * ambiguous match — a dashed card number is a card number, not a phone number.
 * Leaving that to the order somebody happened to type would make the output
 * depend on cosmetics.
 */
export const DETECTOR_NAMES = [
  "jwt",
  "apiKey",
  "secret",
  "email",
  "iban",
  "creditCard",
  "phone",
] as const;
export type DetectorName = (typeof DETECTOR_NAMES)[number];

/** Supported config file version. A file that claims anything else is refused. */
export const REDACTION_CONFIG_VERSION = 1;

// ---------------------------------------------------------------------------
// Shapes
// ---------------------------------------------------------------------------

/** A rule as written in the file: every field optional, inherited when absent. */
export interface RedactionRuleInput {
  mode?: RedactionMode;
  strategy?: RedactionStrategy;
  deny?: string[];
  allow?: string[];
  detectors?: DetectorName[];
  maxDepth?: number;
  maxStringLength?: number;
}

/** A rule after inheritance: every field resolved, nothing left to guess. */
export interface NormalizedRule {
  mode: RedactionMode;
  strategy: RedactionStrategy;
  deny: string[];
  allow: string[];
  detectors: DetectorName[];
  maxDepth: number;
  maxStringLength: number;
}

export interface NormalizedRedactionConfig {
  version: number;
  default: NormalizedRule;
  /** Keyed exactly as written in the file — `payments` or `bull:payments`. */
  queues: Record<string, NormalizedRule>;
}

export type RedactionConfigSource = "flag" | "env" | "cwd" | "home" | "absent";

export interface LoadedRedactionConfig {
  config: NormalizedRedactionConfig;
  /** `sha256:<64 hex>` over the normalised config. */
  policyId: string;
  /** Absolute path the policy was read from, or null when none exists. */
  path: string | null;
  source: RedactionConfigSource;
}

/**
 * Anything that makes the policy unusable. Thrown, never swallowed: the caller
 * is expected to stop, because continuing would mean transmitting under a
 * policy nobody has actually read.
 */
export class RedactionConfigError extends Error {
  readonly code = "REDACTION_CONFIG";

  constructor(message: string) {
    super(message);
    this.name = "RedactionConfigError";
    Object.setPrototypeOf(this, RedactionConfigError.prototype);
  }
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

export const DEFAULT_MAX_DEPTH = 8;
export const DEFAULT_MAX_STRING_LENGTH = 2048;

/** Bounds that keep a hostile or careless config from being a denial of service. */
const MAX_ALLOWED_DEPTH = 64;
const MAX_ALLOWED_STRING_LENGTH = 1_048_576;

/**
 * What applies when there is no file at all.
 *
 * This default is a MIGRATION decision as much as a privacy one, and the two
 * pull in opposite directions:
 *
 *  - Every connector installed before redaction existed transmitted payloads
 *    verbatim, and the dashboard caches what it is sent. Defaulting to `none`
 *    would mean the first sync after `npm update` silently overwrites every
 *    cached payload in the product with `"<type:string>"` — a feature nobody
 *    asked for, delivered as data loss, to customers who changed nothing.
 *  - Defaulting to `all` would mean shipping the privacy feature switched off,
 *    which is the failure the feature exists to prevent.
 *
 * `redact` is the only option that is strictly better than the behaviour it
 * replaces AND strictly better than doing nothing: values still reach the
 * dashboard, so no existing install loses a payload it had yesterday, but every
 * value the detectors recognise — emails, cards, IBANs, phone numbers, JWTs,
 * API keys, `password: …` assignments — is removed on the customer's machine
 * first. It is announced at startup (see `RedactionEngine.describe`) and
 * reported to the dashboard on every sync, so "I did not know it was on" is not
 * a state a customer can end up in.
 *
 * Stricter modes are one file away and documented; `none` in particular
 * transmits key names and value types only, and is what a customer who wants
 * Taskforce parity should write down explicitly.
 */
export function defaultRule(): NormalizedRule {
  return {
    mode: "redact",
    strategy: "label",
    deny: [],
    allow: [],
    detectors: [...DETECTOR_NAMES],
    maxDepth: DEFAULT_MAX_DEPTH,
    maxStringLength: DEFAULT_MAX_STRING_LENGTH,
  };
}

export function absentConfig(): NormalizedRedactionConfig {
  return {
    version: REDACTION_CONFIG_VERSION,
    default: defaultRule(),
    queues: {},
  };
}

// ---------------------------------------------------------------------------
// Validation helpers
//
// Every one of these rejects rather than coerces. A policy is a security
// boundary: "deny" silently ignored because it was spelled "denny", or a mode
// silently defaulted because it was capitalised, is exactly the class of bug
// that makes a product claim protection it does not deliver.
// ---------------------------------------------------------------------------

function fail(message: string): never {
  throw new RedactionConfigError(message);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireObject(value: unknown, where: string): Record<string, unknown> {
  if (!isPlainObject(value)) fail(`${where} must be an object`);
  return value;
}

function rejectUnknownKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  where: string
): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      fail(
        `${where} has unknown key "${key}" (expected one of: ${allowed.join(", ")})`
      );
    }
  }
}

function requireEnum<T extends string>(
  value: unknown,
  allowed: readonly T[],
  where: string
): T {
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    fail(`${where} must be one of: ${allowed.join(", ")}`);
  }
  return value as T;
}

function requireStringArray(value: unknown, where: string): string[] {
  if (!Array.isArray(value)) fail(`${where} must be an array of strings`);
  return value.map((entry, index) => {
    if (typeof entry !== "string" || entry.trim().length === 0) {
      fail(`${where}[${index}] must be a non-empty string`);
    }
    return entry.trim();
  });
}

function requireInteger(
  value: unknown,
  where: string,
  min: number,
  max: number
): number {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    fail(`${where} must be an integer`);
  }
  if (value < min || value > max) {
    fail(`${where} must be between ${min} and ${max}`);
  }
  return value;
}

const RULE_KEYS = [
  "mode",
  "strategy",
  "deny",
  "allow",
  "detectors",
  "maxDepth",
  "maxStringLength",
] as const;

/**
 * Merge one written rule onto an inherited one.
 *
 * Arrays replace rather than concatenate. A per-queue `deny` that quietly
 * inherited the global list would make it impossible to read a queue's rule and
 * know what it does.
 */
function normalizeRule(
  raw: unknown,
  inherited: NormalizedRule,
  where: string
): NormalizedRule {
  const object = requireObject(raw, where);
  rejectUnknownKeys(object, RULE_KEYS, where);

  const rule: NormalizedRule = { ...inherited, deny: [...inherited.deny], allow: [...inherited.allow], detectors: [...inherited.detectors] };

  if ("mode" in object) {
    rule.mode = requireEnum(object.mode, REDACTION_MODES, `${where}.mode`);
  }
  if ("strategy" in object) {
    rule.strategy = requireEnum(
      object.strategy,
      REDACTION_STRATEGIES,
      `${where}.strategy`
    );
  }
  if ("deny" in object) {
    rule.deny = requireStringArray(object.deny, `${where}.deny`);
  }
  if ("allow" in object) {
    rule.allow = requireStringArray(object.allow, `${where}.allow`);
  }
  if ("detectors" in object) {
    const names = requireStringArray(object.detectors, `${where}.detectors`);
    for (const name of names) {
      requireEnum(name, DETECTOR_NAMES, `${where}.detectors`);
    }
    // Canonical order, deduplicated — see DETECTOR_NAMES.
    rule.detectors = DETECTOR_NAMES.filter((name) => names.includes(name));
  }
  if ("maxDepth" in object) {
    rule.maxDepth = requireInteger(
      object.maxDepth,
      `${where}.maxDepth`,
      1,
      MAX_ALLOWED_DEPTH
    );
  }
  if ("maxStringLength" in object) {
    rule.maxStringLength = requireInteger(
      object.maxStringLength,
      `${where}.maxStringLength`,
      1,
      MAX_ALLOWED_STRING_LENGTH
    );
  }

  return rule;
}

/**
 * Turn the parsed contents of a policy file into a fully resolved config.
 * Exported so it can be exercised directly, without a filesystem.
 */
export function normalizeRedactionConfig(raw: unknown): NormalizedRedactionConfig {
  const root = requireObject(raw, "config");
  rejectUnknownKeys(root, ["version", "redaction"], "config");

  if (!("version" in root)) fail(`config.version is required (expected ${REDACTION_CONFIG_VERSION})`);
  const version = requireInteger(root.version, "config.version", 1, 1_000);
  if (version !== REDACTION_CONFIG_VERSION) {
    fail(
      `config.version ${version} is not supported by this connector (expected ${REDACTION_CONFIG_VERSION})`
    );
  }

  if (!("redaction" in root)) fail("config.redaction is required");
  const redaction = requireObject(root.redaction, "config.redaction");
  rejectUnknownKeys(redaction, ["default", "queues"], "config.redaction");

  const base =
    "default" in redaction
      ? normalizeRule(redaction.default, defaultRule(), "config.redaction.default")
      : defaultRule();

  const queues: Record<string, NormalizedRule> = {};
  if ("queues" in redaction) {
    const rawQueues = requireObject(redaction.queues, "config.redaction.queues");
    for (const key of Object.keys(rawQueues)) {
      if (key.trim().length === 0) {
        fail("config.redaction.queues has an empty queue key");
      }
      queues[key.trim()] = normalizeRule(
        rawQueues[key],
        base,
        `config.redaction.queues["${key}"]`
      );
    }
  }

  return { version, default: base, queues };
}

// ---------------------------------------------------------------------------
// Policy identity
// ---------------------------------------------------------------------------

/**
 * Deterministic JSON: object keys sorted, arrays left in order.
 *
 * The hash is taken over the normalised config rather than the file bytes so
 * that reformatting a policy does not look like changing one, and so that two
 * connectors running the same effective policy report the same id.
 */
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(value as Record<string, unknown>).sort();
  const parts = keys.map(
    (key) => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`
  );
  return `{${parts.join(",")}}`;
}

export function computePolicyId(config: NormalizedRedactionConfig): string {
  const digest = createHash("sha256").update(canonicalJson(config), "utf8").digest("hex");
  return `sha256:${digest}`;
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

export const CWD_CONFIG_FILENAME = "dashmq.config.json";
export const HOME_CONFIG_RELATIVE = join(".dashmq", "config.json");

export interface ResolveOptions {
  /** `--config <path>`. */
  configPath?: string | null;
  /** `$DASHMQ_CONFIG`. */
  env?: string | null;
  cwd?: string;
  homeDir?: string;
}

interface Candidate {
  path: string;
  source: RedactionConfigSource;
  /** An explicitly named file that does not exist is an error, not a miss. */
  required: boolean;
}

function candidates(options: ResolveOptions): Candidate[] {
  const cwd = options.cwd ?? process.cwd();
  const home = options.homeDir ?? homedir();
  const list: Candidate[] = [];

  const flag = options.configPath?.trim();
  if (flag) list.push({ path: resolvePath(cwd, flag), source: "flag", required: true });

  const env = options.env?.trim();
  if (env) list.push({ path: resolvePath(cwd, env), source: "env", required: true });

  list.push({ path: resolvePath(cwd, CWD_CONFIG_FILENAME), source: "cwd", required: false });
  list.push({ path: join(home, HOME_CONFIG_RELATIVE), source: "home", required: false });

  return list;
}

function readIfPresent(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch (error: any) {
    if (error && (error.code === "ENOENT" || error.code === "ENOTDIR")) return null;
    fail(`cannot read redaction policy at ${path}: ${error?.message || error}`);
  }
}

/**
 * Find and parse the policy. First hit wins; nothing is merged across files.
 *
 * Order: `--config` -> `$DASHMQ_CONFIG` -> `./dashmq.config.json` ->
 * `~/.dashmq/config.json`. None of these can be influenced by the server.
 */
export function loadRedactionConfig(
  options: ResolveOptions = {}
): LoadedRedactionConfig {
  const env = options.env !== undefined ? options.env : process.env.DASHMQ_CONFIG ?? null;

  for (const candidate of candidates({ ...options, env })) {
    const contents = readIfPresent(candidate.path);

    if (contents === null) {
      if (candidate.required) {
        fail(
          `redaction policy not found at ${candidate.path} ` +
            `(named by ${candidate.source === "flag" ? "--config" : "DASHMQ_CONFIG"})`
        );
      }
      continue;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(contents);
    } catch (error: any) {
      fail(`redaction policy at ${candidate.path} is not valid JSON: ${error?.message || error}`);
    }

    let config: NormalizedRedactionConfig;
    try {
      config = normalizeRedactionConfig(parsed);
    } catch (error: any) {
      fail(`redaction policy at ${candidate.path} is invalid: ${error?.message || error}`);
    }

    return {
      config,
      policyId: computePolicyId(config),
      path: candidate.path,
      source: candidate.source,
    };
  }

  const config = absentConfig();
  return { config, policyId: computePolicyId(config), path: null, source: "absent" };
}

// ---------------------------------------------------------------------------
// Local salt
// ---------------------------------------------------------------------------

export const SALT_RELATIVE_PATH = join(".dashmq", "salt");

export function defaultSaltPath(homeDir?: string): string {
  return join(homeDir ?? homedir(), SALT_RELATIVE_PATH);
}

const SALT_BYTES = 32;

/**
 * Read (creating on first use) the machine-local salt used by the `hash`
 * strategy.
 *
 * This file never leaves the machine and is never sent anywhere. That is the
 * whole point: `sha256(value + salt)` is stable enough for the dashboard to
 * say "1,203 failures carry the same customer reference" and useless to anyone
 * — including us — who wants to know what that reference is.
 */
export function readOrCreateLocalSalt(saltPath: string): string {
  try {
    const existing = readFileSync(saltPath, "utf8").trim();
    if (existing.length > 0) return existing;
  } catch (error: any) {
    if (error && error.code !== "ENOENT" && error.code !== "ENOTDIR") {
      fail(`cannot read local salt at ${saltPath}: ${error?.message || error}`);
    }
  }

  const salt = randomBytes(SALT_BYTES).toString("hex");

  try {
    mkdirSync(dirname(saltPath), { recursive: true, mode: 0o700 });
    // "wx" fails if the file appeared between the read and now, so two
    // connectors starting together cannot end up with different salts.
    writeFileSync(saltPath, `${salt}\n`, { mode: 0o600, flag: "wx" });
    return salt;
  } catch (error: any) {
    if (error && error.code === "EEXIST") {
      // Either another connector won the race, or the path is not writable for
      // a duller reason (a file where a directory should be). Re-reading is the
      // cheap way to tell them apart, and it must not itself escape as a raw
      // filesystem error — the caller is entitled to a message it can act on.
      try {
        const raced = readFileSync(saltPath, "utf8").trim();
        if (raced.length > 0) return raced;
      } catch {
        // Fall through to the clear error below.
      }
    }
    fail(
      `cannot create local salt at ${saltPath}: ${error?.message || error}. ` +
        `The "hash" redaction strategy needs it; use "label" or fix the path.`
    );
  }
}
