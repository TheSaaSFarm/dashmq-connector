// Where the policy comes from, and what happens when it is wrong.
//
// Two claims are being defended here. First, the policy is a local file and
// only a local file: there is no code path by which the backend can supply,
// override, or read one. Second, the connector fails closed — an unreadable
// policy stops it, and an absent policy is mode "none" rather than "off".
//
//   npm test        (builds, then runs)
//   node --test tests/

const test = require("node:test");
const assert = require("node:assert/strict");
const { mkdtempSync, mkdirSync, writeFileSync, readFileSync, statSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join } = require("node:path");

const {
  loadRedactionConfig,
  normalizeRedactionConfig,
  computePolicyId,
  readOrCreateLocalSalt,
  defaultSaltPath,
  RedactionConfigError,
  DETECTOR_NAMES,
} = require("../dist/redaction-config");
const { RedactionEngine } = require("../dist/redaction");

function sandbox() {
  return mkdtempSync(join(tmpdir(), "dashmq-config-"));
}

function write(dir, relative, contents) {
  const path = join(dir, relative);
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(
    path,
    typeof contents === "string" ? contents : JSON.stringify(contents),
    "utf8"
  );
  return path;
}

function load(dir, extra = {}) {
  return loadRedactionConfig({ env: null, cwd: dir, homeDir: dir, ...extra });
}

const MINIMAL = { version: 1, redaction: { default: { mode: "redact" } } };

// ---------------------------------------------------------------------------
// Resolution order
// ---------------------------------------------------------------------------

test("resolution order: --config beats $DASHMQ_CONFIG beats ./ beats ~/", () => {
  const dir = sandbox();
  write(dir, "flag.json", { version: 1, redaction: { default: { mode: "all" } } });
  write(dir, "env.json", { version: 1, redaction: { default: { mode: "allowlist" } } });
  write(dir, "dashmq.config.json", { version: 1, redaction: { default: { mode: "redact" } } });
  write(dir, ".dashmq/config.json", { version: 1, redaction: { default: { mode: "none" } } });

  assert.equal(
    load(dir, { configPath: "flag.json", env: "env.json" }).config.default.mode,
    "all"
  );
  assert.equal(load(dir, { env: "env.json" }).config.default.mode, "allowlist");
  assert.equal(load(dir).config.default.mode, "redact");
});

test("resolution falls through to ~/.dashmq/config.json", () => {
  const dir = sandbox();
  write(dir, ".dashmq/config.json", { version: 1, redaction: { default: { mode: "all" } } });

  const loaded = load(dir);
  assert.equal(loaded.config.default.mode, "all");
  assert.equal(loaded.source, "home");
  assert.equal(loaded.path, join(dir, ".dashmq", "config.json"));
});

test("first hit wins outright — policies are never merged across files", () => {
  const dir = sandbox();
  write(dir, "dashmq.config.json", {
    version: 1,
    redaction: { default: { mode: "redact", deny: ["a"] } },
  });
  write(dir, ".dashmq/config.json", {
    version: 1,
    redaction: { default: { mode: "all", deny: ["b"] }, queues: { q: { mode: "all" } } },
  });

  const loaded = load(dir);
  assert.deepEqual(loaded.config.default.deny, ["a"]);
  assert.deepEqual(Object.keys(loaded.config.queues), []);
});

test("an explicitly named policy that does not exist is an error, not a fallback", () => {
  const dir = sandbox();
  // A perfectly good policy sits right there; naming a missing one must still
  // stop the connector rather than silently using it.
  write(dir, "dashmq.config.json", MINIMAL);

  assert.throws(
    () => load(dir, { configPath: "nope.json" }),
    (error) => {
      assert.ok(error instanceof RedactionConfigError);
      assert.match(error.message, /not found/);
      assert.match(error.message, /--config/);
      return true;
    }
  );

  assert.throws(() => load(dir, { env: "nope.json" }), /DASHMQ_CONFIG/);
});

// ---------------------------------------------------------------------------
// Fail closed
// ---------------------------------------------------------------------------

test("an absent policy is mode redact, not mode off", () => {
  const loaded = load(sandbox());

  assert.equal(loaded.path, null);
  assert.equal(loaded.source, "absent");
  // Not "off" (which would ship the feature disabled) and not "none" (which
  // would blank the cached payloads of every installation that upgraded without
  // asking for anything). Every detector is on, and the connector says so at
  // startup.
  assert.equal(loaded.config.default.mode, "redact");
  assert.deepEqual(loaded.config.default.detectors, [...DETECTOR_NAMES]);
  assert.equal(loaded.config.default.maxDepth, 8);
  assert.equal(loaded.config.default.maxStringLength, 2048);
  // Even with no file there is a policy id to report.
  assert.match(loaded.policyId, /^sha256:[0-9a-f]{64}$/);
});

test("unparseable JSON stops the connector", () => {
  const dir = sandbox();
  write(dir, "dashmq.config.json", "{ not json ");

  assert.throws(() => load(dir), (error) => {
    assert.ok(error instanceof RedactionConfigError);
    assert.match(error.message, /not valid JSON/);
    assert.match(error.message, /dashmq\.config\.json/);
    return true;
  });
});

test("a typo in a policy key is refused rather than ignored", () => {
  // "denny" silently ignored is the exact failure this feature exists to
  // prevent: the customer believes a path is protected and it is not.
  assert.throws(
    () => normalizeRedactionConfig({ version: 1, redaction: { default: { denny: ["x"] } } }),
    /unknown key "denny"/
  );
  assert.throws(
    () => normalizeRedactionConfig({ version: 1, redactions: {} }),
    /unknown key "redactions"/
  );
});

test("every field is validated, none is coerced", () => {
  const broken = [
    [{}, /version is required/],
    [{ version: 2, redaction: {} }, /not supported/],
    [{ version: 1 }, /redaction is required/],
    [{ version: 1, redaction: { default: { mode: "REDACT" } } }, /must be one of/],
    [{ version: 1, redaction: { default: { mode: "off" } } }, /must be one of/],
    [{ version: 1, redaction: { default: { strategy: "sha256" } } }, /must be one of/],
    [{ version: 1, redaction: { default: { deny: "x" } } }, /must be an array/],
    [{ version: 1, redaction: { default: { deny: [""] } } }, /non-empty string/],
    [{ version: 1, redaction: { default: { detectors: ["ssn"] } } }, /must be one of/],
    [{ version: 1, redaction: { default: { maxDepth: 0 } } }, /between/],
    [{ version: 1, redaction: { default: { maxDepth: 1.5 } } }, /must be an integer/],
    [{ version: 1, redaction: { default: { maxStringLength: -1 } } }, /between/],
    [{ version: 1, redaction: { queues: [] } }, /must be an object/],
    [{ version: 1, redaction: { queues: { q: { mode: "nope" } } } }, /must be one of/],
  ];

  for (const [config, pattern] of broken) {
    assert.throws(
      () => normalizeRedactionConfig(config),
      pattern,
      `expected ${JSON.stringify(config)} to be rejected`
    );
  }
});

test("a malformed path pattern stops the connector at startup", () => {
  const dir = sandbox();
  write(dir, "dashmq.config.json", {
    version: 1,
    redaction: { default: { mode: "redact", deny: ["items[.serial"] } },
  });

  // The file parses; the pattern does not. Compiling eagerly is what turns
  // that into a startup failure instead of a job that quietly ships a serial.
  assert.throws(
    () => new RedactionEngine({ env: null, cwd: dir, homeDir: dir, saltPath: join(dir, "salt") }),
    RedactionConfigError
  );
});

// ---------------------------------------------------------------------------
// Inheritance
// ---------------------------------------------------------------------------

test("a queue override inherits the fields it does not restate", () => {
  const config = normalizeRedactionConfig({
    version: 1,
    redaction: {
      default: {
        mode: "redact",
        strategy: "hash",
        detectors: ["email"],
        maxDepth: 4,
        deny: ["**.password"],
      },
      queues: { payments: { mode: "allowlist", allow: ["orderId"] } },
    },
  });

  const payments = config.queues.payments;
  assert.equal(payments.mode, "allowlist");
  assert.deepEqual(payments.allow, ["orderId"]);
  assert.equal(payments.strategy, "hash");
  assert.deepEqual(payments.detectors, ["email"]);
  assert.equal(payments.maxDepth, 4);
  // Arrays replace rather than concatenate, so a rule can be read on its own.
  assert.deepEqual(payments.deny, ["**.password"]);
});

test("detectors are normalised to canonical order regardless of how they are written", () => {
  const a = normalizeRedactionConfig({
    version: 1,
    redaction: { default: { detectors: ["phone", "email", "jwt"] } },
  });
  const b = normalizeRedactionConfig({
    version: 1,
    redaction: { default: { detectors: ["jwt", "phone", "email", "phone"] } },
  });
  assert.deepEqual(a.default.detectors, b.default.detectors);
  assert.deepEqual(a.default.detectors, ["jwt", "email", "phone"]);
});

// ---------------------------------------------------------------------------
// Policy identity
// ---------------------------------------------------------------------------

test("the policy id changes when behaviour changes, and only then", () => {
  const base = { version: 1, redaction: { default: { mode: "redact", deny: ["a", "b"] } } };
  const reordered = {
    redaction: { default: { deny: ["a", "b"], mode: "redact" } },
    version: 1,
  };
  const different = { version: 1, redaction: { default: { mode: "redact", deny: ["a"] } } };

  const id = (config) => computePolicyId(normalizeRedactionConfig(config));

  assert.match(id(base), /^sha256:[0-9a-f]{64}$/);
  // Key order and whitespace are cosmetics; the id must not move for them.
  assert.equal(id(base), id(reordered));
  assert.notEqual(id(base), id(different));

  // Writing out an inherited default explicitly is not a change either.
  assert.equal(
    id(base),
    id({
      version: 1,
      redaction: {
        default: { mode: "redact", deny: ["a", "b"], strategy: "label", maxDepth: 8 },
      },
    })
  );
});

test("the policy id is reported without the policy", () => {
  const dir = sandbox();
  write(dir, "dashmq.config.json", {
    version: 1,
    redaction: { default: { mode: "redact", deny: ["customer.taxId"] } },
  });

  const engine = new RedactionEngine({
    env: null,
    cwd: dir,
    homeDir: dir,
    saltPath: join(dir, "salt"),
  });

  assert.match(engine.policyId, /^sha256:[0-9a-f]{64}$/);
  // Nothing that travels to the server names a path, a queue, or a rule.
  assert.equal(engine.policyId.includes("taxId"), false);
  assert.equal(engine.describe().includes("taxId"), false);
});

// ---------------------------------------------------------------------------
// Local salt
// ---------------------------------------------------------------------------

test("the salt is generated once, kept private, and reused", () => {
  const dir = sandbox();
  const path = join(dir, ".dashmq", "salt");

  const first = readOrCreateLocalSalt(path);
  assert.match(first, /^[0-9a-f]{64}$/);
  assert.equal(readOrCreateLocalSalt(path), first, "the salt must be stable");
  assert.equal(readFileSync(path, "utf8").trim(), first);

  // Owner-only: the salt is what makes a hash useless to anyone else.
  assert.equal(statSync(path).mode & 0o777, 0o600);
});

test("the salt lives on the customer's machine and nowhere else", () => {
  assert.equal(defaultSaltPath("/home/someone"), "/home/someone/.dashmq/salt");
});

test('the "hash" strategy resolves its salt at startup, not mid-transmission', () => {
  const dir = sandbox();
  write(dir, "dashmq.config.json", {
    version: 1,
    redaction: { default: { mode: "redact", strategy: "hash" } },
  });

  // A salt path that cannot exist: better to refuse to start than to discover
  // it while a job is halfway out of the door.
  assert.throws(
    () =>
      new RedactionEngine({
        env: null,
        cwd: dir,
        homeDir: dir,
        saltPath: join(dir, "dashmq.config.json", "salt"),
      }),
    RedactionConfigError
  );
});

test('the "label" strategy never touches the salt file', () => {
  const dir = sandbox();
  write(dir, "dashmq.config.json", MINIMAL);
  const saltPath = join(dir, "salt");

  const engine = new RedactionEngine({ env: null, cwd: dir, homeDir: dir, saltPath });
  engine.redactJob("bull", "q", {
    id: "1",
    name: "n",
    status: "FAILED",
    data: { email: "bob@example.com" },
    opts: {},
    returnValue: null,
    progress: 0,
    timestamp: 0,
    processedOn: null,
    finishedOn: null,
    failedReason: null,
    stacktrace: null,
    attemptsMade: 0,
    attemptsStarted: 0,
    maxAttempts: 0,
    processedBy: null,
  });

  assert.throws(() => statSync(saltPath), /ENOENT/);
});
