// The redaction walk.
//
// This is the security boundary. Everything a job carries out of the connector
// goes through one tree walk, and these tests are what stop that walk from
// quietly acquiring a hole: a dropped key, a subtree that escapes a denylist, a
// cycle that hangs the process, a "__proto__" that stops being data.
//
//   npm test        (builds, then runs)
//   node --test tests/

const test = require("node:test");
const assert = require("node:assert/strict");
const { mkdtempSync, writeFileSync, mkdirSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join } = require("node:path");

const { RedactionEngine, compilePolicy } = require("../dist/redaction");
const { defaultRule } = require("../dist/redaction-config");

function policy(overrides = {}) {
  return compilePolicy({ ...defaultRule(), ...overrides }, () => "test-salt");
}

function redact(value, overrides = {}) {
  return policy(overrides).redactPayload(value, "");
}

/** An isolated home + cwd, so no test can read or write the real ~/.dashmq. */
function sandbox(config) {
  const dir = mkdtempSync(join(tmpdir(), "dashmq-redaction-"));
  if (config !== undefined) {
    writeFileSync(join(dir, "dashmq.config.json"), JSON.stringify(config), "utf8");
  }
  return dir;
}

function engineIn(dir) {
  return new RedactionEngine({
    env: null,
    cwd: dir,
    homeDir: dir,
    saltPath: join(dir, "salt"),
  });
}

function job(overrides = {}) {
  return {
    id: "42",
    name: "send-email",
    status: "FAILED",
    data: { to: "user@example.com", orderId: "ord_9" },
    opts: { attempts: 3 },
    returnValue: null,
    progress: 0,
    timestamp: 1_700_000_000_000,
    processedOn: 1_700_000_001_000,
    finishedOn: 1_700_000_002_000,
    failedReason: "SMTP rejected user@example.com",
    stacktrace: "Error: SMTP rejected user@example.com\n    at send (smtp.js:1:1)",
    attemptsMade: 2,
    attemptsStarted: 2,
    maxAttempts: 3,
    processedBy: "worker-1",
    ...overrides,
  };
}

/** Every own key, at every level, as a sorted list of paths. */
function keyPaths(value, prefix = "", out = []) {
  if (value === null || typeof value !== "object") return out;
  if (Array.isArray(value)) {
    value.forEach((entry, i) => keyPaths(entry, `${prefix}[${i}]`, out));
    return out;
  }
  for (const key of Object.keys(value)) {
    const path = prefix ? `${prefix}.${key}` : key;
    out.push(path);
    keyPaths(value[key], path, out);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Modes
// ---------------------------------------------------------------------------

test('mode "none" transmits key names and value types, never values', () => {
  const { value, redacted } = redact(
    {
      email: "bob@example.com",
      amountCents: 4200,
      paid: true,
      missing: null,
      nested: { ssn: "123-45-6789" },
      list: ["a", 1],
    },
    { mode: "none" }
  );

  assert.deepEqual(value, {
    email: "<type:string>",
    amountCents: "<type:number>",
    paid: "<type:boolean>",
    missing: null,
    nested: { ssn: "<type:string>" },
    list: ["<type:string>", "<type:number>"],
  });
  // Under "none" everything is redacted, so listing the paths would restate the
  // mode at the size of the payload.
  assert.deepEqual(redacted, []);
});

test('mode "none" suppresses free text too, not just payload leaves', () => {
  // The detectors find an email and a card number. They do not find a name, a
  // postal address, a date of birth or an order reference — and those are what
  // a failedReason or a log line is made of. If free text went through under
  // "none", the documented promise would be false for the surface that carries
  // the most prose.
  const none = policy({ mode: "none" });

  assert.equal(
    none.redactText("Payment failed for John Smith, 12 Rue de la Paix, DOB 1984-03-02"),
    "<type:string>"
  );
  assert.deepEqual(
    none.redactLogLines([
      "processing order for Jane Doe, acct 998877, addr 5 Elm St",
      "done",
    ]),
    ["<type:string>", "<type:string>"]
  );
  // Line count is shape, not content, so it survives.
  assert.equal(none.redactLogLines(["a", "b", "c"]).length, 3);
  assert.equal(none.redactText(null), null);
  assert.equal(none.redactText(""), "");
});

test('an absent policy resolves to mode "redact", loudly', () => {
  // The migration decision, pinned down. Defaulting to "none" would blank every
  // payload the dashboard had cached for every installation that upgraded
  // without changing anything; defaulting to "all" would ship the feature off.
  // "redact" is the only default that is better than both, and it is announced.
  const engine = engineIn(sandbox());
  assert.equal(engine.defaultMode, "redact");
  assert.equal(engine.configPath, null);
  assert.equal(engine.isDefaultPolicy, true);

  const result = engine.redactJob("bull", "emails", job());
  // The order id survives — an upgrading customer does not lose their payloads.
  assert.equal(result.data.orderId, "ord_9");
  // The email does not.
  assert.equal(result.data.to, "<redacted:email>");
  assert.equal(result._dashmq.mode, "redact");

  const warnings = engine.warnings().join(" ");
  assert.match(warnings, /No redaction policy found/);
  assert.match(warnings, /ARE transmitted/);
  // And it says how to get the strictest mode, not just that it exists.
  assert.match(warnings, /"mode": "none"/);
  assert.match(engine.describe(), /no policy file found/);
});

test("a configured policy warns about nothing", () => {
  const engine = engineIn(sandbox({ version: 1, redaction: { default: { mode: "none" } } }));
  assert.equal(engine.isDefaultPolicy, false);
  assert.deepEqual(engine.warnings(), []);
});

test('mode "redact" removes denied paths and detector hits, keeps the rest', () => {
  const { value, redacted } = redact(
    {
      orderId: "ord_9",
      amountCents: 4200,
      user: { email: "bob@example.com", password: "hunter2", name: "Bob" },
      items: [
        { sku: "A1", serialNumber: "SN-0001" },
        { sku: "B2", serialNumber: "SN-0002" },
      ],
    },
    { mode: "redact", deny: ["**.password", "items[*].serialNumber"] }
  );

  assert.deepEqual(value, {
    orderId: "ord_9",
    amountCents: 4200,
    user: {
      email: "<redacted:email>", // detector, not a denylist path
      password: "<redacted:path>",
      name: "Bob",
    },
    items: [
      { sku: "A1", serialNumber: "<redacted:path>" },
      { sku: "B2", serialNumber: "<redacted:path>" },
    ],
  });

  assert.deepEqual(redacted.sort(), [
    "items[0].serialNumber",
    "items[1].serialNumber",
    "user.email",
    "user.password",
  ]);
});

test('mode "redact" removes a denied subtree whole, without dropping its key', () => {
  const { value } = redact(
    { billing: { card: { number: "4111111111111111", expiry: "12/29" } }, id: 1 },
    { mode: "redact", deny: ["billing.card"] }
  );

  assert.deepEqual(value, { billing: { card: "<redacted:path>" }, id: 1 });
});

test('mode "allowlist" keeps only listed paths and marks everything else', () => {
  const { value, redacted } = redact(
    {
      orderId: "ord_9",
      amountCents: 4200,
      user: { email: "bob@example.com", name: "Bob" },
    },
    { mode: "allowlist", allow: ["orderId", "amountCents"] }
  );

  assert.deepEqual(value, {
    orderId: "ord_9",
    amountCents: 4200,
    // The shape survives even though nothing in it does.
    user: { email: "<redacted:path>", name: "<redacted:path>" },
  });
  assert.deepEqual(redacted.sort(), ["user.email", "user.name"]);
});

test('mode "allowlist": a named leaf is verbatim, a named container is only a scope', () => {
  // Allowing a path exactly is an instruction about that value, so a detector
  // must not second-guess it — otherwise the allowlist means nothing. Allowing
  // a CONTAINER is an instruction about scope, not a certificate that every
  // value beneath it is safe, so the detectors keep working inside it.
  const named = redact(
    { contact: { email: "bob@example.com" }, secret: "x" },
    { mode: "allowlist", allow: ["contact.email"] }
  );
  assert.deepEqual(named.value, {
    contact: { email: "bob@example.com" },
    secret: "<redacted:path>",
  });

  const scoped = redact(
    { contact: { email: "bob@example.com", note: "call back" }, secret: "x" },
    { mode: "allowlist", allow: ["contact"] }
  );
  assert.deepEqual(scoped.value, {
    contact: { email: "<redacted:email>", note: "call back" },
    secret: "<redacted:path>",
  });
});

test('mode "allowlist" honours deny, and deny wins over allow', () => {
  // The finding this test exists for: `deny` used to be accepted by the config
  // validator and then ignored at runtime under allowlist, so a policy whose
  // author wrote BOTH transmitted the password anyway.
  const { value, redacted } = redact(
    { user: { name: "n", password: "hunter2", email: "a@b.com" }, other: "z" },
    { mode: "allowlist", allow: ["user"], deny: ["user.password"] }
  );

  assert.deepEqual(value, {
    user: { name: "n", password: "<redacted:path>", email: "<redacted:email>" },
    other: "<redacted:path>",
  });
  assert.equal(redacted.includes("user.password"), true);
  assert.equal(JSON.stringify(value).includes("hunter2"), false);
});

test('mode "redact": an exactly allowed path is exempt from the detectors', () => {
  // `allow` is not silently discarded under "redact" either: it is the way to
  // say "yes, I do want this one address" without turning every detector off.
  const { value } = redact(
    { contact: { email: "bob@example.com" }, other: { email: "eve@example.com" } },
    { mode: "redact", allow: ["contact.email"] }
  );

  assert.deepEqual(value, {
    contact: { email: "bob@example.com" },
    other: { email: "<redacted:email>" },
  });
});

test('mode "all" is verbatim', () => {
  const payload = {
    user: { email: "bob@example.com", password: "hunter2" },
    items: [{ serialNumber: "SN-1" }],
  };
  const { value, redacted } = redact(payload, { mode: "all", deny: [] });

  assert.deepEqual(value, payload);
  assert.deepEqual(redacted, []);
  assert.notEqual(value, payload, "the payload is copied, never handed out by reference");
});

test('mode "all" still honours deny, because deny means never', () => {
  // "all" describes the baseline, not a licence to void the one construct whose
  // entire purpose is "do not transmit this". A rule that inherits a denylist
  // and switches to "all" must not quietly start shipping the denied paths;
  // true verbatim is written by restating `deny: []`, which arrays do because
  // they replace rather than concatenate.
  const { value, redacted } = redact(
    {
      user: { email: "bob@example.com", password: "hunter2" },
      items: [{ serialNumber: "SN-1" }],
    },
    { mode: "all", deny: ["**.password"] }
  );

  assert.deepEqual(value, {
    user: { email: "bob@example.com", password: "<redacted:path>" },
    items: [{ serialNumber: "SN-1" }],
  });
  assert.deepEqual(redacted, ["user.password"]);
});

// ---------------------------------------------------------------------------
// Shape preservation
// ---------------------------------------------------------------------------

test("no key is ever dropped, in any mode", () => {
  const payload = {
    a: "bob@example.com",
    b: { c: "hunter2", d: [1, { e: "x" }] },
    f: [],
    g: {},
    h: null,
  };
  const expected = keyPaths(payload).sort();

  // A denied *container* legitimately collapses to a marker — that is the point
  // of denying it. What must never happen is a key disappearing from a level
  // that is transmitted at all, which is what these four policies exercise.
  const policies = [
    { mode: "none" },
    { mode: "redact", deny: ["b.c", "**.e"] },
    { mode: "allowlist", allow: [] },
    { mode: "all" },
  ];

  for (const overrides of policies) {
    const { value } = redact(payload, overrides);
    assert.deepEqual(
      keyPaths(value).sort(),
      expected,
      `mode ${overrides.mode} changed the key set`
    );
  }
});

test("an empty object is not the same as a hidden one", () => {
  // The reason shape matters: {"email": "<redacted:email>"} tells a model the
  // field exists and is hidden; {} tells it the field was missing, and it goes
  // on to misdiagnose the bug.
  const { value } = redact({ email: "bob@example.com" }, { mode: "redact" });
  assert.equal("email" in value, true);
  assert.equal(value.email, "<redacted:email>");
});

test("array length and element positions are preserved", () => {
  const { value } = redact(
    { list: ["bob@example.com", "safe", "alice@example.com"] },
    { mode: "redact" }
  );
  assert.deepEqual(value.list, ["<redacted:email>", "safe", "<redacted:email>"]);
});

// ---------------------------------------------------------------------------
// Awkward inputs
// ---------------------------------------------------------------------------

test("a payload that is a string rather than an object", () => {
  // parseJobHash falls back to the raw string when a job's data is not JSON.
  assert.equal(redact("bob@example.com", { mode: "redact" }).value, "<redacted:email>");
  assert.equal(redact("plain text", { mode: "redact" }).value, "plain text");
  assert.equal(redact("bob@example.com", { mode: "none" }).value, "<type:string>");
  assert.equal(redact("bob@example.com", { mode: "all" }).value, "bob@example.com");

  // A root-level redaction is reported under the tree's own name.
  assert.deepEqual(redact("bob@example.com", { mode: "redact" }).redacted, ["data"]);
  assert.deepEqual(
    policy({ mode: "redact" }).redactPayload("bob@example.com", "returnValue").redacted,
    ["returnValue"]
  );
});

test("a payload that is a bare scalar or nothing at all", () => {
  assert.equal(redact(null, { mode: "redact" }).value, null);
  assert.equal(redact(undefined, { mode: "redact" }).value, null);
  assert.equal(redact(7, { mode: "redact" }).value, 7);
  assert.equal(redact(false, { mode: "none" }).value, "<type:boolean>");
  assert.deepEqual(redact([], { mode: "redact" }).value, []);
});

test("arrays of arrays are walked to the leaves", () => {
  const { value, redacted } = redact(
    { grid: [[["bob@example.com", "ok"]], [["alice@example.com"]]] },
    { mode: "redact" }
  );

  assert.deepEqual(value.grid, [
    [["<redacted:email>", "ok"]],
    [["<redacted:email>"]],
  ]);
  assert.deepEqual(redacted.sort(), ["grid[0][0][0]", "grid[1][0][0]"]);
});

test("array indices in a denylist address the right elements", () => {
  const { value } = redact(
    { rows: [[1, 2], [3, 4]] },
    { mode: "redact", deny: ["rows[1][0]"] }
  );
  assert.deepEqual(value.rows, [[1, 2], ["<redacted:path>", 4]]);
});

test("a cyclic payload terminates instead of hanging", () => {
  const node = { name: "root", email: "bob@example.com" };
  node.self = node;
  node.children = [{ parent: node }];

  const { value } = redact(node, { mode: "redact" });

  assert.equal(value.name, "root");
  assert.equal(value.email, "<redacted:email>");
  assert.equal(value.self, "<circular>");
  assert.equal(value.children[0].parent, "<circular>");
  // And the result is serialisable, which the input was not.
  assert.doesNotThrow(() => JSON.stringify(value));
});

test("two references to the same object are not mistaken for a cycle", () => {
  const shared = { email: "bob@example.com" };
  const { value } = redact({ a: shared, b: shared }, { mode: "redact" });

  assert.deepEqual(value.a, { email: "<redacted:email>" });
  assert.deepEqual(value.b, { email: "<redacted:email>" });
});

test('a payload key called "__proto__" stays data and pollutes nothing', () => {
  const payload = JSON.parse('{"__proto__": {"polluted": true}, "safe": 1}');

  for (const mode of ["none", "redact", "all"]) {
    const { value } = redact(payload, { mode });

    assert.equal(
      Object.getOwnPropertyNames(value).includes("__proto__"),
      true,
      `mode ${mode} dropped the __proto__ key`
    );
    assert.equal(
      Object.getPrototypeOf(value),
      Object.prototype,
      `mode ${mode} reparented the output object`
    );
    assert.equal({}.polluted, undefined, `mode ${mode} polluted Object.prototype`);
    assert.equal(value.safe !== undefined, true);
  }
});

test("inherited properties are not transmitted", () => {
  const parent = { inherited: "bob@example.com" };
  const child = Object.create(parent);
  child.own = "value";

  const { value } = redact(child, { mode: "all" });

  assert.deepEqual(value, { own: "value" });
  assert.equal("inherited" in value, false);
});

test("a value that cannot be serialised is replaced, never shipped", () => {
  const { value } = redact(
    { fn: () => "secret", sym: Symbol("s"), ok: 1 },
    { mode: "all" }
  );
  assert.equal(value.fn, "<redacted:unsupported>");
  assert.equal(value.sym, "<redacted:unsupported>");
  assert.equal(value.ok, 1);
});

// ---------------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------------

test("maxDepth stops the walk and does not transmit what it did not inspect", () => {
  const deep = { l1: { l2: { l3: { l4: { secret: "bob@example.com" } } } } };

  // The root is depth 0, so maxDepth 3 transmits three levels of keys and
  // stops at the fourth — whose contents are therefore never inspected, and
  // never shipped.
  const { value, redacted } = redact(deep, { mode: "all", maxDepth: 3 });

  assert.deepEqual(value, { l1: { l2: { l3: { l4: "<redacted:depth>" } } } });
  assert.deepEqual(redacted, ["l1.l2.l3.l4"]);
  assert.equal(JSON.stringify(value).includes("bob@example.com"), false);
});

test("maxDepth applies in every mode", () => {
  const deep = { a: { b: { c: { d: "x" } } } };
  for (const mode of ["none", "redact", "allowlist", "all"]) {
    const { value } = redact(deep, { mode, maxDepth: 2, allow: ["**"] });
    assert.equal(
      JSON.stringify(value),
      '{"a":{"b":{"c":"<redacted:depth>"}}}',
      `mode ${mode} walked past maxDepth`
    );
  }
});

test("maxStringLength truncates and says by how much", () => {
  const blob = "A".repeat(5000);
  const { value, redacted } = redact({ blob }, { mode: "all", maxStringLength: 100 });

  assert.equal(value.blob, `${"A".repeat(100)}…<truncated:5000>`);
  assert.deepEqual(redacted, ["blob"]);
});

test("truncation happens before detection, so the tail can never leak", () => {
  const text = `${"x".repeat(50)}bob@example.com`;
  const { value } = redact({ note: text }, { mode: "redact", maxStringLength: 20 });

  assert.equal(value.note, `${"x".repeat(20)}…<truncated:65>`);
  assert.equal(value.note.includes("bob@example.com"), false);
});

test("the reported path list is bounded", () => {
  const wide = {};
  for (let i = 0; i < 500; i++) wide[`k${i}`] = "bob@example.com";

  const { redacted } = redact(wide, { mode: "redact" });
  assert.equal(redacted.length, 200);
});

// ---------------------------------------------------------------------------
// Job-level application
// ---------------------------------------------------------------------------

test("redactJob covers data, opts, returnValue, failedReason and the stack trace", () => {
  const dir = sandbox({
    version: 1,
    redaction: { default: { mode: "redact", deny: ["**.password"] } },
  });
  const engine = engineIn(dir);

  const result = engine.redactJob(
    "bull",
    "emails",
    job({
      data: { to: "user@example.com", password: "hunter2", orderId: "ord_9" },
      opts: { attempts: 3, jobId: "bob@example.com" },
      returnValue: { receipt: "alice@example.com", ok: true },
    })
  );

  assert.deepEqual(result.data, {
    to: "<redacted:email>",
    password: "<redacted:path>",
    orderId: "ord_9",
  });
  assert.deepEqual(result.opts, { attempts: 3, jobId: "<redacted:email>" });
  assert.deepEqual(result.returnValue, { receipt: "<redacted:email>", ok: true });
  assert.equal(result.failedReason, "SMTP rejected <redacted:email>");
  assert.equal(result.stacktrace.includes("user@example.com"), false);
  assert.equal(result.stacktrace.includes("at send (smtp.js:1:1)"), true);

  // Metadata is not payload and is never touched.
  assert.equal(result.id, "42");
  assert.equal(result.attemptsMade, 2);
  assert.equal(result.maxAttempts, 3);
  assert.equal(result.processedBy, "worker-1");
});

test("the sidecar says what happened, and mirrors it where the dashboard reads it", () => {
  const dir = sandbox({
    version: 1,
    redaction: { default: { mode: "redact" } },
  });
  const engine = engineIn(dir);
  const result = engine.redactJob("bull", "emails", job());

  assert.deepEqual(result._dashmq.redacted.sort(), ["failedReason", "stackTrace", "to"]);
  assert.equal(result._dashmq.mode, "redact");
  assert.match(result._dashmq.policy, /^sha256:[0-9a-f]{64}$/);
  assert.equal(result._dashmq.policy, engine.policyId);

  // JobFailure.redactionMode / redactionPolicy / payloadRedacted already exist
  // on the dashboard side and are fed from these.
  assert.equal(result.redactionMode, result._dashmq.mode);
  assert.equal(result.redactionPolicy, result._dashmq.policy);
  assert.deepEqual(result.payloadRedacted, result._dashmq.redacted);
});

test("per-queue overrides are keyed like the registry, and by bare name", () => {
  const engine = engineIn(
    sandbox({
      version: 1,
      redaction: {
        default: { mode: "none" },
        queues: {
          payments: { mode: "allowlist", allow: ["orderId"] },
          "custom:audit": { mode: "all" },
        },
      },
    })
  );

  const payload = { orderId: "ord_9", email: "bob@example.com" };

  assert.deepEqual(engine.redactJob("bull", "payments", job({ data: payload })).data, {
    orderId: "ord_9",
    email: "<redacted:path>",
  });
  assert.deepEqual(engine.redactJob("custom", "audit", job({ data: payload })).data, payload);
  assert.deepEqual(engine.redactJob("bull", "emails", job({ data: payload })).data, {
    orderId: "<type:string>",
    email: "<type:string>",
  });
  // A queue named "audit" under a different prefix does not inherit the
  // "custom:audit" override.
  assert.deepEqual(engine.redactJob("bull", "audit", job({ data: payload })).data, {
    orderId: "<type:string>",
    email: "<type:string>",
  });
});

test("a queue's policy is resolved once and then reused", () => {
  const engine = engineIn(sandbox());
  const first = engine.policyFor("bull", "emails");
  assert.equal(engine.policyFor("bull", "emails"), first);

  engine.prime([{ prefix: "bull", name: "emails" }, { prefix: "bull", name: "sms" }]);
  assert.equal(engine.policyFor("bull", "emails"), first);
});

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------

test("log lines get the detectors, because a denylist means nothing to free text", () => {
  const engine = engineIn(
    sandbox({ version: 1, redaction: { default: { mode: "redact", deny: ["**.email"] } } })
  );

  const lines = engine.redactLogs("bull", "emails", [
    "starting job for bob@example.com",
    "charging card 4111 1111 1111 1111",
    "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
    "nothing sensitive here",
  ]);

  assert.deepEqual(lines, [
    "starting job for <redacted:email>",
    "charging card <redacted:creditCard>",
    "token <redacted:jwt>",
    "nothing sensitive here",
  ]);
});

test("logs are scrubbed even under mode none, where there are no paths to deny", () => {
  const engine = engineIn(sandbox());
  assert.deepEqual(engine.redactLogs("bull", "emails", ["hi bob@example.com"]), [
    "hi <redacted:email>",
  ]);
});

test("logs are verbatim only under an explicit mode all", () => {
  const engine = engineIn(
    sandbox({ version: 1, redaction: { default: { mode: "all" } } })
  );
  assert.deepEqual(engine.redactLogs("bull", "emails", ["hi bob@example.com"]), [
    "hi bob@example.com",
  ]);
});

test("a log line longer than the guard is truncated", () => {
  const engine = engineIn(
    sandbox({
      version: 1,
      redaction: { default: { mode: "redact", maxStringLength: 10 } },
    })
  );
  assert.deepEqual(engine.redactLogs("bull", "emails", ["A".repeat(100)]), [
    `${"A".repeat(10)}…<truncated:100>`,
  ]);
});

// ---------------------------------------------------------------------------
// The hash strategy end to end
// ---------------------------------------------------------------------------

test("hash keeps values correlatable without ever disclosing them", () => {
  const dir = sandbox({
    version: 1,
    redaction: { default: { mode: "redact", strategy: "hash", deny: ["customerRef"] } },
  });
  mkdirSync(join(dir, ".dashmq"), { recursive: true });
  const engine = engineIn(dir);

  const a = engine.redactJob("bull", "q", job({ data: { customerRef: "cus_123" } }));
  const b = engine.redactJob("bull", "q", job({ data: { customerRef: "cus_123" } }));
  const c = engine.redactJob("bull", "q", job({ data: { customerRef: "cus_999" } }));

  assert.match(a.data.customerRef, /^<hash:[0-9a-f]{12}>$/);
  assert.equal(a.data.customerRef, b.data.customerRef, "same reference, same hash");
  assert.notEqual(a.data.customerRef, c.data.customerRef);
  assert.equal(JSON.stringify(a).includes("cus_123"), false);
});

// ---------------------------------------------------------------------------
// Reported paths
// ---------------------------------------------------------------------------

test("a dotted key is addressable, and reported unambiguously", () => {
  // A key that literally contains a "." is common — flattened form data, i18n
  // keys, metric names, Stripe metadata. Before the quoting form existed,
  // deny: ["a.b"] against {"a.b": …} validated cleanly, matched nothing, and
  // protected nothing.
  const quoted = redact({ "a.b": "x", a: { b: "y" } }, {
    mode: "redact",
    deny: ['["a.b"]'],
  });
  assert.deepEqual(quoted.value, { "a.b": "<redacted:path>", a: { b: "y" } });
  assert.deepEqual(quoted.redacted, ['["a.b"]']);

  const dotted = redact({ "a.b": "x", a: { b: "y" } }, {
    mode: "redact",
    deny: ["a.b"],
  });
  assert.deepEqual(dotted.value, { "a.b": "x", a: { b: "<redacted:path>" } });
  assert.deepEqual(dotted.redacted, ["a.b"]);

  // And the two shapes report distinguishable paths, so the sidecar can be used
  // to reason about which field actually went.
  const both = redact(
    { "a.b": { password: "x" }, a: { b: { password: "y" } } },
    { mode: "redact", deny: ["**.password"] }
  );
  assert.deepEqual(both.redacted.sort(), ['["a.b"].password', "a.b.password"]);

  // An empty key and a bracket-bearing key are quoted too.
  const odd = redact({ "": "x", "a[0]": "y" }, {
    mode: "redact",
    deny: ["*"],
  });
  assert.deepEqual(odd.redacted.sort(), ['[""]', '["a[0]"]']);
});

// ---------------------------------------------------------------------------
// Text fields are addressable
// ---------------------------------------------------------------------------

test("deny and allow reach failedReason, stackTrace and logs", () => {
  const denied = engineIn(
    sandbox({
      version: 1,
      redaction: { default: { mode: "redact", deny: ["stackTrace", "logs"] } },
    })
  );
  const result = denied.redactJob("bull", "emails", job());
  assert.equal(result.stacktrace, "<redacted:path>");
  assert.equal(result.failedReason, "SMTP rejected <redacted:email>");
  assert.deepEqual(denied.redactLogs("bull", "emails", ["anything at all"]), [
    "<redacted:path>",
  ]);

  // Under allowlist free text does not travel unless it was named — it is a
  // value like any other, and "only what I named" has to mean that.
  const strict = engineIn(
    sandbox({
      version: 1,
      redaction: { default: { mode: "allowlist", allow: ["orderId"] } },
    })
  );
  const quiet = strict.redactJob("bull", "emails", job());
  assert.equal(quiet.failedReason, "<redacted:path>");
  assert.equal(quiet.stacktrace, "<redacted:path>");

  const loud = engineIn(
    sandbox({
      version: 1,
      redaction: {
        default: { mode: "allowlist", allow: ["orderId", "failedReason"] },
      },
    })
  );
  assert.equal(
    loud.redactJob("bull", "emails", job()).failedReason,
    "SMTP rejected user@example.com"
  );
});
