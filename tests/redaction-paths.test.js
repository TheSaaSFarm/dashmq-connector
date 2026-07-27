// The path pattern language.
//
// A redactor that silently misses a path is worse than no redactor at all: the
// product then claims a protection it does not deliver. These tests exercise
// the matcher on its own rather than through a tree walk, so a wildcard that
// stops matching is a failing test and not a quiet leak.
//
//   npm test        (builds, then runs)
//   node --test tests/

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  parsePathPattern,
  compilePattern,
  matchPath,
} = require("../dist/redaction");
const { RedactionConfigError } = require("../dist/redaction-config");

function matches(source, path) {
  return matchPath(compilePattern(source), path).matches;
}

function canDescend(source, path) {
  return matchPath(compilePattern(source), path).canDescend;
}

test("parsePathPattern: plain keys", () => {
  assert.deepEqual(parsePathPattern("user.email"), [
    { kind: "key", name: "user" },
    { kind: "key", name: "email" },
  ]);
});

test("parsePathPattern: brackets, wildcards and mixtures", () => {
  assert.deepEqual(parsePathPattern("items[*].serialNumber"), [
    { kind: "key", name: "items" },
    { kind: "anyIndex" },
    { kind: "key", name: "serialNumber" },
  ]);
  assert.deepEqual(parsePathPattern("**.password"), [
    { kind: "anyDepth" },
    { kind: "key", name: "password" },
  ]);
  assert.deepEqual(parsePathPattern("a.*.b"), [
    { kind: "key", name: "a" },
    { kind: "any" },
    { kind: "key", name: "b" },
  ]);
  assert.deepEqual(parsePathPattern("rows[3][1]"), [
    { kind: "key", name: "rows" },
    { kind: "index", index: 3 },
    { kind: "index", index: 1 },
  ]);
  assert.deepEqual(parsePathPattern("[0].id"), [
    { kind: "index", index: 0 },
    { kind: "key", name: "id" },
  ]);
});

test("parsePathPattern: malformed patterns are config errors, not silent no-ops", () => {
  const broken = [
    "",
    "   ",
    ".",
    ".a",
    "a.",
    "a..b",
    "a[",
    "a[]",
    "a[x]",
    "a[1]b",
    "a]b",
    "part*ial",
    "**extra",
  ];

  for (const source of broken) {
    assert.throws(
      () => parsePathPattern(source),
      RedactionConfigError,
      `expected ${JSON.stringify(source)} to be rejected`
    );
  }
});

test("parsePathPattern: a pattern longer than the state machine is rejected", () => {
  const long = Array.from({ length: 31 }, (_, i) => `k${i}`).join(".");
  assert.throws(() => parsePathPattern(long), RedactionConfigError);
  // One shorter is fine.
  const fits = Array.from({ length: 30 }, (_, i) => `k${i}`).join(".");
  assert.equal(parsePathPattern(fits).length, 30);
});

test("exact paths match exactly", () => {
  assert.equal(matches("user.email", ["user", "email"]), true);
  assert.equal(matches("user.email", ["user", "Email"]), false);
  assert.equal(matches("user.email", ["user"]), false);
  assert.equal(matches("user.email", ["user", "email", "domain"]), false);
  assert.equal(matches("user.email", ["account", "user", "email"]), false);
  assert.equal(matches("orderId", ["orderId"]), true);
});

test("** matches at any depth, including zero", () => {
  assert.equal(matches("**.password", ["password"]), true);
  assert.equal(matches("**.password", ["a", "password"]), true);
  assert.equal(matches("**.password", ["a", "b", "c", "d", "password"]), true);
  assert.equal(matches("**.password", ["a", 0, "password"]), true);
  assert.equal(matches("**.password", ["password", "hint"]), false);
  assert.equal(matches("**.password", ["a", "passwordHint"]), false);
});

test("** in the middle spans any number of segments", () => {
  assert.equal(matches("a.**.z", ["a", "z"]), true);
  assert.equal(matches("a.**.z", ["a", "b", "z"]), true);
  assert.equal(matches("a.**.z", ["a", "b", 2, "c", "z"]), true);
  assert.equal(matches("a.**.z", ["b", "z"]), false);
});

test("* matches exactly one segment, key or index", () => {
  assert.equal(matches("user.*.token", ["user", "auth", "token"]), true);
  assert.equal(matches("user.*.token", ["user", 0, "token"]), true);
  assert.equal(matches("user.*.token", ["user", "token"]), false);
  assert.equal(matches("user.*.token", ["user", "a", "b", "token"]), false);
});

test("[*] matches any index and only an index", () => {
  assert.equal(matches("items[*].serialNumber", ["items", 0, "serialNumber"]), true);
  assert.equal(matches("items[*].serialNumber", ["items", 97, "serialNumber"]), true);
  // A string key that merely looks numeric is not an array index.
  assert.equal(matches("items[*].serialNumber", ["items", "0", "serialNumber"]), false);
  assert.equal(matches("items[*].serialNumber", ["items", "id", "serialNumber"]), false);
});

test("[n] pins a single index", () => {
  assert.equal(matches("items[0].sku", ["items", 0, "sku"]), true);
  assert.equal(matches("items[0].sku", ["items", 1, "sku"]), false);
});

test("nested arrays are addressable", () => {
  assert.equal(matches("grid[*][*]", ["grid", 0, 3]), true);
  assert.equal(matches("grid[*][*]", ["grid", 0]), false);
  assert.equal(matches("grid[1][2]", ["grid", 1, 2]), true);
  assert.equal(matches("grid[1][2]", ["grid", 2, 1]), false);
  assert.equal(matches("**.secret", ["grid", 0, 1, "secret"]), true);
});

test("canDescend drives allowlist traversal", () => {
  // "user" is not itself allowed, but it must be entered to reach user.email.
  assert.equal(canDescend("user.email", ["user"]), true);
  assert.equal(matches("user.email", ["user"]), false);

  // A fully matched leaf pattern has nothing deeper to offer.
  assert.equal(canDescend("user.email", ["user", "email"]), false);

  // A dead branch is neither.
  assert.equal(canDescend("user.email", ["billing"]), false);
  assert.equal(matches("user.email", ["billing"]), false);

  // ** can always match deeper.
  assert.equal(canDescend("**.password", ["a", "b"]), true);
});

// ---------------------------------------------------------------------------
// Quoted keys
//
// `.` and `[` are structural here and perfectly ordinary in a JSON key.
// Flattened form data, i18n keys, metric names and Stripe-style metadata maps
// all produce keys like "user.email". Without a quoting form an operator could
// write deny: ["customer.email"] against a literal key, watch it validate
// cleanly, and get no protection at all.
// ---------------------------------------------------------------------------

test("parsePathPattern: a quoted key is one literal segment", () => {
  assert.deepEqual(parsePathPattern('["a.b"]'), [{ kind: "key", name: "a.b" }]);
  assert.deepEqual(parsePathPattern("['a.b'].c"), [
    { kind: "key", name: "a.b" },
    { kind: "key", name: "c" },
  ]);
  assert.deepEqual(parsePathPattern('user["first.name"]'), [
    { kind: "key", name: "user" },
    { kind: "key", name: "first.name" },
  ]);
  // A quoted key is literal: no wildcard, no separator, no index.
  assert.deepEqual(parsePathPattern('["*"]'), [{ kind: "key", name: "*" }]);
  assert.deepEqual(parsePathPattern('["0"]'), [{ kind: "key", name: "0" }]);
  // Escapes, so a key can contain the quote itself.
  assert.deepEqual(parsePathPattern('["a\\"b"]'), [{ kind: "key", name: 'a"b' }]);
  assert.deepEqual(parsePathPattern('["a[b]"]'), [{ kind: "key", name: "a[b]" }]);
});

test("a quoted key addresses the literal key and nothing else", () => {
  assert.equal(matches('["a.b"]', ["a.b"]), true);
  assert.equal(matches('["a.b"]', ["a", "b"]), false);
  assert.equal(matches("a.b", ["a", "b"]), true);
  assert.equal(matches("a.b", ["a.b"]), false);

  assert.equal(matches('["a.b"].password', ["a.b", "password"]), true);
  assert.equal(matches('user["first.name"]', ["user", "first.name"]), true);
  // "*" quoted is a key named "*", not a wildcard.
  assert.equal(matches('["*"]', ["*"]), true);
  assert.equal(matches('["*"]', ["anything"]), false);
  // A quoted key still participates in ** and canDescend.
  assert.equal(matches('**["a.b"]', ["x", "y", "a.b"]), true);
  assert.equal(canDescend('["a.b"].password', ["a.b"]), true);
});

test("a malformed quoted key is refused, not silently reinterpreted", () => {
  const bad = ['["a.b]', "['a.b\"]", '[""]', '["a.b"x]', '["a\\'];
  for (const source of bad) {
    assert.throws(
      () => compilePattern(source),
      (error) => {
        assert.ok(error instanceof RedactionConfigError);
        return true;
      },
      `"${source}" should not compile`
    );
  }
  // The unquoted bracket error points at the quoting form.
  assert.throws(() => compilePattern("[foo]"), /quoted key/);
});
