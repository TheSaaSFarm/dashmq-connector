// Value detectors.
//
// Detectors are the only defence on free text — log lines, failedReason, stack
// traces — where a path denylist means nothing. They are deliberately tuned to
// over-redact, with two exceptions that would otherwise be useless: an
// unqualified run of digits would swallow every 13-digit millisecond timestamp
// as a card number and every ISO date as a phone number.
//
//   npm test        (builds, then runs)
//   node --test tests/

const test = require("node:test");
const assert = require("node:assert/strict");

const { compilePolicy } = require("../dist/redaction");
const { defaultRule } = require("../dist/redaction-config");

function policy(overrides = {}) {
  return compilePolicy({ ...defaultRule(), ...overrides }, () => "test-salt");
}

/**
 * Free text goes through redactText: inline replacement, not whole-value.
 *
 * Pinned to "redact" because that is the mode the detectors are FOR. Under
 * "none" free text is type-tagged and no detector ever runs (see
 * redaction-engine.test.js); under "all" nothing runs either. A detector test
 * that leaned on whatever the default mode happens to be would stop testing
 * detectors the day that default changed.
 */
function scrub(text, overrides) {
  return policy({ mode: "redact", ...overrides }).redactText(text);
}

/** A payload leaf goes through redactPayload: whole-value replacement. */
function leaf(value, overrides) {
  return policy({ mode: "redact", ...overrides }).redactPayload({ v: value }, "").value.v;
}

test("email", () => {
  assert.equal(scrub("mail to bob@example.com now"), "mail to <redacted:email> now");
  assert.equal(scrub("first.last+tag@sub.example.co.uk"), "<redacted:email>");
  assert.equal(scrub("o'brien@example.com"), "<redacted:email>");
  // Two in one line, both go.
  assert.equal(
    scrub("a@x.com -> b@y.org"),
    "<redacted:email> -> <redacted:email>"
  );
  // Not an email.
  assert.equal(scrub("no at sign here"), "no at sign here");
  assert.equal(scrub("user@localhost"), "user@localhost");
});

test("jwt", () => {
  const token =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  assert.equal(scrub(`Authorization: Bearer ${token}`), "Authorization: Bearer <redacted:jwt>");
  // Unsigned tokens (empty third part) still count.
  assert.equal(scrub("eyJhbGciOiJub25lIn0.eyJzdWIiOiJhYmMifQ."), "<redacted:jwt>");
  assert.equal(scrub("eyJ.short"), "eyJ.short");
});

test("creditCard: grouped or Luhn-valid, not every long number", () => {
  assert.equal(scrub("card 4111 1111 1111 1111 ok"), "card <redacted:creditCard> ok");
  assert.equal(scrub("4111-1111-1111-1111"), "<redacted:creditCard>");
  // Bare but Luhn-valid.
  assert.equal(scrub("4111111111111111"), "<redacted:creditCard>");
  assert.equal(scrub("378282246310005"), "<redacted:creditCard>");

  // A millisecond timestamp is 13 digits and must survive, or every job in the
  // product reads "<redacted:creditCard>".
  assert.equal(scrub("timestamp 1700000000000"), "timestamp 1700000000000");
  // Too short / too long to be a card.
  assert.equal(scrub("123456789012"), "123456789012");
  assert.equal(scrub("12345678901234567890"), "12345678901234567890");
});

test("iban: shape is enough, a checksum is not required", () => {
  assert.equal(scrub("pay GB82WEST12345698765432 today"), "pay <redacted:iban> today");
  assert.equal(scrub("DE89 3704 0044 0532 0130 00"), "<redacted:iban>");
  // A mistyped IBAN is still a bank account, so it must not survive on the
  // grounds that its check digits are wrong.
  assert.equal(scrub("GB82WEST12345698765431"), "<redacted:iban>");
  assert.equal(scrub("HELLO WORLD"), "HELLO WORLD");
});

test("phone", () => {
  assert.equal(scrub("call +33612345678"), "call <redacted:phone>");
  assert.equal(scrub("call +1 (555) 123-4567"), "call <redacted:phone>");
  assert.equal(scrub("555-123-4567"), "<redacted:phone>");
  assert.equal(scrub("555 123 4567"), "<redacted:phone>");

  // ISO dates are not phone numbers.
  assert.equal(scrub("failed on 2024-01-15"), "failed on 2024-01-15");
  // Neither are dotted version numbers or IP addresses.
  assert.equal(scrub("v1.2.3"), "v1.2.3");
  assert.equal(scrub("192.168.1.100"), "192.168.1.100");
});

test("detector order is fixed, so an ambiguous match resolves the same way twice", () => {
  // A dashed card number also fits the phone shape. Card wins, in both
  // orderings of the config, because the order is canonical rather than typed.
  const a = scrub("4111-1111-1111-1111", { detectors: ["phone", "creditCard"] });
  const b = scrub("4111-1111-1111-1111", { detectors: ["creditCard", "phone"] });
  assert.equal(a, "<redacted:creditCard>");
  assert.equal(b, "<redacted:creditCard>");
});

test("only the configured detectors run", () => {
  assert.equal(
    scrub("bob@example.com called +33612345678", { detectors: ["email"] }),
    "<redacted:email> called +33612345678"
  );
  assert.equal(scrub("bob@example.com", { detectors: [] }), "bob@example.com");
});

test("a payload leaf is replaced whole, not inline", () => {
  // In a payload the value IS the sensitive thing, so partial survival would
  // leak the context it sits in.
  assert.equal(leaf("please email bob@example.com"), "<redacted:email>");
  assert.equal(leaf("nothing here"), "nothing here");
  // Non-strings cannot carry a detector hit and pass through untouched.
  assert.equal(leaf(42), 42);
  assert.equal(leaf(true), true);
});

test("the hash strategy replaces with a stable, salted digest", () => {
  const hashed = policy({ mode: "redact", strategy: "hash" });
  const first = hashed.redactText("bob@example.com");
  const second = hashed.redactText("bob@example.com");

  assert.match(first, /^<hash:[0-9a-f]{12}>$/);
  assert.equal(first, second, "the same value must hash the same way");
  assert.notEqual(
    first,
    hashed.redactText("alice@example.com"),
    "different values must hash differently"
  );
  // The point of the salt: the digest is not the digest of the value alone.
  const other = compilePolicy(
    { ...defaultRule(), mode: "redact", strategy: "hash" },
    () => "a-different-machine"
  );
  assert.notEqual(first, other.redactText("bob@example.com"));
  // And the plaintext is nowhere in the output.
  assert.equal(first.includes("bob"), false);
});

test("free text keeps its shape around the redaction", () => {
  assert.equal(
    scrub("Failed to deliver to bob@example.com after 3 attempts"),
    "Failed to deliver to <redacted:email> after 3 attempts"
  );
});

test("null and undefined text stay null", () => {
  assert.equal(scrub(null), null);
  assert.equal(scrub(undefined), null);
});

// ---------------------------------------------------------------------------
// Non-ASCII addresses
//
// An ASCII-only address class exempts every accented local part and every
// internationalised domain. For a European product that is not an exotic edge
// case, and free text is exactly where the path denylist cannot help.
// ---------------------------------------------------------------------------

test("email: non-ASCII local parts and IDN domains", () => {
  assert.equal(scrub("josé@exámple.com"), "<redacted:email>");
  assert.equal(scrub("مستخدم@example.com"), "<redacted:email>");
  assert.equal(scrub("δοκιμή@παράδειγμα.δοκιμή"), "<redacted:email>");
  assert.equal(scrub("почта@пример.рф"), "<redacted:email>");
  assert.equal(scrub("xn--80a1acny@xn--p1ai.xn--p1ai"), "<redacted:email>");
  // Plain ASCII still works, and a bare hostname is still not an address.
  assert.equal(scrub("jose@example.com"), "<redacted:email>");
  assert.equal(scrub("user@localhost"), "user@localhost");
  assert.equal(
    scrub("écrire à josé@exámple.com stp"),
    "écrire à <redacted:email> stp"
  );
});

// ---------------------------------------------------------------------------
// Credentials
//
// A payload can put a password behind a deny path. A log line cannot: it has no
// paths. These two detectors are the only thing standing between
// `console.log({ apiKey })` and the network.
// ---------------------------------------------------------------------------

// Fixtures are assembled at runtime rather than written as literals. The
// strings below are synthetic, but a literal in the right shape trips GitHub's
// push protection and blocks the push — and this repo has to stay pushable to
// stay auditable. Concatenation keeps the detector under real test without
// putting a credential-shaped literal in the file.
const fakeKey = (prefix, body) => prefix + body;

test("apiKey: vendor-prefixed credentials", () => {
  assert.equal(
    scrub("charging with " + fakeKey("sk_live", "_51H8xYzAbCdEfGhIjKlMnOpQr")),
    "charging with <redacted:apiKey>"
  );
  assert.equal(scrub(fakeKey("sk_test", "_abcdefghijkl")), "<redacted:apiKey>");
  assert.equal(
    scrub(fakeKey("ghp", "_16C7e42F292c6912E7710c838347Ae178B4a")),
    "<redacted:apiKey>"
  );
  assert.equal(scrub(fakeKey("AKIA", "IOSFODNN7EXAMPLE")), "<redacted:apiKey>");
  assert.equal(scrub(fakeKey("xoxb", "-1234567890-abcdefghij")), "<redacted:apiKey>");
  // Not every underscore-bearing token is a key.
  assert.equal(scrub("job_id_12345"), "job_id_12345");
});

test("secret: a key name is enough, and only the value goes", () => {
  // The key name is what makes the line readable and is not the part that
  // needed removing.
  assert.equal(scrub("password: hunter2"), "password: <redacted:secret>");
  // The quotes go with the value: they delimited it, and what is left of the
  // line is no longer pretending to be a string.
  assert.equal(scrub('api_key="abcdef123456"'), "api_key=<redacted:secret>");
  assert.equal(scrub("Bearer abcdef123456"), "Bearer <redacted:secret>");
  assert.equal(
    scrub("client_secret=s3cr3t-value, retries=2"),
    "client_secret=<redacted:secret>, retries=2"
  );

  // Values that are not secrets stay, or every log line reads as a credential.
  assert.equal(scrub("status: ok"), "status: ok");
  assert.equal(scrub("token: null"), "token: null");
  assert.equal(scrub("authorization: required"), "authorization: required");

  // And a marker this engine already wrote is never redacted a second time.
  assert.equal(
    scrub("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"),
    "Authorization: Bearer <redacted:jwt>"
  );
});

test("credentials in a payload leaf are replaced whole", () => {
  assert.equal(leaf(fakeKey("sk_live", "_51H8xYzAbCdEfGhIjKlMnOpQr")), "<redacted:apiKey>");
  assert.equal(leaf("password: hunter2"), "<redacted:secret>");
});
