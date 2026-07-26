// Regression tests for the pure (Redis-free) parts of queue detection and
// multi-version dispatch. Uses Node's built-in test runner against the compiled
// output — no test framework dependency.
//
//   npm test        (builds, then runs)
//   node --test tests/

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  parseQueueMetaVersion,
  parseMajorVersion,
} = require("../dist/queue-factory");
const {
  selectQueueModule,
  queueKey,
  UnsupportedQueueTypeError,
} = require("../dist/queue-registry");
const { hashRedisOptions } = require("../dist/redis-clients");

test("parseQueueMetaVersion: BullMQ meta version", () => {
  assert.deepEqual(parseQueueMetaVersion("bullmq:5.34.10"), {
    type: "bullmq",
    majorVersion: 5,
    version: "5.34.10",
  });
  assert.deepEqual(parseQueueMetaVersion("bullmq:3.16.2"), {
    type: "bullmq",
    majorVersion: 3,
    version: "3.16.2",
  });
  assert.deepEqual(parseQueueMetaVersion("bullmq:4.18.3"), {
    type: "bullmq",
    majorVersion: 4,
    version: "4.18.3",
  });
});

test("parseQueueMetaVersion: BullMQ Pro is not mis-tagged as plain bullmq", () => {
  assert.deepEqual(parseQueueMetaVersion("bullmq-pro:7.10.1"), {
    type: "bullmq-pro",
    majorVersion: 7,
    version: "7.10.1",
  });
  // case-insensitive, tolerant of stray whitespace
  assert.equal(parseQueueMetaVersion("BullMQ-Pro: 7.0.0 ").type, "bullmq-pro");
});

test("parseQueueMetaVersion: unusable meta degrades to bull", () => {
  for (const input of [
    null,
    undefined,
    "",
    "5.34.10", // no library separator
    ":5.34.10", // empty library
    "bullmq:", // empty version
    "somethingelse:1.0.0", // unknown library
  ]) {
    assert.deepEqual(
      parseQueueMetaVersion(input),
      { type: "bull", majorVersion: 0 },
      `expected bull for ${JSON.stringify(input)}`
    );
  }
});

test("parseQueueMetaVersion: unparseable major version is guarded to 0", () => {
  assert.deepEqual(parseQueueMetaVersion("bullmq:next"), {
    type: "bullmq",
    majorVersion: 0,
    version: "next",
  });
  assert.deepEqual(parseQueueMetaVersion("bullmq:-1.0.0"), {
    type: "bullmq",
    majorVersion: 0,
    version: "-1.0.0",
  });
});

test("parseQueueMetaVersion: returns a fresh object each call", () => {
  const a = parseQueueMetaVersion(null);
  const b = parseQueueMetaVersion(null);
  assert.notEqual(a, b);
  a.majorVersion = 99;
  assert.equal(b.majorVersion, 0);
});

test("parseMajorVersion", () => {
  assert.equal(parseMajorVersion("5.34.10"), 5);
  assert.equal(parseMajorVersion("12"), 12);
  assert.equal(parseMajorVersion("  4.1.0 "), 4);
  assert.equal(parseMajorVersion(""), 0);
  assert.equal(parseMajorVersion(null), 0);
  assert.equal(parseMajorVersion(undefined), 0);
  assert.equal(parseMajorVersion("abc"), 0);
  assert.equal(parseMajorVersion(".1.0"), 0);
});

test("selectQueueModule: dispatches to the module that speaks the protocol", () => {
  assert.equal(selectQueueModule("bull", 0), "bull");
  assert.equal(selectQueueModule("bull", 4), "bull");
  assert.equal(selectQueueModule("bullmq", 3), "bullmq-v3");
  assert.equal(selectQueueModule("bullmq", 4), "bullmq-v4");
  assert.equal(selectQueueModule("bullmq", 5), "bullmq-v5");
  // major 0 (unknown) and anything newer than what we alias fall back to the
  // top-level bullmq dependency
  assert.equal(selectQueueModule("bullmq", 0), "bullmq");
  assert.equal(selectQueueModule("bullmq", 1), "bullmq");
  assert.equal(selectQueueModule("bullmq", 6), "bullmq");
});

test("selectQueueModule: unsupported flavours fail loudly, not silently", () => {
  assert.throws(() => selectQueueModule("bullmq-pro", 7), (err) => {
    assert.ok(err instanceof UnsupportedQueueTypeError);
    assert.equal(err.code, "UNSUPPORTED_QUEUE_TYPE");
    assert.equal(err.queueType, "bullmq-pro");
    assert.equal(err.majorVersion, 7);
    return true;
  });

  assert.throws(() => selectQueueModule("kue", 0), UnsupportedQueueTypeError);
});

test("queueKey", () => {
  assert.equal(queueKey("bull", "emails"), "bull:emails");
  assert.notEqual(queueKey("bull", "emails"), queueKey("other", "emails"));
});

test("hashRedisOptions: stable, endpoint-sensitive, function-tolerant", () => {
  const base = { host: "localhost", port: 6379, db: 0, password: "s3cret" };

  assert.equal(hashRedisOptions(base), hashRedisOptions({ ...base }));
  // key order must not matter
  assert.equal(
    hashRedisOptions({ db: 0, password: "s3cret", port: 6379, host: "localhost" }),
    hashRedisOptions(base)
  );
  // non-identifying options (retryStrategy is a function) must not matter
  assert.equal(
    hashRedisOptions({ ...base, retryStrategy: () => 1, connectTimeout: 5000 }),
    hashRedisOptions(base)
  );
  // identifying options must matter
  assert.notEqual(hashRedisOptions({ ...base, db: 1 }), hashRedisOptions(base));
  assert.notEqual(hashRedisOptions({ ...base, port: 6380 }), hashRedisOptions(base));
  assert.notEqual(hashRedisOptions({ ...base, tls: {} }), hashRedisOptions(base));
  // credentials must not be recoverable from the key
  assert.ok(!hashRedisOptions(base).includes("s3cret"));
});
