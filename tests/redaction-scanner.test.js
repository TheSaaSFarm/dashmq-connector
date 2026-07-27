// The choke point.
//
// The engine can be correct in isolation and still useless if a read path
// forgets to call it. These tests drive the actual Redis read functions against
// a stub client, so they fail if a job or a log line can reach a caller
// unredacted — which is the failure that matters, because it is invisible.
//
//   npm test        (builds, then runs)
//   node --test tests/

const test = require("node:test");
const assert = require("node:assert/strict");
const { mkdtempSync, writeFileSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join } = require("node:path");

const { fetchJobsBatch, fetchJobLogs } = require("../dist/scanner");
const { toJobSummary } = require("../dist/rpc");
const { RedactionEngine } = require("../dist/redaction");

function engineWith(config) {
  const dir = mkdtempSync(join(tmpdir(), "dashmq-scanner-"));
  if (config !== undefined) {
    writeFileSync(join(dir, "dashmq.config.json"), JSON.stringify(config), "utf8");
  }
  return new RedactionEngine({
    env: null,
    cwd: dir,
    homeDir: dir,
    saltPath: join(dir, "salt"),
  });
}

/** Just enough ioredis to drive the two read paths. */
function stubRedis({ hashes = {}, lists = {} } = {}) {
  return {
    pipeline() {
      const keys = [];
      const chain = {
        hgetall(key) {
          keys.push(key);
          return chain;
        },
        async exec() {
          return keys.map((key) => [null, hashes[key] || {}]);
        },
      };
      return chain;
    },
    async lrange(key) {
      return lists[key] || [];
    },
  };
}

const HASH = {
  name: "send-email",
  data: JSON.stringify({
    to: "bob@example.com",
    password: "hunter2",
    orderId: "ord_9",
  }),
  opts: JSON.stringify({ attempts: 3 }),
  returnvalue: JSON.stringify({ receipt: "alice@example.com" }),
  timestamp: "1700000000000",
  processedOn: "1700000001000",
  finishedOn: "1700000002000",
  failedReason: "SMTP rejected bob@example.com",
  stacktrace: "Error: SMTP rejected bob@example.com",
  attemptsMade: "2",
};

const DENY_PASSWORDS = {
  version: 1,
  redaction: { default: { mode: "redact", deny: ["**.password"] } },
};

test("fetchJobsBatch redacts on the way out of Redis", async () => {
  const redis = stubRedis({ hashes: { "bull:emails:1": HASH } });

  const [job] = await fetchJobsBatch(
    redis,
    "emails",
    "failed",
    ["1"],
    "bull",
    engineWith(DENY_PASSWORDS)
  );

  assert.deepEqual(job.data, {
    to: "<redacted:email>",
    password: "<redacted:path>",
    orderId: "ord_9",
  });
  assert.deepEqual(job.returnValue, { receipt: "<redacted:email>" });
  assert.equal(job.failedReason, "SMTP rejected <redacted:email>");

  // Nothing anywhere in the object still carries the plaintext.
  assert.equal(JSON.stringify(job).includes("bob@example.com"), false);
  assert.equal(JSON.stringify(job).includes("hunter2"), false);
});

test("the push loop's default — no policy file — redacts without blacking out", async () => {
  // The upgrade path. A connector that is updated and restarted with no policy
  // file must not overwrite the dashboard's cached payloads with placeholders:
  // that is data loss delivered as a feature. It must also not ship the values
  // a detector recognises.
  const redis = stubRedis({ hashes: { "bull:emails:1": HASH } });

  const [job] = await fetchJobsBatch(redis, "emails", "failed", ["1"], "bull", engineWith());

  assert.deepEqual(job.data, {
    to: "<redacted:email>",
    password: "hunter2",
    orderId: "ord_9",
  });
  assert.equal(job._dashmq.mode, "redact");
  assert.equal(job.failedReason, "SMTP rejected <redacted:email>");
  assert.equal(JSON.stringify(job).includes("bob@example.com"), false);
});

test("mode none, written down explicitly, does black out — including free text", async () => {
  const redis = stubRedis({ hashes: { "bull:emails:1": HASH } });
  const engine = engineWith({ version: 1, redaction: { default: { mode: "none" } } });

  const [job] = await fetchJobsBatch(redis, "emails", "failed", ["1"], "bull", engine);

  assert.deepEqual(job.data, {
    to: "<type:string>",
    password: "<type:string>",
    orderId: "<type:string>",
  });
  assert.equal(job._dashmq.mode, "none");
  assert.equal(job.failedReason, "<type:string>");
  assert.equal(job.stacktrace, "<type:string>");
  assert.equal(JSON.stringify(job).includes("ord_9"), false);
  assert.equal(JSON.stringify(job).includes("SMTP"), false);
});

test("every job carries the policy that produced it", async () => {
  const engine = engineWith(DENY_PASSWORDS);
  const redis = stubRedis({ hashes: { "bull:emails:1": HASH, "bull:emails:2": HASH } });

  const jobs = await fetchJobsBatch(redis, "emails", "failed", ["1", "2"], "bull", engine);

  assert.equal(jobs.length, 2);
  for (const job of jobs) {
    assert.equal(job.redactionPolicy, engine.policyId);
    assert.equal(job.redactionMode, "redact");
    assert.deepEqual(job.payloadRedacted, job._dashmq.redacted);
  }
});

test("a list row carries the scrubbed error and no payload at all", async () => {
  const redis = stubRedis({ hashes: { "bull:emails:1": HASH } });
  const [job] = await fetchJobsBatch(
    redis,
    "emails",
    "failed",
    ["1"],
    "bull",
    engineWith(DENY_PASSWORDS)
  );

  const summary = toJobSummary(job);

  assert.equal("data" in summary, false);
  assert.equal("opts" in summary, false);
  assert.equal("returnValue" in summary, false);
  assert.equal("_dashmq" in summary, false);
  // The one payload-derived string a list row does carry is redacted.
  assert.equal(summary.failedReason, "SMTP rejected <redacted:email>");
});

test("a per-queue override reaches the read path", async () => {
  const engine = engineWith({
    version: 1,
    redaction: {
      default: { mode: "none" },
      queues: { emails: { mode: "redact", deny: ["**.password"] } },
    },
  });
  const redis = stubRedis({
    hashes: { "bull:emails:1": HASH, "bull:reports:1": HASH },
  });

  const [emails] = await fetchJobsBatch(redis, "emails", "failed", ["1"], "bull", engine);
  const [reports] = await fetchJobsBatch(redis, "reports", "failed", ["1"], "bull", engine);

  assert.equal(emails.data.orderId, "ord_9");
  assert.equal(reports.data.orderId, "<type:string>");
});

test("fetchJobLogs redacts every line it reads", async () => {
  const redis = stubRedis({
    lists: {
      "bull:emails:1:logs": [
        "sending to bob@example.com",
        "card 4111 1111 1111 1111",
        "done",
      ],
    },
  });

  const logs = await fetchJobLogs(redis, "emails", "1", "bull", engineWith(DENY_PASSWORDS));

  assert.deepEqual(logs, [
    "sending to <redacted:email>",
    "card <redacted:creditCard>",
    "done",
  ]);
});

test("fetchJobLogs scrubs even with no policy file, where paths mean nothing", async () => {
  const redis = stubRedis({
    lists: { "bull:emails:1:logs": ["user bob@example.com failed"] },
  });

  const logs = await fetchJobLogs(redis, "emails", "1", "bull", engineWith());

  assert.deepEqual(logs, ["user <redacted:email> failed"]);
});

test("a job with no logs, and a Redis that refuses, both yield nothing", async () => {
  const engine = engineWith(DENY_PASSWORDS);

  assert.deepEqual(await fetchJobLogs(stubRedis(), "emails", "1", "bull", engine), []);

  const angry = {
    async lrange() {
      throw new Error("WRONGTYPE");
    },
  };
  assert.deepEqual(await fetchJobLogs(angry, "emails", "1", "bull", engine), []);
});

test("an unparseable payload is still redacted, not passed through raw", async () => {
  // parseJobHash falls back to the raw string when data is not JSON. That
  // fallback must not become a way around the walk.
  const redis = stubRedis({
    hashes: {
      "bull:emails:1": { ...HASH, data: "raw text with bob@example.com in it" },
    },
  });

  const [job] = await fetchJobsBatch(
    redis,
    "emails",
    "failed",
    ["1"],
    "bull",
    engineWith(DENY_PASSWORDS)
  );

  assert.equal(job.data, "<redacted:email>");
});
