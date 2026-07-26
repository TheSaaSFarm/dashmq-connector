// Regression tests for the list/detail split in the RPC layer.
//
// The Postgres list endpoints were deliberately changed to stop returning job
// payloads (a 100-row page went from 294 kB to 15 kB). `job.list` answers the
// same question over a different transport, and an RPC response has no
// equivalent of Prisma's explicit `select` — so the projection is what keeps
// that regression from being reinstated the moment a list view is wired up.
//
//   npm test        (builds, then runs)
//   node --test tests/

const test = require("node:test");
const assert = require("node:assert/strict");

const { toJobSummary } = require("../dist/rpc");

function fullJob(overrides = {}) {
  return {
    id: "42",
    name: "send-email",
    status: "failed",
    data: { to: "user@example.com", body: "x".repeat(4096) },
    opts: { attempts: 3, backoff: { type: "exponential", delay: 1000 } },
    progress: 50,
    timestamp: 1_700_000_000_000,
    processedOn: 1_700_000_001_000,
    finishedOn: 1_700_000_002_000,
    failedReason: "SMTP timeout",
    stacktrace: "Error: SMTP timeout\n    at send (smtp.js:1:1)",
    attemptsMade: 2,
    ...overrides,
  };
}

test("toJobSummary drops the payload fields a list must never ship", () => {
  const summary = toJobSummary(fullJob());

  assert.equal("data" in summary, false);
  assert.equal("opts" in summary, false);
  assert.equal("stacktrace" in summary, false);
});

test("toJobSummary keeps exactly the columns the list view renders", () => {
  const summary = toJobSummary(fullJob());

  assert.deepEqual(Object.keys(summary).sort(), [
    "attemptsMade",
    "failedReason",
    "finishedOn",
    "id",
    "name",
    "processedOn",
    "progress",
    "status",
    "timestamp",
  ]);

  assert.deepEqual(summary, {
    id: "42",
    name: "send-email",
    status: "failed",
    progress: 50,
    timestamp: 1_700_000_000_000,
    processedOn: 1_700_000_001_000,
    finishedOn: 1_700_000_002_000,
    failedReason: "SMTP timeout",
    attemptsMade: 2,
  });
});

test("toJobSummary is a whitelist: a new JobData field is not leaked by default", () => {
  const summary = toJobSummary(
    fullJob({ returnvalue: { receiptId: "abc" }, parentKey: "bull:x:1" })
  );

  assert.equal("returnvalue" in summary, false);
  assert.equal("parentKey" in summary, false);
});

test("toJobSummary preserves nulls rather than inventing values", () => {
  const summary = toJobSummary(
    fullJob({ processedOn: null, finishedOn: null, failedReason: null })
  );

  assert.equal(summary.processedOn, null);
  assert.equal(summary.finishedOn, null);
  assert.equal(summary.failedReason, null);
});

test("a summary page stays small where a payload page would not", () => {
  const jobs = Array.from({ length: 100 }, (_, i) =>
    fullJob({ id: String(i) })
  );

  const payloadBytes = Buffer.byteLength(JSON.stringify(jobs), "utf8");
  const summaryBytes = Buffer.byteLength(
    JSON.stringify(jobs.map(toJobSummary)),
    "utf8"
  );

  assert.ok(
    summaryBytes * 10 < payloadBytes,
    `summary page (${summaryBytes} B) should be an order of magnitude smaller than the payload page (${payloadBytes} B)`
  );
});
