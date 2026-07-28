// job.exists — the existence probe retention deletes on the strength of.
//
// The dashboard cannot reach this Redis, so without this method it has to skip
// its orphan sweep for connector connections entirely and non-terminal rows
// accumulate forever. Because the answer causes deletions, the interesting
// cases are all about not reporting a job missing when it isn't.
//
//   npm test        (builds, then runs)
//   node --test tests/

const test = require("node:test");
const assert = require("node:assert/strict");

const { RPC_METHODS } = require("../dist/rpc");

test("job.exists is advertised, so the dashboard knows it can ask", () => {
  assert.ok(RPC_METHODS.includes("job.exists"));
});

test("the advertised list stays a superset of the older protocol", () => {
  // An older dashboard must keep working against a newer connector.
  for (const method of ["ping", "queue.list", "queue.counts", "job.list", "job.get"]) {
    assert.ok(RPC_METHODS.includes(method), `${method} was dropped`);
  }
});
