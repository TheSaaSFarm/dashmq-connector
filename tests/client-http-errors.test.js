// A failed sync must be describable in one log line.
//
// The sync loop runs every 5 seconds. When the backend URL points at something
// that is not DashMQ's API, the old error path interpolated the whole response
// body into the message — a Next.js 404 page is tens of kilobytes of minified
// RSC payload, reprinted twelve times a minute, burying the actual problem.
//
//   npm test        (builds, then runs)
//   node --test tests/

const test = require("node:test");
const assert = require("node:assert/strict");

const { describeHttpFailure } = require("../dist/client");

const NEXT_404 = `<!DOCTYPE html><html><head><title>404: This page could not be found.</title></head><body><script>self.__next_f.push([1,"${"x".repeat(5000)}"])</script></body></html>`;

test("an HTML body is reported as a misaddressed backend, not quoted", () => {
  const message = describeHttpFailure(404, NEXT_404);

  assert.match(message, /did not answer with JSON/);
  assert.match(message, /HTTP 404/);
  // The point of the change: none of the page comes along for the ride.
  assert.equal(message.includes("__next_f"), false);
  assert.equal(message.includes("<!DOCTYPE"), false);
  assert.ok(message.length < 400, `message was ${message.length} chars`);
});

test("names the trailing-path mistake, which is the usual cause", () => {
  assert.match(describeHttpFailure(404, NEXT_404), /trailing path/);
});

test("a short non-HTML body is quoted verbatim", () => {
  assert.equal(
    describeHttpFailure(500, '{"error":"boom"}'),
    'Server error (HTTP 500): {"error":"boom"}'
  );
});

test("a long non-HTML body is truncated, not dropped", () => {
  const message = describeHttpFailure(500, "e".repeat(9000));

  assert.match(message, /truncated/);
  assert.ok(message.length < 400, `message was ${message.length} chars`);
});

test("an empty body still says something", () => {
  assert.match(describeHttpFailure(502, "   "), /empty response/);
});

test("leading whitespace does not hide the markup", () => {
  assert.match(describeHttpFailure(404, "\n\n  <html><body>nope"), /did not answer with JSON/);
});
