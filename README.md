# DashMQ Connector

This service allows you to connect your local Redis queues to [DashMQ](https://dashmq.com) for monitoring and management. It acts as a bridge between your local queues and the DashMQ dashboard.

Currently supports [Bull](https://github.com/optimalbits/bull) and [BullMQ](https://github.com/taskforcesh/bullmq) queues.

## Install

Using npm:

```bash
npm install -g dashmq-connector
```

Using yarn:

```bash
yarn global add dashmq-connector
```

## Usage

Get your API token from your DashMQ account settings, then run:

```bash
dashmq -n "My Local Connection" -t your-api-token-here
```

### Options

```bash
Usage: dashmq [options]

Options:
  -V, --version               output the version number
  -n, --name [name]           connection name [My Connection] (default: "My Connection")
  -t, --token [token]         API token (get yours from DashMQ dashboard)
  -p, --port [port]           redis port [6379] (default: "6379")
  -h, --host [host]           redis host [localhost] (default: "localhost")
  -d, --database [db]         redis database [0] (default: "0")
  --username [username]       redis username
  --passwd [passwd]           redis password
  -u, --uri [uri]             redis uri
  --tls                       activate secured TLS connection to Redis
  -b, --backend [url]          DashMQ API URL [http://localhost:3000] (default: "http://localhost:3000")
  --queues <queues>           optional comma-separated list of queues to monitor
  -c, --config [path]         path to the local redaction policy
  -h, --help                  output usage information
```

### Environment Variables

You can also specify options via environment variables:

```bash
DASHMQ_TOKEN=your-token-here
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWD=your-password
DASHMQ_CONFIG=./dashmq.config.json
REDIS_URI=redis://localhost:6379
DASHMQ_BACKEND=http://localhost:3000
```

### Example

```bash
dashmq -n "Production Queue" -t dashmq_abc123xyz -h redis.example.com -p 6379 --passwd mypassword
```

## How It Works

1. The connector connects to your local Redis instance
2. It discovers all Bull/BullMQ queues automatically
3. It sends queue metadata and job information to DashMQ via REST API
4. The connection appears in your DashMQ dashboard automatically

## Redaction

Job payloads routinely contain personal data. The connector runs on your
machine, next to your Redis, so it can strip that data out **before anything is
transmitted**. This repository is public so you can verify that it does.

Three properties make that claim checkable rather than promotional:

- **The policy is a local file.** It is read from your disk and from nowhere
  else. There is no API, header, or response field by which DashMQ can supply,
  override, or read your policy. The server is told one thing about it: its
  SHA-256 hash, so the dashboard can display which policy is live.
- **It fails closed.** A policy that cannot be parsed stops the connector with a
  non-zero exit — it does not start up "unprotected".
- **The default is `redact`, and it announces itself.** With no policy file the
  connector runs `mode: "redact"`: values are transmitted, minus everything the
  value detectors recognise (emails, cards, IBANs, phone numbers, JWTs, API
  keys, `password:`-style assignments). It prints a warning saying exactly that
  on every start, and the mode travels with every sync so the dashboard shows
  it. See [The default, and why it is not `none`](#the-default-and-why-it-is-not-none).
- **Shape is preserved.** A redacted field keeps its key. `{"email":
  "<redacted:email>"}` tells you — and the failure-diagnosis model — that the
  field was present and hidden. `{}` would say it was missing, and lead to the
  wrong diagnosis.

### The default, and why it is not `none`

The strictest mode is `none`: key names and value types travel, values never do.
It is not the default, and the reason is a migration one.

Connectors installed before redaction existed transmitted payloads verbatim, and
the dashboard caches what it is sent. If an absent policy meant `none`, the first
sync after a routine `npm update` would overwrite every cached payload in the
product with `"<type:string>"` — for customers who changed nothing, asked for
nothing, and were told nothing. That is data loss shipped as a feature.
Defaulting to `all` is the opposite failure: the privacy feature arrives
switched off.

`redact` is the only default that is better than both the behaviour it replaces
and than doing nothing. Nobody loses a payload they had yesterday, and every
value a detector recognises stops leaving the network. Then:

- The connector prints a warning at every start while no policy file exists.
- Every sync reports the mode and the policy hash, and the dashboard shows both
  on the connection and on each job.
- `mode: "none"` is one file away, and is what to write for shape-only
  behaviour:

  ```json
  { "version": 1, "redaction": { "default": { "mode": "none" } } }
  ```

Be clear about what `redact` does not do. The detectors recognise value
*shapes*. They do not recognise a person's name, a postal address, a date of
birth or an order reference. If your payloads carry those, write a `deny` list
or use `allowlist`/`none` — a default cannot guess them for you.

### Where the policy is read from

First hit wins. Nothing is merged across files.

1. `--config <path>` (`-c`)
2. `$DASHMQ_CONFIG`
3. `./dashmq.config.json`
4. `~/.dashmq/config.json`

If you name a file explicitly with `--config` or `$DASHMQ_CONFIG` and it is not
there, the connector stops rather than quietly falling through to a different
policy.

### Format

See [`dashmq.config.example.json`](./dashmq.config.example.json).

```json
{
  "version": 1,
  "redaction": {
    "default": {
      "mode": "redact",
      "strategy": "label",
      "deny": ["**.password", "user.email", "items[*].serialNumber", "[\"customer.email\"]"],
      "allow": [],
      "detectors": ["jwt", "apiKey", "secret", "email", "iban", "creditCard", "phone"],
      "maxDepth": 8,
      "maxStringLength": 2048
    },
    "queues": {
      "payments": { "mode": "allowlist", "allow": ["orderId"] }
    }
  }
}
```

Unknown keys are rejected. A `deny` list misspelled `denny` would otherwise be
ignored, and you would believe a field was protected when it was not.

Per-queue keys are matched as `prefix:name` — the same key the queue registry
uses — or as a bare queue name. An override inherits every field it does not
restate; arrays replace rather than concatenate, so a rule can be read on its
own.

#### Modes

| Mode | What is transmitted |
| --- | --- |
| `none` | Key names and value types only (`"<type:string>"`). Free text — logs, `failedReason`, stack traces — is type-tagged too. |
| `redact` | Everything except paths matching `deny` and values matching a detector. **The default when no policy file exists.** |
| `allowlist` | Only paths matching `allow`, free text included. Everything else keeps its key and loses its value. |
| `all` | Verbatim, except paths matching `deny`. Reachable only by writing it explicitly. |

#### Precedence

Three constructs can have an opinion about one value. They resolve in this
order, and the order is the whole point: a rule element that validates must
never be discarded at runtime.

1. **`deny` wins, in every mode that transmits anything** — including `all`. It
   is the only construct whose entire purpose is "never transmit this", so a
   mode does not get to void it. An author who writes both an allowlist and a
   denylist means the deny. For true verbatim, restate `"deny": []` (arrays
   replace rather than concatenate, so this reads on its own).
2. **A path matched EXACTLY by `allow` beats the detectors.** `allow:
   ["contact.email"]` names one field; second-guessing that with a value-shape
   heuristic would make the allowlist mean nothing. This holds under `redact`
   too, which is how you say "yes, I do want this one address" without turning a
   detector off globally.
3. **Matching only an ancestor does not.** `allow: ["user"]` says the subtree may
   travel, not that every value in it is safe, so the detectors still run on
   `user.email`. A container `allow` is a scope, not a blanket exemption.

A rule element is only ever ignored when ignoring it transmits *less*: `allow`
under `none` (which sends nothing) and under `all` (which already sends
everything). Nothing is ignored in the direction that would transmit more than
you asked for.

#### Strategies

`strategy` applies to `redact` and `allowlist`.

- `label` replaces a value with `"<redacted:email>"` — the reason it went.
- `hash` replaces it with `"<hash:9f3a1c7e2b04>"`, the first 12 hex digits of
  `sha256(value + localSalt)`. The salt is 32 random bytes generated once and
  stored at `~/.dashmq/salt`, mode `0600`, **on your machine only**. It is never
  transmitted. This is what lets the dashboard say "1,203 of these failures
  share the same customer reference" while being unable to learn what that
  reference is.

#### Path syntax

| Pattern | Matches |
| --- | --- |
| `user.email` | exactly that path |
| `*` | exactly one segment — `user.*.token` |
| `**` | any number of segments — `**.password` matches `password` at any depth |
| `[3]` | one array index — `items[3].sku` |
| `[*]` | any array index — `items[*].serialNumber` |
| `["a.b"]` | a literal key, quotes and all — see below |

`.` and `[` are structural above and perfectly ordinary inside a JSON key.
Flattened form data, i18n keys, metric names and Stripe-style metadata maps all
produce keys like `user.email`. Write those in the quoted form:

| Payload | Pattern that matches it |
| --- | --- |
| `{"user": {"email": …}}` | `user.email` |
| `{"user.email": …}` | `["user.email"]` |

A quoted key is always literal — no wildcard, no separator — so `["*"]`
addresses a key actually named `*`, and `\"` escapes a quote inside one. A
malformed quoted key is a config error, not a pattern that silently matches
nothing.

Reported paths use the same form, so `["a.b"].password` and `a.b.password` are
different strings and the sidecar can be read to find out which field actually
went.

#### Detectors

`detectors` selects which value shapes are recognised in payload leaves and in
free text. All of them are on by default.

| Detector | Recognises |
| --- | --- |
| `jwt` | `eyJ…`-shaped tokens, signed or unsigned |
| `apiKey` | vendor-prefixed credentials — `sk_live_…`, `ghp_…`, `AKIA…`, `xoxb-…`, `AIza…` |
| `secret` | a credential behind a key name — `password: …`, `api_key="…"`, `Authorization: Bearer …`. Only the value is replaced, so the line stays readable |
| `email` | addresses, including non-ASCII local parts and internationalised domains (`josé@exámple.com`, `مستخدم@example.com`) |
| `iban` | IBAN shape, deliberately without the checksum — a mistyped IBAN is still a bank account |
| `creditCard` | grouped or Luhn-valid card numbers, not every 13-digit timestamp |
| `phone` | phone shapes, excluding ISO dates, version numbers and IP addresses |

Detector order is fixed by the connector, not by the order you write them, so an
ambiguous match resolves the same way every time.

#### Guards

`maxDepth` (default 8) and `maxStringLength` (default 2048) bound the cost of
walking a payload and stop a base64 blob being shipped wholesale. Anything
deeper than `maxDepth` becomes `"<redacted:depth>"` — it is not inspected, so it
is not transmitted. Longer strings are cut and marked `…<truncated:N>`, where
`N` is the original length. Both guards stay active under `mode: "all"`: they
are transport bounds, not privacy ones.

### What is covered

| Surface | Treatment |
| --- | --- |
| Job payloads on list reads | Redacted under the queue's mode |
| `data`, `opts`, `returnValue` on detail reads | Redacted under the queue's mode |
| Job logs | Under the queue's mode, addressed as `logs` |
| `failedReason`, stack traces | Under the queue's mode, addressed as `failedReason` / `stackTrace` |

Free text is a value like any other, so it follows the mode rather than getting
its own rules:

| Mode | Free text |
| --- | --- |
| `none` | `"<type:string>"`. Nothing of the content travels. Log line count is preserved, because that is shape. |
| `redact` | Detectors applied inline: `"Failed to deliver to <redacted:email>"`. |
| `allowlist` | Suppressed unless named — `"allow": ["failedReason", "stackTrace", "logs"]`. |
| `all` | Verbatim, within the length guard. |

`deny` reaches it too, so `"deny": ["stackTrace"]` is something you can write and
have honoured.

Be clear about what the **detectors** can and cannot do under `redact`, because
free text is where the path denylist cannot help: `console.log(user)` prints an
object whose email, card number and API key they will catch, and whose `name`,
`dateOfBirth` and postal address they will not. If your processors log whole
user objects, log identifiers instead — or set `"mode": "none"`, under which no
free-text content leaves the machine at all.

Every redaction is reported alongside the payload, so both the dashboard and any
model reading it know what happened:

```json
{
  "data": { "orderId": "ord_9", "email": "<redacted:email>" },
  "_dashmq": {
    "redacted": ["email"],
    "policy": "sha256:3f9a2c…",
    "mode": "redact"
  }
}
```

### Verifying it yourself

```bash
npm install && npm test
```

The redaction tests are `tests/redaction-*.test.js`. `lib/redaction.ts` is the
single choke point: `fetchJobsBatch` and `fetchJobLogs` in `lib/scanner.ts` take
the engine as a **required** argument, so there is no code path that reads a job
or a log line out of Redis without passing it through redaction first.

## Use as a Library

You can also use the connector as a library in your Node.js application:

```js
const { Connect } = require("dashmq-connector");

const connection = Connect("My Connection", "your-token", {
  host: "localhost",
  port: 6379,
  password: "your-password",
});
```

## License

MIT
