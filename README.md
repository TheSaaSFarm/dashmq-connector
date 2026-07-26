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
  -h, --help                  output usage information
```

### Environment Variables

You can also specify options via environment variables:

```bash
DASHMQ_TOKEN=your-token-here
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWD=your-password
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
