import { Command } from "commander";
import { blueBright, red } from "chalk";
import { Connect } from "./index";

export const run = (name: string, version: string) => {
  console.info(
    blueBright(`DashMQ Connector v${version} - Connect your queues to DashMQ`)
  );

  const program = new Command();
  program
    .version(version)
    .option("-n, --name [name]", "connection name [My Connection]", "My Connection")
    .option(
      "-t, --token [token]",
      "API token (get yours from DashMQ dashboard)",
      process.env.DASHMQ_TOKEN
    )
    .option(
      "-p, --port [port]",
      "redis port [6379]",
      process.env.REDIS_PORT || "6379"
    )
    .option("--tls", "Activate secured TLS connection to Redis")
    .option(
      "-h, --host [host]",
      "redis host [localhost]",
      process.env.REDIS_HOST || "localhost"
    )
    .option("-d, --database [db]", "redis database [0]", "0")
    .option("--username [username]", "redis username", process.env.REDIS_USERNAME)
    .option("--passwd [passwd]", "redis password", process.env.REDIS_PASSWD)
    .option("-u, --uri [uri]", "redis uri", process.env.REDIS_URI)
    .option(
      "-b, --backend [url]",
      "DashMQ API URL",
      process.env.DASHMQ_BACKEND || "http://localhost:3000"
    )
    .option("--queues <queues>", "optional comma-separated list of queues to monitor")
    .parse(process.argv);

  const options = program.opts();

  if (!options.token) {
    console.error(
      red(
        `ERROR: A valid token is required, use either DASHMQ_TOKEN env or pass it with -t (get token from DashMQ dashboard)`
      )
    );
    process.exit(1);
  }

  const queueNames = options.queues
    ? options.queues.split(",").map((q: string) => q.trim())
    : undefined;

  const connection = {
    port: parseInt(options.port, 10),
    host: options.host,
    username: options.username,
    password: options.passwd,
    db: parseInt(options.database, 10),
    uri: options.uri,
    tls: options.tls
      ? {
          rejectUnauthorized: false,
        }
      : undefined,
  };

  // Remove undefined values
  Object.keys(connection).forEach((key) => {
    if ((connection as any)[key] === undefined) {
      delete (connection as any)[key];
    }
  });

  // If uri is defined, remove host and port
  if (options.uri) {
    delete (connection as any).port;
    delete (connection as any).host;
  }

  const client = Connect(options.name, options.token, connection, options.backend, {
    queueNames,
  });

  client.start().catch((err) => {
    console.error(red("[DashMQ] Failed to start:"), err.message);
    process.exit(1);
  });

  // Handle graceful shutdown
  process.on("SIGINT", async () => {
    console.log("\n" + blueBright("Shutting down..."));
    await client.stop();
    process.exit(0);
  });

  process.on("SIGTERM", async () => {
    await client.stop();
    process.exit(0);
  });

  // Catch uncaught exceptions
  process.on("uncaughtException", function (err) {
    console.error(red("Uncaught exception:"), err);
    client.stop().finally(() => process.exit(1));
  });

  process.on("unhandledRejection", (reason, promise) => {
    console.error(red("Unhandled Rejection at:"), promise, reason);
    client.stop().finally(() => process.exit(1));
  });
};
