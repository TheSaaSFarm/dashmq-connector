import fetch from "node-fetch";
import chalk from "chalk";
import { QueueRegistry, RegisteredQueue } from "./queue-registry";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ConnectorCommand {
  id: string;
  type: "retry" | "delete" | "pause" | "resume";
  queue: string;
  bullmqId?: string | null;
  payload?: any;
}

interface CommandResult {
  commandId: string;
  status: "acked" | "failed";
  result?: string;
}

// ---------------------------------------------------------------------------
// CommandExecutor — polls for and executes commands from the dashboard
// ---------------------------------------------------------------------------

export class CommandExecutor {
  private registry: QueueRegistry;
  private prefix: string;

  constructor(registry: QueueRegistry, prefix: string = "bull") {
    this.registry = registry;
    this.prefix = prefix;
  }

  async pollAndExecute(token: string, backendUrl: string): Promise<void> {
    let commands: ConnectorCommand[];

    try {
      const response = await fetch(`${backendUrl}/api/connector/commands`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        if (response.status !== 401) {
          console.error(chalk.red("[DashMQ] Failed to poll commands:"), response.status);
        }
        return;
      }

      const data = (await response.json()) as { commands: ConnectorCommand[] };
      commands = data.commands || [];
    } catch (error: any) {
      // Network errors are transient — don't spam logs
      return;
    }

    if (commands.length === 0) return;

    console.log(`${chalk.yellow("DashMQ:")} ${chalk.blueBright("Executing")} ${chalk.gray(`${commands.length} command(s)`)}`);

    for (const cmd of commands) {
      const result = await this.execute(cmd);
      await this.ack(token, backendUrl, result);
    }
  }

  private async execute(cmd: ConnectorCommand): Promise<CommandResult> {
    try {
      // Resolve through the registry so the queue is driven by the client that
      // actually speaks its protocol (Bull v3/v4 vs BullMQ v3/v4/v5) and so we
      // reuse the cached connection instead of opening a new one per command.
      const registered = this.registry.getByName(cmd.queue, this.prefix);
      const { queue } = registered;

      switch (cmd.type) {
        case "retry": {
          if (!cmd.bullmqId) throw new Error("bullmqId required for retry");
          const job = await queue.getJob(cmd.bullmqId);
          if (!job) throw new Error(`Job ${cmd.bullmqId} not found`);
          await job.retry();
          console.log(`${chalk.yellow("DashMQ:")} ${chalk.green("Retried")} job ${chalk.gray(cmd.bullmqId)} in ${chalk.blueBright(cmd.queue)} ${chalk.gray(describe(registered))}`);
          break;
        }
        case "delete": {
          if (!cmd.bullmqId) throw new Error("bullmqId required for delete");
          const job = await queue.getJob(cmd.bullmqId);
          if (job) {
            await job.remove();
            console.log(`${chalk.yellow("DashMQ:")} ${chalk.green("Deleted")} job ${chalk.gray(cmd.bullmqId)} in ${chalk.blueBright(cmd.queue)} ${chalk.gray(describe(registered))}`);
          } else {
            console.log(`${chalk.yellow("DashMQ:")} Job ${chalk.gray(cmd.bullmqId)} already removed`);
          }
          break;
        }
        case "pause": {
          await queue.pause();
          console.log(`${chalk.yellow("DashMQ:")} ${chalk.green("Paused")} queue ${chalk.blueBright(cmd.queue)} ${chalk.gray(describe(registered))}`);
          break;
        }
        case "resume": {
          await queue.resume();
          console.log(`${chalk.yellow("DashMQ:")} ${chalk.green("Resumed")} queue ${chalk.blueBright(cmd.queue)} ${chalk.gray(describe(registered))}`);
          break;
        }
        default:
          throw new Error(`Unknown command type: ${cmd.type}`);
      }

      return { commandId: cmd.id, status: "acked" };
    } catch (error: any) {
      console.error(chalk.red(`[DashMQ] Command ${cmd.type} failed:`), error.message);
      return { commandId: cmd.id, status: "failed", result: error.message };
    }
  }

  private async ack(token: string, backendUrl: string, result: CommandResult): Promise<void> {
    try {
      await fetch(`${backendUrl}/api/connector/commands/ack`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(result),
      });
    } catch {
      // Best effort — command will be retried on next poll if ack fails
    }
  }
}

function describe(registered: RegisteredQueue): string {
  return registered.version
    ? `(${registered.type} v${registered.version})`
    : `(${registered.type})`;
}
