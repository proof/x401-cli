import {
  mkdir,
  open,
  readFile,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { Environment } from "@proof.com/proof-vc-common";
import { CliError } from "./output.ts";

export type Tokens = {
  issuer?: string;
  access_token: string;
  refresh_token?: string;
  expires_at?: number;
  scope?: string;
};

export type Credentials = Partial<Record<Environment, Tokens>>;

const LOCK_RETRY_MS = 50;
const LOCK_TIMEOUT_MS = 10_000;
const LOCK_STALE_MS = 60_000;

export function credentialsPath(env: NodeJS.ProcessEnv): string {
  if (env.X401_AUTH_FILE) {
    return env.X401_AUTH_FILE;
  }
  const config = env.XDG_CONFIG_HOME || join(env.HOME || homedir(), ".config");
  return join(config, "proof", "x401-cli", "credentials.json");
}

export function pendingDir(path: string): string {
  return join(dirname(path), "pending");
}

export async function readCredentials(path: string): Promise<Credentials> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return {};
    }
    throw error;
  }
  const parsed: unknown = JSON.parse(text);
  if (typeof parsed !== "object" || parsed === null) {
    throw new CliError("usage", `${path} is not a credentials file`);
  }
  return parsed as Credentials;
}

export async function writeCredentials(
  path: string,
  credentials: Credentials,
): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(credentials, null, 2)}\n`, {
    mode: 0o600,
  });
  await rename(temporary, path);
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export async function withLock<T>(
  path: string,
  fn: () => Promise<T>,
): Promise<T> {
  const lock = `${path}.lock`;
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const deadline = Date.now() + LOCK_TIMEOUT_MS;
  for (;;) {
    try {
      const handle = await open(lock, "wx", 0o600);
      await handle.close();
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
        throw error;
      }
      const held = await stat(lock).catch(() => undefined);
      if (held !== undefined && Date.now() - held.mtimeMs > LOCK_STALE_MS) {
        await rm(lock, { force: true });
        continue;
      }
      if (Date.now() > deadline) {
        throw new CliError("usage", `credentials file is locked: ${lock}`);
      }
      await sleep(LOCK_RETRY_MS);
    }
  }
  try {
    return await fn();
  } finally {
    await rm(lock, { force: true });
  }
}
