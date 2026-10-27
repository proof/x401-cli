import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Environment } from "@proof.com/proof-vc-common";
import type { PresentationPending } from "@proof.com/x401-agent";
import { CliError } from "./output.ts";

export type StoredRequest = {
  method: string;
  url: string;
  headers: [string, string][];
  body?: string;
};

export type PendingRecord = {
  environment: Environment;
  presentation: PresentationPending;
  request?: StoredRequest;
};

const file = (dir: string, id: string) =>
  join(dir, `${encodeURIComponent(id)}.json`);

export async function writePending(
  dir: string,
  record: PendingRecord,
): Promise<void> {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await writeFile(file(dir, record.presentation.id), JSON.stringify(record), {
    mode: 0o600,
  });
}

export async function readPending(
  dir: string,
  id: string,
): Promise<PendingRecord> {
  try {
    return JSON.parse(await readFile(file(dir, id), "utf8")) as PendingRecord;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new CliError(
        "usage",
        `no pending presentation with id ${id} in ${dir}`,
      );
    }
    throw error;
  }
}

export async function removePending(dir: string, id: string): Promise<void> {
  await rm(file(dir, id), { force: true });
}

export async function storeRequest(request: Request): Promise<StoredRequest> {
  const body = Buffer.from(await request.clone().arrayBuffer());
  return {
    method: request.method,
    url: request.url,
    headers: [...request.headers],
    ...(body.length > 0 && { body: body.toString("base64") }),
  };
}

export function restoreRequest(
  stored: StoredRequest,
  signal: AbortSignal,
): Request {
  return new Request(stored.url, {
    method: stored.method,
    headers: stored.headers,
    ...(stored.body !== undefined && {
      body: new Uint8Array(Buffer.from(stored.body, "base64")),
    }),
    redirect: "manual",
    signal,
  });
}
