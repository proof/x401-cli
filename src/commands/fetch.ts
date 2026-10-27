import { readFile, writeFile } from "node:fs/promises";
import { setTimeout as sleep } from "node:timers/promises";
import type { Environment } from "@proof.com/proof-vc-common";
import {
  awaitPresentation,
  cancelPresentation,
  createPresentation,
  encodeProofResponse,
  getPresentation,
  requirementOf,
  retryWithProofResponse,
  withX401Fetch,
  X401AgentError,
  type DcApiRequest,
  type Presentation,
  type PresentationPending,
  type ProofOptions,
  type ResultReference,
  type X401Wallet,
} from "@proof.com/x401-agent";
import { proofOptions, type Context } from "../context.ts";
import { pendingDir } from "../credentials.ts";
import { environmentOf } from "../environment.ts";
import { CliError, event } from "../output.ts";
import {
  readPending,
  removePending,
  restoreRequest,
  storeRequest,
  writePending,
} from "../pending.ts";

type Announced = Pick<PresentationPending, "id" | "notification">;

function resolveEnvironment(
  ctx: Context,
  requirement: DcApiRequest,
): Environment {
  const detected = environmentOf(requirement);
  if (ctx.options.sandbox) {
    if (detected !== undefined && detected !== "sandbox") {
      throw new CliError(
        "environment_mismatch",
        "the challenge is for Proof production; run without --sandbox",
      );
    }
    return "sandbox";
  }
  if (detected === undefined) {
    throw new CliError(
      "environment_mismatch",
      "the challenge is not for a known Proof environment",
    );
  }
  return detected;
}

function pendingError(
  presentation: PresentationPending | Presentation,
  message: string,
): CliError {
  return new CliError("approval_pending", message, {
    presentationId: presentation.id,
    ...("approval_uri" in presentation && {
      approvalUri: presentation.approval_uri,
    }),
    ...("retry_after" in presentation && {
      retryAfter: presentation.retry_after,
    }),
  });
}

function announce(ctx: Context, pending: PresentationPending): void {
  const { channel, destination_hint } = pending.notification;
  const parts = [
    channel,
    ...(destination_hint !== undefined ? [destination_hint] : []),
    `expires=${pending.expires_at}`,
    `id=${pending.id}`,
    ...(channel === "none" ? [`approve at ${pending.approval_uri}`] : []),
  ];
  event(ctx.io, "approval_required", parts.join(" "));
}

export function mapError(
  ctx: Context,
  error: unknown,
  signal?: AbortSignal,
): CliError {
  if (error instanceof CliError) {
    return error;
  }
  if (error instanceof X401AgentError) {
    switch (error.code) {
      case "proof_rejected":
        return new CliError("proof_rejected", error.message, {
          ...(error.result !== undefined && { result: error.result }),
        });
      case "rate_limited":
        return new CliError("rate_limited", error.message, {
          ...(error.retryAfter !== undefined && {
            retryAfter: error.retryAfter,
          }),
        });
      case "unauthorized":
        return new CliError(
          "unauthorized",
          ctx.env.PROOF_ACCESS_TOKEN
            ? "Proof rejected PROOF_ACCESS_TOKEN"
            : "Proof rejected the stored token; run `x401-cli login`",
        );
      default:
        return new CliError(error.code, error.message);
    }
  }
  if (signal?.aborted) {
    return new CliError("network", "the request did not complete in time");
  }
  return new CliError(
    "network",
    error instanceof Error ? error.message : String(error),
  );
}

async function awaitOrPending(
  ctx: Context,
  options: ProofOptions,
  presentation: Presentation,
  signal: AbortSignal,
): Promise<ResultReference> {
  let current = presentation;
  try {
    while (current.status === "pending" && current.retry_after > 0) {
      await sleep(current.retry_after * 1000, undefined, { signal });
      current = await getPresentation(options, current.id);
    }
  } catch (error) {
    if (signal.aborted) {
      throw pendingError(
        current,
        `no approval yet; run \`x401-cli resume ${current.id}\``,
      );
    }
    throw error;
  }
  const proof = await awaitPresentation(options, current);
  await removePending(pendingDir(ctx.options.auth), current.id);
  return proof;
}

function wallet(
  ctx: Context,
  signal: AbortSignal,
  onPending: (
    environment: Environment,
    pending: PresentationPending,
  ) => Promise<void>,
): X401Wallet {
  return {
    present: async ({ requirement }) => {
      const environment = resolveEnvironment(ctx, requirement);
      const options = proofOptions(ctx, environment);
      const pending = await createPresentation(options, requirement);
      await onPending(environment, pending);
      announce(ctx, pending);
      if (ctx.options.noWait) {
        throw pendingError(
          pending,
          `waiting for the user's approval; run \`x401-cli resume ${pending.id}\``,
        );
      }
      return awaitOrPending(ctx, options, pending, signal);
    },
  };
}

async function bodyFrom(ctx: Context, data: string): Promise<Buffer> {
  if (data === "@-") {
    return ctx.readStdin();
  }
  if (data.startsWith("@")) {
    return readFile(data.slice(1));
  }
  return Buffer.from(data);
}

async function buildRequest(
  ctx: Context,
  url: string,
  signal: AbortSignal,
): Promise<Request> {
  const headers = new Headers();
  for (const header of ctx.options.headers) {
    const colon = header.indexOf(":");
    if (colon <= 0) {
      throw new CliError("usage", `invalid header: ${header}`);
    }
    headers.append(
      header.slice(0, colon).trim(),
      header.slice(colon + 1).trim(),
    );
  }
  if (!headers.has("user-agent")) {
    headers.set("User-Agent", "x401-cli");
  }
  const body =
    ctx.options.data !== undefined
      ? await bodyFrom(ctx, ctx.options.data)
      : undefined;
  try {
    return new Request(new URL(url), {
      method: ctx.options.method ?? (body === undefined ? "GET" : "POST"),
      headers,
      ...(body !== undefined && { body: new Uint8Array(body) }),
      redirect: "manual",
      signal,
    });
  } catch (error) {
    throw new CliError(
      "usage",
      `invalid request: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

async function emit(
  ctx: Context,
  response: Response,
  presentation: Announced | undefined,
): Promise<void> {
  const bytes = Buffer.from(await response.arrayBuffer());
  event(
    ctx.io,
    String(response.status),
    `${response.statusText || ""} (${bytes.length} B)`.trim(),
  );
  const output = ctx.options.output;
  if (output !== undefined) {
    await writeFile(output, bytes);
  }
  if (ctx.options.json) {
    let body: string;
    let encoding: "utf-8" | "base64" = "utf-8";
    try {
      body = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      body = bytes.toString("base64");
      encoding = "base64";
    }
    ctx.io.stdout.write(
      `${JSON.stringify({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        ...(output === undefined
          ? { body, body_encoding: encoding }
          : { body_file: output }),
        ...(presentation !== undefined && {
          presentation: {
            id: presentation.id,
            notification: presentation.notification,
          },
        }),
      })}\n`,
    );
    return;
  }
  if (output === undefined) {
    ctx.io.stdout.write(bytes);
  }
}

export async function fetchCommand(ctx: Context, url: string): Promise<void> {
  const signal = AbortSignal.timeout(ctx.options.timeoutMs);
  const request = await buildRequest(ctx, url, signal);
  const stored = await storeRequest(request);
  let announced: Announced | undefined;
  const proofWallet = wallet(ctx, signal, async (environment, pending) => {
    announced = pending;
    await writePending(pendingDir(ctx.options.auth), {
      environment,
      presentation: pending,
      request: stored,
    });
  });
  let response: Response;
  try {
    response = await withX401Fetch(ctx.fetch, proofWallet)(request);
  } catch (error) {
    throw mapError(ctx, error, signal);
  }
  await emit(ctx, response, announced);
}

export async function resumeCommand(ctx: Context, id: string): Promise<void> {
  const record = await readPending(pendingDir(ctx.options.auth), id);
  const options = proofOptions(ctx, record.environment);
  const signal = AbortSignal.timeout(ctx.options.timeoutMs);
  let proof: ResultReference;
  try {
    const presentation = await getPresentation(options, id);
    proof = await awaitOrPending(ctx, options, presentation, signal);
  } catch (error) {
    throw mapError(ctx, error, signal);
  }
  if (record.request === undefined) {
    emitProof(ctx, proof);
    return;
  }
  let response: Response;
  try {
    response = await retryWithProofResponse(
      ctx.fetch,
      restoreRequest(record.request, signal),
      proof,
    );
  } catch (error) {
    throw mapError(ctx, error, signal);
  }
  await emit(ctx, response, record.presentation);
}

export async function cancelCommand(ctx: Context, id: string): Promise<void> {
  const dir = pendingDir(ctx.options.auth);
  const record = await readPending(dir, id);
  try {
    await cancelPresentation(proofOptions(ctx, record.environment), id);
  } catch (error) {
    throw mapError(ctx, error);
  }
  await removePending(dir, id);
  event(ctx.io, "cancelled", `id=${id}`);
  if (ctx.options.json) {
    ctx.io.stdout.write(`${JSON.stringify({ cancelled: id })}\n`);
  }
}

function emitProof(ctx: Context, result: ResultReference): void {
  const proof = encodeProofResponse(result);
  ctx.io.stdout.write(
    ctx.options.json
      ? `${JSON.stringify({ proof_response: proof })}\n`
      : `${proof}\n`,
  );
}

async function proofRequestFrom(ctx: Context, value: string): Promise<string> {
  if (value === "-") {
    return (await ctx.readStdin()).toString().trim();
  }
  if (value.startsWith("@")) {
    return (await readFile(value.slice(1), "utf8")).trim();
  }
  return value.trim();
}

export async function presentCommand(ctx: Context): Promise<void> {
  if (ctx.options.resume !== undefined) {
    await resumeCommand(ctx, ctx.options.resume);
    return;
  }
  if (ctx.options.proofRequest === undefined) {
    throw new CliError(
      "usage",
      "present needs --proof-request <value|-|@file> or --resume <id>",
    );
  }
  let requirement: DcApiRequest;
  try {
    requirement = requirementOf(
      await proofRequestFrom(ctx, ctx.options.proofRequest),
    );
  } catch {
    throw new CliError(
      "invalid_proof_request",
      "the PROOF-REQUEST value is not a valid x401 proof requirement",
    );
  }
  const signal = AbortSignal.timeout(ctx.options.timeoutMs);
  const proofWallet = wallet(ctx, signal, (environment, pending) =>
    writePending(pendingDir(ctx.options.auth), {
      environment,
      presentation: pending,
    }),
  );
  let proof: ResultReference;
  try {
    proof = await proofWallet.present({ requirement, origin: "" });
  } catch (error) {
    throw mapError(ctx, error, signal);
  }
  emitProof(ctx, proof);
}
