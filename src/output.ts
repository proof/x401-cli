import type { X401ErrorObject } from "@proof.com/x401-node";

export const EXIT = {
  usage: 1,
  network: 2,
  unauthorized: 3,
  environment_mismatch: 4,
  approval_pending: 5,
  expired: 7,
  cancelled: 8,
  proof_rejected: 9,
  invalid_proof_request: 10,
  rate_limited: 11,
  presentation_failed: 12,
} as const;

export type ErrorCode = keyof typeof EXIT;

export type ErrorExtra = {
  presentationId?: string;
  approvalUri?: string;
  retryAfter?: number;
  result?: X401ErrorObject;
};

export class CliError extends Error {
  readonly code: ErrorCode;
  readonly extra: ErrorExtra;

  constructor(code: ErrorCode, message: string, extra: ErrorExtra = {}) {
    super(message);
    this.code = code;
    this.extra = extra;
  }
}

export type Writer = { write(chunk: string | Uint8Array): unknown };

export type Io = { stdout: Writer; stderr: Writer };

export function event(io: Io, code: string, text: string): void {
  io.stderr.write(`x401-cli: ${code} ${text}\n`);
}

export function failureJson(error: CliError): Record<string, unknown> {
  const { presentationId, approvalUri, retryAfter, result } = error.extra;
  return {
    error: error.code,
    error_description: error.message,
    exit_code: EXIT[error.code],
    ...(presentationId !== undefined && { presentation_id: presentationId }),
    ...(approvalUri !== undefined && { approval_uri: approvalUri }),
    ...(retryAfter !== undefined && { retry_after: retryAfter }),
    ...(result !== undefined && { result }),
  };
}

export function parseDuration(value: string): number {
  const match = /^(\d+)(ms|s|m|h)?$/.exec(value.trim());
  if (match === null) {
    throw new CliError("usage", `invalid duration: ${value}`);
  }
  const amount = Number(match[1]);
  switch (match[2]) {
    case "ms":
      return amount;
    case "m":
      return amount * 60_000;
    case "h":
      return amount * 3_600_000;
    default:
      return amount * 1000;
  }
}
