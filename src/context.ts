import type { Environment } from "@proof.com/proof-vc-common";
import type { ProofOptions } from "@proof.com/x401-agent";
import {
  readCredentials,
  withLock,
  writeCredentials,
  type Tokens,
} from "./credentials.ts";
import { issuerOf, type Issuers } from "./environment.ts";
import { refresh, type OAuthDeps } from "./oauth.ts";
import { CliError, type Io } from "./output.ts";

export type Deps = {
  env: NodeJS.ProcessEnv;
  io: Io;
  fetch: typeof globalThis.fetch;
  openBrowser: (url: string) => Promise<void>;
  now: () => number;
  readStdin: () => Promise<Buffer>;
  issuers?: Issuers;
};

export type Options = {
  json: boolean;
  sandbox: boolean;
  auth: string;
  timeoutMs: number;
  noWait: boolean;
  noBrowser: boolean;
  method?: string;
  headers: string[];
  data?: string;
  output?: string;
  proofRequest?: string;
  resume?: string;
};

export type Context = Deps & { options: Options };

const REFRESH_MARGIN_SECONDS = 30;

export const loginCommand = (environment: Environment): string =>
  environment === "sandbox" ? "x401-cli login --sandbox" : "x401-cli login";

export function oauthDeps(ctx: Context, environment: Environment): OAuthDeps {
  return {
    issuer: issuerOf(environment, ctx.issuers),
    fetch: ctx.fetch,
    now: ctx.now,
  };
}

export const loginIssuer = (environment: Environment, tokens: Tokens): string =>
  tokens.issuer ?? issuerOf(environment);

function assertIssuer(
  ctx: Context,
  environment: Environment,
  tokens: Tokens,
): void {
  const issuer = loginIssuer(environment, tokens);
  const expected = issuerOf(environment, ctx.issuers);
  if (issuer !== expected) {
    throw new CliError(
      "environment_mismatch",
      `the ${environment} login is for ${issuer}, but this run uses ${expected}; set PROOF_ISSUER to match or run \`${loginCommand(environment)}\``,
    );
  }
}

function expired(ctx: Context, tokens: Tokens): boolean {
  return (
    tokens.expires_at !== undefined &&
    tokens.expires_at <= ctx.now() + REFRESH_MARGIN_SECONDS
  );
}

export function accessTokenFor(
  ctx: Context,
  environment: Environment,
): () => Promise<string> {
  return async () => {
    const fromEnv = ctx.env.PROOF_ACCESS_TOKEN;
    if (fromEnv) {
      return fromEnv;
    }
    const path = ctx.options.auth;
    let tokens = (await readCredentials(path))[environment];
    if (tokens === undefined) {
      const others = Object.keys(await readCredentials(path)).length > 0;
      throw new CliError(
        others ? "environment_mismatch" : "unauthorized",
        `no ${environment} login; run \`${loginCommand(environment)}\``,
      );
    }
    assertIssuer(ctx, environment, tokens);
    if (expired(ctx, tokens)) {
      tokens = await withLock(path, async () => {
        const credentials = await readCredentials(path);
        const current = credentials[environment];
        if (current !== undefined && !expired(ctx, current)) {
          return current;
        }
        const next = await refresh(
          oauthDeps(ctx, environment),
          current ?? tokens!,
        );
        await writeCredentials(path, { ...credentials, [environment]: next });
        return next;
      });
    }
    return tokens.access_token;
  };
}

export function proofOptions(
  ctx: Context,
  environment: Environment,
): ProofOptions {
  const issuer = ctx.issuers?.[environment];
  return {
    environment: issuer === undefined ? environment : { baseUrl: issuer },
    accessToken: accessTokenFor(ctx, environment),
    fetch: ctx.fetch,
  };
}
