import type { Environment } from "@proof.com/proof-vc-common";
import {
  accessTokenFor,
  loginIssuer,
  oauthDeps,
  type Context,
} from "../context.ts";
import {
  readCredentials,
  withLock,
  writeCredentials,
  type Tokens,
} from "../credentials.ts";
import { CLIENT_ID, ENVIRONMENTS } from "../environment.ts";
import { login, revoke } from "../oauth.ts";
import { CliError, EXIT, event, failureJson } from "../output.ts";

const environments = (ctx: Context): Environment[] =>
  ctx.options.sandbox ? ["sandbox"] : [...ENVIRONMENTS];

const environmentOf = (ctx: Context): Environment =>
  ctx.options.sandbox ? "sandbox" : "production";

async function signIn(ctx: Context, environment: Environment): Promise<Tokens> {
  const tokens = await login(oauthDeps(ctx, environment), {
    io: ctx.io,
    openBrowser: ctx.openBrowser,
    noBrowser: ctx.options.noBrowser,
    timeoutMs: ctx.options.timeoutMs,
  });
  const path = ctx.options.auth;
  await withLock(path, async () => {
    const credentials = await readCredentials(path);
    await writeCredentials(path, { ...credentials, [environment]: tokens });
  });
  event(ctx.io, "logged_in", `${environment} (${path})`);
  return tokens;
}

export async function loginCommand(ctx: Context): Promise<void> {
  const environment = environmentOf(ctx);
  const tokens = await signIn(ctx, environment);
  if (ctx.options.json) {
    ctx.io.stdout.write(
      `${JSON.stringify({ environment, expires_at: tokens.expires_at ?? null })}\n`,
    );
  }
}

export async function tokenCommand(ctx: Context): Promise<void> {
  const environment = environmentOf(ctx);
  if (
    !ctx.env.PROOF_ACCESS_TOKEN &&
    (await readCredentials(ctx.options.auth))[environment] === undefined
  ) {
    await signIn(ctx, environment);
  }
  const token = await accessTokenFor(ctx, environment)();
  ctx.io.stdout.write(
    ctx.options.json
      ? `${JSON.stringify({ access_token: token })}\n`
      : `${token}\n`,
  );
}

export async function logoutCommand(ctx: Context): Promise<void> {
  const path = ctx.options.auth;
  const loggedOut: Environment[] = [];
  await withLock(path, async () => {
    const credentials = await readCredentials(path);
    for (const environment of environments(ctx)) {
      const tokens = credentials[environment];
      if (tokens === undefined) {
        continue;
      }
      try {
        await revoke(
          {
            ...oauthDeps(ctx, environment),
            issuer: loginIssuer(environment, tokens),
          },
          tokens,
        );
      } catch {
        event(
          ctx.io,
          "logout",
          `${environment}: Proof did not confirm the revocation`,
        );
      }
      delete credentials[environment];
      loggedOut.push(environment);
      event(ctx.io, "logged_out", environment);
    }
    await writeCredentials(path, credentials);
  });
  if (ctx.options.json) {
    ctx.io.stdout.write(`${JSON.stringify({ logged_out: loggedOut })}\n`);
  }
}

type Status = {
  environment: Environment;
  issuer: string;
  expires_at: number | null;
  refreshable: boolean;
};

export async function statusCommand(ctx: Context): Promise<number> {
  const path = ctx.options.auth;
  const fromEnv = Boolean(ctx.env.PROOF_ACCESS_TOKEN);
  const credentials = await readCredentials(path);
  const entries: Status[] = environments(ctx).flatMap((environment) => {
    const tokens: Tokens | undefined = credentials[environment];
    return tokens === undefined
      ? []
      : [
          {
            environment,
            issuer: loginIssuer(environment, tokens),
            expires_at: tokens.expires_at ?? null,
            refreshable: tokens.refresh_token !== undefined,
          },
        ];
  });
  const missing = !fromEnv && entries.length === 0;
  const failure = new CliError(
    "unauthorized",
    `no login; run \`x401-cli login${ctx.options.sandbox ? " --sandbox" : ""}\``,
  );
  const summary = {
    client_id: CLIENT_ID,
    credentials_file: path,
    token_source: fromEnv ? "env" : "file",
    logins: entries,
    ...(missing && failureJson(failure)),
  };
  if (ctx.options.json) {
    ctx.io.stdout.write(`${JSON.stringify(summary)}\n`);
  } else {
    ctx.io.stdout.write(
      [
        `client_id: ${CLIENT_ID}`,
        `credentials: ${path}${fromEnv ? " (overridden by PROOF_ACCESS_TOKEN)" : ""}`,
        ...entries.map(
          (entry) =>
            `${entry.environment} (${entry.issuer}): expires ${
              entry.expires_at === null
                ? "never"
                : new Date(entry.expires_at * 1000).toISOString()
            }${entry.refreshable ? ", refreshable" : ""}`,
        ),
        ...(entries.length === 0 ? ["no login"] : []),
      ].join("\n") + "\n",
    );
  }
  if (missing) {
    event(ctx.io, failure.code, failure.message);
    return EXIT.unauthorized;
  }
  return 0;
}
