#!/usr/bin/env node
import { spawn } from "node:child_process";
import { parseArgs } from "node:util";
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import {
  loginCommand,
  logoutCommand,
  statusCommand,
  tokenCommand,
} from "./commands/auth.ts";
import {
  cancelCommand,
  fetchCommand,
  presentCommand,
  resumeCommand,
} from "./commands/fetch.ts";
import type { Context, Deps, Options } from "./context.ts";
import { credentialsPath } from "./credentials.ts";
import { CliError, EXIT, event, failureJson, parseDuration } from "./output.ts";

const USAGE = `Usage: x401-cli <command> [options]

Commands
  login                 Sign in to Proof in the browser and store the tokens
  logout                Revoke and forget the stored tokens
  status                Show the stored logins
  token                 Print the access token; signs in first when there is no login
  fetch <url>           Fetch a URL, presenting the user's Proof credential if it asks for one
  resume <id>           Continue a pending presentation and replay its request
  cancel <id>           Cancel a pending presentation
  present               Turn a PROOF-REQUEST into a PROOF-RESPONSE for your own HTTP client

Options
  --sandbox             Use Proof's sandbox environment
  --json                One JSON object on stdout, on success and failure
  --auth <path>         Credentials file (default: $XDG_CONFIG_HOME/proof/x401-cli/credentials.json)
  --timeout <duration>  How long to wait for the user's approval, e.g. 9m (default: 15m)
  --no-wait             Return as soon as the approval is pending (exit 5), resume later
  --no-browser          login: print the sign-in URL instead of opening the browser
  -X, --method <m>      fetch: HTTP method
  -H, --header <h>      fetch: header "Name: value", repeatable
  -d, --data <body>     fetch: body; @file or @- for stdin
  -o, --output <file>   fetch: write the body to a file
  --proof-request <v>   present: the PROOF-REQUEST value, - for stdin, @file
  --resume <id>         present: continue a pending presentation
  -h, --help            Show this help

Environment
  PROOF_ACCESS_TOKEN    Use this access token instead of the credentials file (no refresh)
  X401_AUTH_FILE        Credentials file path
  PROOF_ISSUER          Proof API base URL to use instead of the environment's (local testing)

Exit codes
  0 the site answered   1 usage   2 network   3 unauthorized (run login)
  4 environment_mismatch   5 approval_pending   7 expired   8 cancelled
  9 proof_rejected   10 invalid_proof_request   11 rate_limited   12 presentation_failed
`;

const DEFAULT_TIMEOUT = "15m";

function parse(argv: string[]): {
  command: string | undefined;
  positional: string[];
  options: Options;
  help: boolean;
} {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      json: { type: "boolean", default: false },
      sandbox: { type: "boolean", default: false },
      auth: { type: "string" },
      timeout: { type: "string", default: DEFAULT_TIMEOUT },
      "no-wait": { type: "boolean", default: false },
      "no-browser": { type: "boolean", default: false },
      method: { type: "string", short: "X" },
      header: { type: "string", short: "H", multiple: true, default: [] },
      data: { type: "string", short: "d" },
      output: { type: "string", short: "o" },
      "proof-request": { type: "string" },
      resume: { type: "string" },
      help: { type: "boolean", short: "h", default: false },
    },
  });
  const [command, ...positional] = positionals;
  return {
    command,
    positional,
    help: values.help,
    options: {
      json: values.json,
      sandbox: values.sandbox,
      auth: values.auth ?? "",
      timeoutMs: parseDuration(values.timeout),
      noWait: values["no-wait"],
      noBrowser: values["no-browser"],
      ...(values.method !== undefined && {
        method: values.method.toUpperCase(),
      }),
      headers: values.header,
      ...(values.data !== undefined && { data: values.data }),
      ...(values.output !== undefined && { output: values.output }),
      ...(values["proof-request"] !== undefined && {
        proofRequest: values["proof-request"],
      }),
      ...(values.resume !== undefined && { resume: values.resume }),
    },
  };
}

const requireOne = (positional: string[], what: string): string => {
  const [value] = positional;
  if (value === undefined || positional.length !== 1) {
    throw new CliError("usage", `exactly one ${what} is required`);
  }
  return value;
};

async function dispatch(
  ctx: Context,
  command: string | undefined,
  positional: string[],
): Promise<number | void> {
  switch (command) {
    case "login":
      return loginCommand(ctx);
    case "logout":
      return logoutCommand(ctx);
    case "status":
      return statusCommand(ctx);
    case "token":
      return tokenCommand(ctx);
    case "fetch":
      return fetchCommand(ctx, requireOne(positional, "URL"));
    case "resume":
      return resumeCommand(ctx, requireOne(positional, "presentation id"));
    case "cancel":
      return cancelCommand(ctx, requireOne(positional, "presentation id"));
    case "present":
      return presentCommand(ctx);
    case undefined:
      throw new CliError("usage", "a command is required; see --help");
    default:
      throw new CliError("usage", `unknown command ${command}; see --help`);
  }
}

export async function run(argv: string[], deps: Deps): Promise<number> {
  let parsed: ReturnType<typeof parse>;
  try {
    parsed = parse(argv);
  } catch (error) {
    deps.io.stderr.write(
      `x401-cli: usage ${error instanceof Error ? error.message : String(error)}\n`,
    );
    return EXIT.usage;
  }
  if (parsed.help) {
    deps.io.stdout.write(USAGE);
    return 0;
  }
  const options = {
    ...parsed.options,
    auth: parsed.options.auth || credentialsPath(deps.env),
  };
  const issuer = deps.env.PROOF_ISSUER;
  const ctx: Context = {
    ...deps,
    ...(issuer !== undefined &&
      issuer !== "" && {
        issuers: { production: issuer, sandbox: issuer },
      }),
    options,
  };
  try {
    return (await dispatch(ctx, parsed.command, parsed.positional)) ?? 0;
  } catch (error) {
    const failure =
      error instanceof CliError
        ? error
        : new CliError(
            "presentation_failed",
            error instanceof Error ? error.message : String(error),
          );
    event(ctx.io, failure.code, failure.message);
    if (options.json) {
      ctx.io.stdout.write(`${JSON.stringify(failureJson(failure))}\n`);
    }
    return EXIT[failure.code];
  }
}

function openBrowser(url: string): Promise<void> {
  const [command, ...args] =
    process.platform === "darwin"
      ? ["open", url]
      : process.platform === "win32"
        ? ["cmd", "/c", "start", "", url]
        : ["xdg-open", url];
  return new Promise((resolve, reject) => {
    const child = spawn(command!, args, { stdio: "ignore", detached: true });
    child.once("error", reject);
    child.once("spawn", () => {
      child.unref();
      resolve();
    });
  });
}

async function readStdin(): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href
) {
  const code = await run(process.argv.slice(2), {
    env: process.env,
    io: { stdout: process.stdout, stderr: process.stderr },
    fetch: globalThis.fetch,
    openBrowser,
    now: () => Math.floor(Date.now() / 1000),
    readStdin,
  });
  process.exitCode = code;
}
