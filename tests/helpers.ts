import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Environment } from "@proof.com/proof-vc-common";
import { authorizationServerIssuer } from "@proof.com/proof-vc-common/internal";
import { HEADER, verifier } from "@proof.com/x401-node";
import type { Deps } from "../src/context.ts";
import { run } from "../src/cli.ts";

export const SANDBOX = "https://api.fairfax.proof.com";
export const SITE = "https://site.example/protected";
export const NOW = 1_800_000_000;

export const b64url = (value: unknown): string =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

export const proofRequestFor = (environment: Environment): string =>
  verifier.encodePayload(
    verifier.buildPayload({
      credentialRequirements: {
        digital: {
          requests: [
            {
              protocol: "openid4vp-v1-signed",
              data: {
                request: `${b64url({ alg: "ES256" })}.${b64url({
                  aud: authorizationServerIssuer(environment),
                })}.sig`,
              },
            },
          ],
        },
      },
    }),
  );

export const AS_METADATA = {
  issuer: SANDBOX,
  authorization_endpoint: `${SANDBOX}/oauth/v2/authorize`,
  token_endpoint: `${SANDBOX}/oauth/v2/token`,
  revocation_endpoint: `${SANDBOX}/oauth/v2/revoke`,
  code_challenge_methods_supported: ["S256"],
  response_types_supported: ["code"],
  token_endpoint_auth_methods_supported: ["none"],
};

export const PENDING = {
  id: "ot1",
  status: "pending",
  approval_uri: "https://proof.example/approve/ot1",
  notification: { channel: "email", destination_hint: "j***@example.com" },
  retry_after: 1,
  expires_at: "2027-01-15T09:00:00Z",
};

export const READY = {
  id: "ot1",
  status: "ready",
  credential_result_uri: `${SANDBOX}/verifiable-credentials/v1/dc-api/results/4f8c`,
  expires_at: "2027-01-15T08:05:00Z",
};

export const TOKENS = {
  access_token: "fresh-access",
  refresh_token: "fresh-refresh",
  expires_in: 7200,
  token_type: "bearer",
  scope: "agentic",
};

export const challenge = (environment: Environment = "sandbox") =>
  new Response(null, {
    status: 401,
    headers: { [HEADER.PROOF_REQUEST]: proofRequestFor(environment) },
  });

export const rejection = (error: string) =>
  new Response(null, {
    status: 401,
    headers: {
      [HEADER.PROOF_RESULT]: b64url({
        scheme: "x401",
        version: "0.2.0",
        error,
      }),
    },
  });

export type Route = (
  request: Request,
  url: URL,
) => Promise<Response | undefined> | Response | undefined;

export function stubFetch(...routes: Route[]) {
  const calls: Request[] = [];
  const fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    calls.push(request.clone());
    const url = new URL(request.url);
    for (const route of routes) {
      const response = await route(request, url);
      if (response !== undefined) {
        return response;
      }
    }
    return new Response(`unrouted ${request.method} ${request.url}`, {
      status: 599,
    });
  };
  return { fetch, calls };
}

export const siteRoute =
  (onRetry: () => Response = () => new Response("granted")): Route =>
  (request, url) => {
    if (url.origin !== new URL(SITE).origin) {
      return undefined;
    }
    return request.headers.has(HEADER.PROOF_RESPONSE) ? onRetry() : challenge();
  };

export const proofRoute =
  (views: Record<string, unknown>[] = [READY]): Route =>
  (request, url) => {
    if (url.origin !== SANDBOX) {
      return undefined;
    }
    const key = `${request.method} ${url.pathname}`;
    if (key === "GET /.well-known/oauth-authorization-server") {
      return Response.json(AS_METADATA);
    }
    if (key === "POST /oauth/v2/token") {
      return Response.json(TOKENS);
    }
    if (key === "POST /oauth/v2/revoke") {
      return Response.json({});
    }
    if (key === "POST /verifiable-credentials/v1/dc-api/requests") {
      return Response.json(PENDING, { status: 201 });
    }
    if (key === "GET /verifiable-credentials/v1/dc-api/requests/ot1") {
      return Response.json(views.shift() ?? READY);
    }
    if (key === "DELETE /verifiable-credentials/v1/dc-api/requests/ot1") {
      return new Response(null, { status: 204 });
    }
    return undefined;
  };

export async function workspace(credentials?: Record<string, unknown>) {
  const dir = await mkdtemp(join(tmpdir(), "x401-cli-"));
  const auth = join(dir, "credentials.json");
  if (credentials !== undefined) {
    await writeFile(auth, JSON.stringify(credentials));
  }
  return { dir, auth };
}

export const sandboxLogin = (expiresAt = NOW + 3600, issuer = SANDBOX) => ({
  sandbox: {
    issuer,
    access_token: "tok",
    refresh_token: "ref",
    expires_at: expiresAt,
  },
});

export async function cli(
  argv: string[],
  deps: Partial<Deps> & { fetch: typeof globalThis.fetch },
) {
  let stdout = "";
  let stderr = "";
  const code = await run(argv, {
    env: {},
    io: {
      stdout: { write: (chunk) => (stdout += chunk.toString()) },
      stderr: { write: (chunk) => (stderr += chunk.toString()) },
    },
    openBrowser: async () => undefined,
    now: () => NOW,
    readStdin: async () => Buffer.alloc(0),
    ...deps,
  });
  return { code, stdout, stderr, json: () => JSON.parse(stdout) };
}

export const readJson = async (path: string) =>
  JSON.parse(await readFile(path, "utf8"));
