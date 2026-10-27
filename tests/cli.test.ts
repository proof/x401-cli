import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readdir, readFile, stat, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { requirementOf } from "@proof.com/x401-agent";
import { HEADER, verifier } from "@proof.com/x401-node";
import { withLock, writeCredentials } from "../src/credentials.ts";
import { environmentOf } from "../src/environment.ts";
import { parseDuration } from "../src/output.ts";
import {
  cli,
  NOW,
  PENDING,
  proofRequestFor,
  proofRoute,
  READY,
  readJson,
  rejection,
  sandboxLogin,
  SITE,
  siteRoute,
  stubFetch,
  workspace,
} from "./helpers.ts";

test("environmentOf reads the Proof environment from the signed request's audience", () => {
  const environmentFor = (value: string) => environmentOf(requirementOf(value));
  assert.equal(environmentFor(proofRequestFor("sandbox")), "sandbox");
  assert.equal(environmentFor(proofRequestFor("production")), "production");
  assert.equal(
    environmentOf({
      protocol: "openid4vp-v1-signed",
      data: { request: "not-a-jwt" },
    }),
    undefined,
  );
});

test("the CLI runs when started through a symlink, as npm and npx install it", async () => {
  const dir = await mkdtemp(join(tmpdir(), "x401-cli-bin-"));
  const link = join(dir, "x401-cli.ts");
  await symlink(fileURLToPath(new URL("../src/cli.ts", import.meta.url)), link);

  const { stdout } = await promisify(execFile)(process.execPath, [
    link,
    "--help",
  ]);

  assert.match(stdout, /^Usage: x401-cli/);
});

test("parseDuration accepts seconds, minutes, hours and bare seconds", () => {
  assert.equal(parseDuration("9m"), 540_000);
  assert.equal(parseDuration("30s"), 30_000);
  assert.equal(parseDuration("1h"), 3_600_000);
  assert.equal(parseDuration("600"), 600_000);
  assert.throws(() => parseDuration("soon"));
});

test("the credentials file is private and the lock serializes writers", async () => {
  const { auth } = await workspace();
  await writeCredentials(auth, sandboxLogin());
  assert.equal((await stat(auth)).mode & 0o777, 0o600);

  const order: string[] = [];
  await Promise.all([
    withLock(auth, async () => {
      order.push("a-start");
      await new Promise((resolve) => setTimeout(resolve, 100));
      order.push("a-end");
    }),
    withLock(auth, async () => {
      order.push("b-start");
      order.push("b-end");
    }),
  ]);
  assert.equal(order.length, 4);
  assert.equal(order[1], order[0]!.replace("start", "end"));
  assert.equal(order[3], order[2]!.replace("start", "end"));
});

test("fetch presents on a challenge, replays once, and reports the site's answer as JSON", async () => {
  const { auth, dir } = await workspace(sandboxLogin());
  const { fetch, calls } = stubFetch(siteRoute(), proofRoute());

  const result = await cli(["fetch", SITE, "--json", "--auth", auth], {
    fetch,
  });

  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(result.json(), {
    status: 200,
    headers: { "content-type": "text/plain;charset=UTF-8" },
    body: "granted",
    body_encoding: "utf-8",
    presentation: { id: "ot1", notification: PENDING.notification },
  });
  assert.match(
    result.stderr,
    /x401-cli: approval_required email j\*\*\*@example.com expires=.* id=ot1/,
  );
  assert.match(result.stderr, /x401-cli: 200/);
  const site = calls.filter((call) => call.url === SITE);
  assert.equal(site.length, 2);
  assert.equal(site[0]!.redirect, "manual");
  assert.equal(site[1]!.redirect, "manual");
  const artifact = verifier.decodeResultArtifact(
    site[1]!.headers.get(HEADER.PROOF_RESPONSE)!,
  );
  assert.equal(artifact.credential_result_uri, READY.credential_result_uri);
  const proof = calls.find((call) => call.url.endsWith("/dc-api/requests"))!;
  assert.equal(proof.headers.get("authorization"), "Bearer tok");
  assert.equal(result.stdout.includes(artifact.credential_result_uri!), false);
  assert.deepEqual(await readdir(join(dir, "pending")), []);
});

test("fetch sends the method, headers and body, and never follows redirects", async () => {
  const { auth } = await workspace(sandboxLogin());
  const { fetch, calls } = stubFetch(siteRoute(), proofRoute());

  const result = await cli(
    [
      "fetch",
      SITE,
      "--auth",
      auth,
      "-X",
      "post",
      "-H",
      "X-Test: 1",
      "-d",
      "payload",
    ],
    { fetch },
  );

  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.stdout, "granted");
  for (const call of calls.filter((call) => call.url === SITE)) {
    assert.equal(call.method, "POST");
    assert.equal(call.headers.get("x-test"), "1");
    assert.equal(await call.text(), "payload");
    assert.equal(call.redirect, "manual");
  }
});

test("a response that is not a challenge is reported with exit 0", async () => {
  const { auth } = await workspace(sandboxLogin());
  const { fetch } = stubFetch(() => new Response("missing", { status: 404 }));

  const result = await cli(["fetch", SITE, "--json", "--auth", auth], {
    fetch,
  });

  assert.equal(result.code, 0);
  assert.equal(result.json().status, 404);
  assert.equal("presentation" in result.json(), false);
});

test("--no-wait stores the request and exits approval_pending; resume replays it", async () => {
  const { auth, dir } = await workspace(sandboxLogin());
  const { fetch } = stubFetch(siteRoute(), proofRoute());

  const pending = await cli(
    ["fetch", SITE, "--json", "--auth", auth, "--no-wait", "-d", "payload"],
    { fetch },
  );
  assert.equal(pending.code, 5);
  assert.deepEqual(pending.json(), {
    error: "approval_pending",
    error_description:
      "waiting for the user's approval; run `x401-cli resume ot1`",
    exit_code: 5,
    presentation_id: "ot1",
    approval_uri: PENDING.approval_uri,
    retry_after: 1,
  });
  assert.deepEqual(await readdir(join(dir, "pending")), ["ot1.json"]);

  const resumed = await cli(["resume", "ot1", "--json", "--auth", auth], {
    fetch,
  });
  assert.equal(resumed.code, 0, resumed.stderr);
  assert.equal(resumed.json().body, "granted");
  assert.deepEqual(await readdir(join(dir, "pending")), []);
});

test("a timeout while waiting exits approval_pending and keeps the presentation resumable", async () => {
  const { auth, dir } = await workspace(sandboxLogin());
  const { fetch } = stubFetch(
    siteRoute(),
    proofRoute([PENDING, PENDING, PENDING]),
  );

  const result = await cli(
    ["fetch", SITE, "--json", "--auth", auth, "--timeout", "1500ms"],
    { fetch },
  );

  assert.equal(result.code, 5);
  assert.equal(result.json().presentation_id, "ot1");
  assert.deepEqual(await readdir(join(dir, "pending")), ["ot1.json"]);
});

test("cancel deletes the presentation on Proof and locally", async () => {
  const { auth, dir } = await workspace(sandboxLogin());
  const { fetch, calls } = stubFetch(siteRoute(), proofRoute());
  await cli(["fetch", SITE, "--auth", auth, "--no-wait"], { fetch });

  const result = await cli(["cancel", "ot1", "--json", "--auth", auth], {
    fetch,
  });

  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(result.json(), { cancelled: "ot1" });
  assert.equal(
    calls.some((call) => call.method === "DELETE"),
    true,
  );
  assert.deepEqual(await readdir(join(dir, "pending")), []);
});

test("a PROOF-RESULT on the replay exits proof_rejected with the verifier's result", async () => {
  const { auth } = await workspace(sandboxLogin());
  const { fetch } = stubFetch(
    siteRoute(() => rejection("invalid_nonce")),
    proofRoute(),
  );

  const result = await cli(["fetch", SITE, "--json", "--auth", auth], {
    fetch,
  });

  assert.equal(result.code, 9);
  assert.equal(result.json().error, "proof_rejected");
  assert.equal(result.json().result.error, "invalid_nonce");
});

test("expired presentations exit expired", async () => {
  const { auth } = await workspace(sandboxLogin());
  const { fetch } = stubFetch(
    siteRoute(),
    proofRoute([{ id: "ot1", status: "expired" }]),
  );

  const result = await cli(["fetch", SITE, "--json", "--auth", auth], {
    fetch,
  });

  assert.equal(result.code, 7);
  assert.equal(result.json().error, "expired");
});

test("without a login the CLI exits unauthorized before calling Proof", async () => {
  const { auth } = await workspace();
  const { fetch, calls } = stubFetch(siteRoute(), proofRoute());

  const result = await cli(["fetch", SITE, "--json", "--auth", auth], {
    fetch,
  });

  assert.equal(result.code, 3);
  assert.equal(result.json().error, "unauthorized");
  assert.match(result.json().error_description, /x401-cli login --sandbox/);
  assert.equal(
    calls.some((call) => call.url.startsWith("https://api.fairfax")),
    false,
  );
});

test("a login for the other environment exits environment_mismatch", async () => {
  const { auth } = await workspace({
    production: { access_token: "tok", expires_at: NOW + 3600 },
  });
  const { fetch } = stubFetch(siteRoute(), proofRoute());

  const result = await cli(["fetch", SITE, "--json", "--auth", auth], {
    fetch,
  });

  assert.equal(result.code, 4);
  assert.match(result.json().error_description, /x401-cli login --sandbox/);
});

test("PROOF_ACCESS_TOKEN bypasses the credentials file", async () => {
  const { auth } = await workspace();
  const { fetch, calls } = stubFetch(siteRoute(), proofRoute());

  const result = await cli(["fetch", SITE, "--auth", auth], {
    fetch,
    env: { PROOF_ACCESS_TOKEN: "env-token" },
  });

  assert.equal(result.code, 0, result.stderr);
  const proof = calls.find((call) => call.url.endsWith("/dc-api/requests"))!;
  assert.equal(proof.headers.get("authorization"), "Bearer env-token");
});

test("an expired access token is refreshed under the lock and the new pair is stored before use", async () => {
  const { auth } = await workspace(sandboxLogin(NOW - 10));
  const { fetch, calls } = stubFetch(siteRoute(), proofRoute());

  const result = await cli(["fetch", SITE, "--auth", auth], { fetch });

  assert.equal(result.code, 0, result.stderr);
  const refresh = calls.find((call) => call.url.endsWith("/oauth/v2/token"))!;
  const form = new URLSearchParams(await refresh.text());
  assert.equal(form.get("grant_type"), "refresh_token");
  assert.equal(form.get("refresh_token"), "ref");
  assert.equal(form.get("client_id"), "cag5xwbbz");
  const proof = calls.find((call) => call.url.endsWith("/dc-api/requests"))!;
  assert.equal(proof.headers.get("authorization"), "Bearer fresh-access");
  const stored = await readJson(auth);
  assert.equal(stored.sandbox.access_token, "fresh-access");
  assert.equal(stored.sandbox.refresh_token, "fresh-refresh");
  assert.equal(stored.sandbox.expires_at, NOW + 7200);
});

test("token prints the stored access token, refreshing it when it has expired", async () => {
  const current = await workspace(sandboxLogin());
  const printed = await cli(["token", "--sandbox", "--auth", current.auth], {
    fetch: globalThis.fetch,
  });
  assert.equal(printed.code, 0, printed.stderr);
  assert.equal(printed.stdout, "tok\n");

  const stale = await workspace(sandboxLogin(NOW - 10));
  const { fetch } = stubFetch(proofRoute());
  const refreshed = await cli(
    ["token", "--sandbox", "--json", "--auth", stale.auth],
    { fetch },
  );
  assert.equal(refreshed.code, 0, refreshed.stderr);
  assert.deepEqual(refreshed.json(), { access_token: "fresh-access" });
  assert.equal(
    (await readJson(stale.auth)).sandbox.access_token,
    "fresh-access",
  );
});

test("token signs in first when there is no login", async () => {
  const { auth } = await workspace();
  const { fetch } = stubFetch(proofRoute());
  let opened = false;

  const result = await cli(["token", "--sandbox", "--auth", auth], {
    fetch,
    openBrowser: async (url) => {
      opened = true;
      const authorizeUrl = new URL(url);
      const redirect = new URL(authorizeUrl.searchParams.get("redirect_uri")!);
      redirect.searchParams.set("code", "the-code");
      redirect.searchParams.set(
        "state",
        authorizeUrl.searchParams.get("state")!,
      );
      await globalThis.fetch(redirect);
    },
  });

  assert.equal(result.code, 0, result.stderr);
  assert.equal(opened, true);
  assert.equal(result.stdout, "fresh-access\n");
  assert.equal((await readJson(auth)).sandbox.access_token, "fresh-access");
});

test("PROOF_ISSUER points every Proof call at another base URL", async () => {
  const local = "http://127.0.0.1:3000";
  const { auth } = await workspace(sandboxLogin(NOW + 3600, local));
  const { fetch, calls } = stubFetch(siteRoute(), (request, url) =>
    url.origin === local && request.method === "POST"
      ? Response.json(PENDING, { status: 201 })
      : url.origin === local
        ? Response.json(READY)
        : undefined,
  );

  const result = await cli(["fetch", SITE, "--sandbox", "--auth", auth], {
    fetch,
    env: { PROOF_ISSUER: local },
  });

  assert.equal(result.code, 0, result.stderr);
  assert.equal(
    calls.some((call) =>
      call.url.startsWith(`${local}/verifiable-credentials/`),
    ),
    true,
  );
  assert.equal(
    calls.some((call) => call.url.startsWith("https://api.fairfax")),
    false,
  );
});

test("a login from another issuer exits environment_mismatch without sending its tokens anywhere", async () => {
  const local = "http://127.0.0.1:3000";
  const { auth } = await workspace(sandboxLogin(NOW - 10, local));
  const { fetch, calls } = stubFetch(siteRoute(), proofRoute());

  const result = await cli(["fetch", SITE, "--json", "--auth", auth], {
    fetch,
  });

  assert.equal(result.code, 4);
  assert.match(
    result.json().error_description,
    /the sandbox login is for http:\/\/127\.0\.0\.1:3000, but this run uses https:\/\/api\.fairfax\.proof\.com/,
  );
  assert.equal(
    calls.some((call) => new URL(call.url).origin !== new URL(SITE).origin),
    false,
  );
});

test("an invalid URL is a usage error", async () => {
  const { auth } = await workspace(sandboxLogin());
  const result = await cli(["fetch", "not-a-url", "--json", "--auth", auth], {
    fetch: globalThis.fetch,
  });
  assert.equal(result.code, 1);
  assert.equal(result.json().error, "usage");
});

test("present refuses an undecodable PROOF-REQUEST before looking at the environment", async () => {
  const { auth } = await workspace(sandboxLogin());
  const result = await cli(
    ["present", "--proof-request", "garbage", "--json", "--auth", auth],
    { fetch: globalThis.fetch },
  );
  assert.equal(result.code, 10);
  assert.equal(result.json().error, "invalid_proof_request");
});

test("--json with -o writes the file and reports its path instead of the body", async () => {
  const { auth, dir } = await workspace(sandboxLogin());
  const { fetch } = stubFetch(
    () => new Response("binary\u0000", { status: 200 }),
  );
  const output = join(dir, "body.bin");

  const result = await cli(
    ["fetch", SITE, "--json", "--auth", auth, "-o", output],
    { fetch },
  );

  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.json().body_file, output);
  assert.equal("body" in result.json(), false);
  assert.equal((await readFile(output)).toString(), "binary\u0000");
});

test("resume with an unknown id names the local state directory", async () => {
  const { auth, dir } = await workspace(sandboxLogin());
  const result = await cli(["resume", "nope", "--json", "--auth", auth], {
    fetch: globalThis.fetch,
  });
  assert.equal(result.code, 1);
  assert.match(
    result.json().error_description,
    new RegExp(join(dir, "pending")),
  );
});

test("a 429 from Proof exits rate_limited with retry_after", async () => {
  const { auth } = await workspace(sandboxLogin());
  const { fetch } = stubFetch(siteRoute(), (request, url) =>
    url.origin === "https://api.fairfax.proof.com" && request.method === "POST"
      ? new Response(null, { status: 429, headers: { "Retry-After": "1800" } })
      : undefined,
  );

  const result = await cli(["fetch", SITE, "--json", "--auth", auth], {
    fetch,
  });

  assert.equal(result.code, 11);
  assert.equal(result.json().retry_after, 1800);
});

test("present prints the PROOF-RESPONSE for a challenge read from stdin", async () => {
  const { auth } = await workspace(sandboxLogin());
  const { fetch } = stubFetch(proofRoute());

  const result = await cli(
    ["present", "--proof-request", "-", "--json", "--auth", auth],
    {
      fetch,
      readStdin: async () => Buffer.from(`${proofRequestFor("sandbox")}\n`),
    },
  );

  assert.equal(result.code, 0, result.stderr);
  const artifact = verifier.decodeResultArtifact(result.json().proof_response);
  assert.equal(artifact.credential_result_uri, READY.credential_result_uri);
});

test("login signs in through the loopback redirect with PKCE and stores the tokens", async () => {
  const { auth } = await workspace();
  const { fetch, calls } = stubFetch(proofRoute());
  let authorizeUrl: URL | undefined;

  const result = await cli(["login", "--sandbox", "--json", "--auth", auth], {
    fetch,
    openBrowser: async (url) => {
      authorizeUrl = new URL(url);
      const redirect = new URL(authorizeUrl.searchParams.get("redirect_uri")!);
      redirect.searchParams.set("code", "the-code");
      redirect.searchParams.set(
        "state",
        authorizeUrl.searchParams.get("state")!,
      );
      await globalThis.fetch(redirect);
    },
  });

  assert.equal(result.code, 0, result.stderr);
  assert.equal(authorizeUrl!.origin, "https://api.fairfax.proof.com");
  assert.equal(authorizeUrl!.searchParams.get("client_id"), "cag5xwbbz");
  assert.equal(authorizeUrl!.searchParams.get("scope"), "agentic");
  assert.equal(authorizeUrl!.searchParams.get("code_challenge_method"), "S256");
  assert.match(
    authorizeUrl!.searchParams.get("redirect_uri")!,
    /^http:\/\/127\.0\.0\.1:\d+\/callback$/,
  );
  const exchange = calls.find((call) => call.url.endsWith("/oauth/v2/token"))!;
  const form = new URLSearchParams(await exchange.text());
  assert.equal(form.get("grant_type"), "authorization_code");
  assert.equal(form.get("code"), "the-code");
  assert.equal(form.has("code_verifier"), true);
  assert.equal(form.has("client_secret"), false);
  assert.deepEqual(await readJson(auth), {
    sandbox: {
      issuer: "https://api.fairfax.proof.com",
      access_token: "fresh-access",
      refresh_token: "fresh-refresh",
      expires_at: NOW + 7200,
      scope: "agentic",
    },
  });
  assert.equal(result.stdout.includes("fresh-access"), false);
  assert.equal(result.stderr.includes("fresh-access"), false);
});

test("login exits network with the TLS cause when Proof cannot be reached", async () => {
  const { auth } = await workspace();
  const cause = Object.assign(new Error("unable to verify"), {
    code: "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  });

  const result = await cli(
    ["login", "--sandbox", "--no-browser", "--auth", auth],
    {
      fetch: async () => {
        throw new TypeError("fetch failed", { cause });
      },
    },
  );

  assert.equal(result.code, 2);
  assert.match(
    result.stderr,
    /could not reach Proof to read its OAuth metadata \(UNABLE_TO_VERIFY_LEAF_SIGNATURE\)/,
  );
});

test("status reports the logins and exits unauthorized when there are none", async () => {
  const empty = await workspace();
  const none = await cli(["status", "--json", "--auth", empty.auth], {
    fetch: globalThis.fetch,
  });
  assert.equal(none.code, 3);
  assert.deepEqual(none.json().logins, []);
  assert.equal(none.json().error, "unauthorized");
  assert.equal(none.json().exit_code, 3);

  const nothing = await cli(["logout", "--json", "--auth", empty.auth], {
    fetch: globalThis.fetch,
  });
  assert.equal(nothing.code, 0);
  assert.deepEqual(nothing.json(), { logged_out: [] });

  const { auth } = await workspace(sandboxLogin());
  const some = await cli(["status", "--json", "--auth", auth], {
    fetch: globalThis.fetch,
  });
  assert.equal(some.code, 0);
  assert.deepEqual(some.json().logins, [
    {
      environment: "sandbox",
      issuer: "https://api.fairfax.proof.com",
      expires_at: NOW + 3600,
      refreshable: true,
    },
  ]);
  assert.equal(some.json().client_id, "cag5xwbbz");
});

test("logout revokes the refresh token and forgets the login", async () => {
  const { auth } = await workspace(sandboxLogin());
  const { fetch, calls } = stubFetch(proofRoute());

  const result = await cli(["logout", "--auth", auth], { fetch });

  assert.equal(result.code, 0, result.stderr);
  const revoke = calls.find((call) => call.url.endsWith("/oauth/v2/revoke"))!;
  const form = new URLSearchParams(await revoke.text());
  assert.equal(form.get("token"), "ref");
  assert.deepEqual(await readJson(auth), {});
});
