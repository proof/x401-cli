import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import * as oauth from "oauth4webapi";
import type { Tokens } from "./credentials.ts";
import { CLIENT_ID, SCOPE } from "./environment.ts";
import { CliError, event, type Io } from "./output.ts";

export type OAuthDeps = {
  issuer: string;
  fetch: typeof globalThis.fetch;
  now: () => number;
};

const CLIENT: oauth.Client = { client_id: CLIENT_ID };

const CALLBACK_PAGE =
  "<!doctype html><title>x401-cli</title><p>Signed in. You can close this window.</p>";

function requestOptions(deps: OAuthDeps) {
  return {
    [oauth.customFetch]: (url: string, options: object) =>
      deps.fetch(url, options as RequestInit),
    ...(deps.issuer.startsWith("http:") && {
      [oauth.allowInsecureRequests]: true,
    }),
  };
}

async function reach(
  action: string,
  request: () => Promise<Response>,
): Promise<Response> {
  try {
    return await request();
  } catch (error) {
    const cause = error instanceof Error ? error.cause : undefined;
    const code =
      cause instanceof Error && "code" in cause
        ? ` (${String(cause.code)})`
        : "";
    throw new CliError("network", `could not reach Proof to ${action}${code}`);
  }
}

async function server(deps: OAuthDeps): Promise<oauth.AuthorizationServer> {
  const issuer = new URL(deps.issuer);
  const response = await reach("read its OAuth metadata", () =>
    oauth.discoveryRequest(issuer, {
      ...requestOptions(deps),
      algorithm: "oauth2",
    }),
  );
  return oauth.processDiscoveryResponse(issuer, response);
}

function tokens(
  deps: OAuthDeps,
  response: oauth.TokenEndpointResponse,
): Tokens {
  return {
    issuer: deps.issuer,
    access_token: response.access_token,
    ...(response.refresh_token !== undefined && {
      refresh_token: response.refresh_token,
    }),
    ...(response.expires_in !== undefined && {
      expires_at: deps.now() + response.expires_in,
    }),
    ...(response.scope !== undefined && { scope: response.scope }),
  };
}

function listen(): Promise<{
  redirectUri: string;
  callback: Promise<URL>;
  close: () => void;
}> {
  return new Promise((resolveListening, rejectListening) => {
    let resolveCallback: (url: URL) => void = () => undefined;
    const callback = new Promise<URL>((resolve) => {
      resolveCallback = resolve;
    });
    const httpServer = createServer((request, response) => {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      if (url.pathname !== "/callback") {
        response.writeHead(404).end();
        return;
      }
      response
        .writeHead(200, { "Content-Type": "text/html" })
        .end(CALLBACK_PAGE);
      resolveCallback(url);
    });
    httpServer.once("error", rejectListening);
    httpServer.listen(0, "127.0.0.1", () => {
      const { port } = httpServer.address() as AddressInfo;
      resolveListening({
        redirectUri: `http://127.0.0.1:${port}/callback`,
        callback,
        close: () => httpServer.close(),
      });
    });
  });
}

export type SignInOptions = {
  io: Io;
  openBrowser: (url: string) => Promise<void>;
  noBrowser: boolean;
  timeoutMs: number;
};

const openedBrowser = async (
  options: SignInOptions,
  url: string,
): Promise<boolean> =>
  !options.noBrowser &&
  (await options.openBrowser(url).then(
    () => true,
    () => false,
  ));

async function showSignIn(
  options: SignInOptions,
  url: string,
  messages: { opened: string; manual: string },
): Promise<void> {
  const opened = await openedBrowser(options, url);
  event(options.io, "login", opened ? messages.opened : messages.manual);
}

export async function login(
  deps: OAuthDeps,
  options: SignInOptions,
): Promise<Tokens> {
  const as = await server(deps);
  const codeVerifier = oauth.generateRandomCodeVerifier();
  const state = oauth.generateRandomState();
  const { redirectUri, callback, close } = await listen();
  try {
    const url = new URL(as.authorization_endpoint!);
    url.searchParams.set("client_id", CLIENT_ID);
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", SCOPE);
    url.searchParams.set(
      "code_challenge",
      await oauth.calculatePKCECodeChallenge(codeVerifier),
    );
    url.searchParams.set("code_challenge_method", "S256");
    url.searchParams.set("state", state);
    await showSignIn(options, url.href, {
      opened: "opened your browser to sign in to Proof",
      manual: `open this URL to sign in: ${url.href}`,
    });
    const timeout = new Promise<never>((_resolve, reject) => {
      setTimeout(
        () =>
          reject(
            new CliError("unauthorized", "sign-in did not complete in time"),
          ),
        options.timeoutMs,
      ).unref();
    });
    const callbackUrl = await Promise.race([callback, timeout]);
    const parameters = oauth.validateAuthResponse(
      as,
      CLIENT,
      callbackUrl,
      state,
    );
    const response = await reach("exchange the sign-in code", () =>
      oauth.authorizationCodeGrantRequest(
        as,
        CLIENT,
        oauth.None(),
        parameters,
        redirectUri,
        codeVerifier,
        requestOptions(deps),
      ),
    );
    return tokens(
      deps,
      await oauth.processAuthorizationCodeResponse(as, CLIENT, response),
    );
  } finally {
    close();
  }
}

const DEFAULT_INTERVAL_SECONDS = 5;
const SLOW_DOWN_SECONDS = 5;

const oauthErrorOf = (error: unknown): string | undefined =>
  error instanceof oauth.ResponseBodyError ? error.error : undefined;

function deviceRefusal(error: unknown): CliError {
  const code = oauthErrorOf(error);
  const reason =
    code !== undefined
      ? ` (${code})`
      : error instanceof Error
        ? `: ${error.message}`
        : "";
  return new CliError(
    "unauthorized",
    `Proof refused the device sign-in${reason}`,
  );
}

export async function deviceLogin(
  deps: OAuthDeps,
  options: SignInOptions & { sleep: (ms: number) => Promise<void> },
): Promise<Tokens> {
  const as = await server(deps);
  if (as.device_authorization_endpoint === undefined) {
    throw new CliError(
      "usage",
      `${deps.issuer} does not offer device sign-in; run login without --device`,
    );
  }
  const started = await reach("start the device sign-in", () =>
    oauth.deviceAuthorizationRequest(
      as,
      CLIENT,
      oauth.None(),
      { scope: SCOPE },
      requestOptions(deps),
    ),
  );
  let device: oauth.DeviceAuthorizationResponse;
  try {
    device = await oauth.processDeviceAuthorizationResponse(
      as,
      CLIENT,
      started,
    );
  } catch (error) {
    throw deviceRefusal(error);
  }
  const opened = await openedBrowser(
    options,
    device.verification_uri_complete ?? device.verification_uri,
  );
  options.io.stderr.write(
    [
      ...(opened
        ? [
            "Opening Proof in your browser to sign in.",
            "If nothing opened, or to sign in from another device, go to:",
          ]
        : ["To sign in, go to:"]),
      "",
      device.verification_uri,
      "",
      "and enter this code:",
      "",
      device.user_code,
      "",
      "",
    ].join("\n"),
  );
  const limitMs = Math.min(options.timeoutMs, device.expires_in * 1000);
  let intervalMs = (device.interval ?? DEFAULT_INTERVAL_SECONDS) * 1000;
  let waitedMs = 0;
  for (;;) {
    if (waitedMs + intervalMs > limitMs) {
      throw new CliError("unauthorized", "sign-in did not complete in time");
    }
    await options.sleep(intervalMs);
    waitedMs += intervalMs;
    const response = await reach("check the device sign-in", () =>
      oauth.deviceCodeGrantRequest(
        as,
        CLIENT,
        oauth.None(),
        device.device_code,
        requestOptions(deps),
      ),
    );
    try {
      return tokens(
        deps,
        await oauth.processDeviceCodeResponse(as, CLIENT, response),
      );
    } catch (error) {
      switch (oauthErrorOf(error)) {
        case "authorization_pending":
          break;
        case "slow_down":
          intervalMs += SLOW_DOWN_SECONDS * 1000;
          break;
        case "access_denied":
          throw new CliError("cancelled", "the sign-in was denied");
        case "expired_token":
          throw new CliError(
            "expired",
            "the sign-in code expired; run login again",
          );
        default:
          throw deviceRefusal(error);
      }
    }
  }
}

export async function refresh(
  deps: OAuthDeps,
  current: Tokens,
): Promise<Tokens> {
  const refreshToken = current.refresh_token;
  if (refreshToken === undefined) {
    throw new CliError(
      "unauthorized",
      "the access token expired and cannot be refreshed",
    );
  }
  const as = await server(deps);
  const response = await reach("refresh the token", () =>
    oauth.refreshTokenGrantRequest(
      as,
      CLIENT,
      oauth.None(),
      refreshToken,
      requestOptions(deps),
    ),
  );
  try {
    return tokens(
      deps,
      await oauth.processRefreshTokenResponse(as, CLIENT, response),
    );
  } catch {
    throw new CliError(
      "unauthorized",
      "Proof refused the refresh token; sign in again",
    );
  }
}

export async function revoke(deps: OAuthDeps, current: Tokens): Promise<void> {
  const as = await server(deps);
  if (as.revocation_endpoint === undefined) {
    return;
  }
  const response = await reach("revoke the token", () =>
    oauth.revocationRequest(
      as,
      CLIENT,
      oauth.None(),
      current.refresh_token ?? current.access_token,
      {
        ...requestOptions(deps),
        ...(current.refresh_token !== undefined && {
          additionalParameters: { token_type_hint: "refresh_token" },
        }),
      },
    ),
  );
  await oauth.processRevocationResponse(response);
}
