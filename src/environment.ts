import type { Environment } from "@proof.com/proof-vc-common";
import {
  authorizationServerIssuer,
  resolveBaseUrl,
} from "@proof.com/proof-vc-common/internal";
import type { DcApiRequest } from "@proof.com/x401-agent";

export const ENVIRONMENTS: readonly Environment[] = ["production", "sandbox"];
export const CLIENT_ID = "cag5xwbbz";
export const SCOPE = "agentic";

export type Issuers = Partial<Record<Environment, string>>;

export function issuerOf(
  environment: Environment,
  issuers: Issuers = {},
): string {
  return issuers[environment] ?? resolveBaseUrl(environment);
}

function jwtAudience(jwt: string): string | undefined {
  const payload = jwt.split(".")[1];
  if (payload === undefined) {
    return undefined;
  }
  try {
    const claims: unknown = JSON.parse(
      Buffer.from(payload, "base64url").toString(),
    );
    return typeof claims === "object" &&
      claims !== null &&
      "aud" in claims &&
      typeof claims.aud === "string"
      ? claims.aud
      : undefined;
  } catch {
    return undefined;
  }
}

export function environmentOf(
  requirement: DcApiRequest,
): Environment | undefined {
  const { data } = requirement;
  const jwt =
    typeof data === "object" && data !== null && "request" in data
      ? data.request
      : undefined;
  if (typeof jwt !== "string") {
    return undefined;
  }
  const audience = jwtAudience(jwt);
  return ENVIRONMENTS.find(
    (environment) => authorizationServerIssuer(environment) === audience,
  );
}
