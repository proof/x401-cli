# x401-cli

Node CLI, bin `x401-cli`: calls x401 endpoints with the user's Proof credential. It signs the user
in to Proof and stores the tokens; everything x401 comes from `@proof.com/x401-agent`.

## Rules

1. **No x401 logic here.** The CLI maps x401-agent calls to commands, files and exit codes.
2. **OAuth through `oauth4webapi` only.** Authorization code with PKCE S256 and a loopback redirect;
   public client `cag5xwbbz`, no secret.
3. **Output is a contract.** stdout carries only the endpoint's body, one JSON object (`--json`),
   the token (`token`) or the `PROOF-RESPONSE` (`present`). stderr carries one `x401-cli: <code>`
   line per event. Exit codes live in `src/output.ts`. Never print a token anywhere else.
4. **Refresh under the credentials-file lock**, and store the new pair before using it: Proof
   revokes the grant when a rotated refresh token is reused.
5. **Never follow redirects.**
6. Run `yarn check-all` before any commit or push. No `eslint-disable`, `@ts-ignore`,
   `@ts-expect-error`, or code comments. Never bump, tag or publish without explicit confirmation.

## Conventions

- `import type` / `export type` (`verbatimModuleSyntax`); optional fields by conditional spread
  (`exactOptionalPropertyTypes`); local imports end in `.ts`.
- Arguments with `node:util` `parseArgs`; no CLI framework.
