# x401-cli

x401-cli lets you and your coding agent call endpoints that require proof of identity from a
terminal.

When an endpoint answers with an [x401](https://x401.proof.com/spec/latest/) proof request, the user
presents their credential from their Proof Cloud Wallet, and the CLI retries the request with the
presented credential and prints the endpoint's answer.

In code, use [x401-agent](https://github.com/proof/x401-agent) instead.

- [Installation](#installation)
- [Quickstart](#quickstart)
- [Usage](#usage)
  - [Pick up a pending request](#pick-up-a-pending-request)
  - [Cancel a request](#cancel-a-request)
  - [Get the access token](#get-the-access-token)
- [Use with agents](#use-with-agents)
- [Commands](#commands)
- [Options](#options)
- [Environment variables](#environment-variables)
- [Exit codes](#exit-codes)
- [Links](#links)
- [License](#license)

## Installation

```sh
npm install -g @proof.com/x401-cli
```

## Quickstart

Sign in to Proof's sandbox and request the sandbox test endpoint:

```sh
x401-cli login --sandbox
x401-cli fetch "https://try.proof.com/x401/protected?env=fairfax"
```

Proof emails the user an approval link. The CLI waits for the approval and prints the endpoint's
answer:

```
x401-cli: approval_required email j******@proof.com expires=2026-10-27T11:42:09Z id=ot7gzqj4p
x401-cli: 200 (238 B)
{"ok":true,"kind":"protected","credentials":{"proof_id_default":[{"credentialType":"ProofCredentialV1","format":"dc+sd-jwt","nonce":"afc8ffc9-e6cc-4a1d-9cd7-0c0635f264df","givenName":"Alexander J","familyName":"Sample","isOver18":true}]}}
```

## Usage

### Pick up a pending request

`--no-wait` exits with code 5 while the request waits for the user's approval, and `--timeout` does
the same when the wait runs out. `resume` takes the request id that `fetch` printed, waits for the
approval and replays the request.

```sh
x401-cli fetch --no-wait "https://try.proof.com/x401/protected?env=fairfax"
x401-cli resume ot7gzqj4p
```

### Cancel a request

```sh
x401-cli cancel ot7gzqj4p
```

### Get the access token

`token` prints the access token.

```sh
export PROOF_ACCESS_TOKEN=$(x401-cli token --sandbox)
```

## Use with agents

- Pass `--json` and read `exit_code`.
- Pass a `--timeout` shorter than your tool's time limit, for example `--timeout 9m`.
- On exit code 5, ask the user to present their credential from their Proof Cloud Wallet, and run
  `x401-cli resume <presentation_id> --json`.
- Run `resume` for a pending request rather than `fetch` again: each `fetch` sends the user a new
  request.

## Commands

| Command       | Description                                                                                        |
| ------------- | -------------------------------------------------------------------------------------------------- |
| `login`       | Signs the user in to Proof in the browser and stores the tokens                                    |
| `logout`      | Revokes and removes the stored tokens                                                              |
| `status`      | Shows the stored logins                                                                            |
| `token`       | Prints the access token; signs in first when there is no login                                     |
| `fetch <url>` | Requests the URL and presents the user's credential when the endpoint asks for one                 |
| `resume <id>` | Waits for a pending approval and replays the request, or prints the `PROOF-RESPONSE` for `present` |
| `cancel <id>` | Cancels a pending request                                                                          |
| `present`     | Turns a `PROOF-REQUEST` into a `PROOF-RESPONSE`                                                    |

## Options

| Option                | Commands                                                 | Description                                                                                                 |
| --------------------- | -------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `--sandbox`           | `login`, `logout`, `status`, `token`, `fetch`, `present` | Uses Proof's sandbox                                                                                        |
| `--json`              | all                                                      | Prints one JSON object on stdout: the response's `status`, `headers` and `body`, or `error` and `exit_code` |
| `--timeout <d>`       | `login`, `token`, `fetch`, `resume`, `present`           | How long to wait for the sign-in or the approval, e.g. `9m` (default 15m)                                   |
| `--no-wait`           | `fetch`, `present`                                       | Exits with code 5 while the approval is pending                                                             |
| `--no-browser`        | `login`, `token`                                         | Prints the sign-in URL instead of opening the browser                                                       |
| `-X`, `-H`, `-d`      | `fetch`                                                  | Method, header, body, as in curl; `-d @file` and `-d @-` read the body from a file or stdin                 |
| `-o <file>`           | `fetch`                                                  | Writes the body to a file                                                                                   |
| `--proof-request <v>` | `present`                                                | The `PROOF-REQUEST` value, `-` for stdin, `@file`                                                           |

## Environment variables

| Name                 | Required | Default | Description                                  |
| -------------------- | -------- | ------- | -------------------------------------------- |
| `PROOF_ACCESS_TOKEN` | no       | none    | Used instead of the stored login, no refresh |

## Exit codes

| Code | Name                    | Meaning                                                                             |
| ---- | ----------------------- | ----------------------------------------------------------------------------------- |
| 0    |                         | Success. For `fetch`, the endpoint answered with any HTTP status                    |
| 1    | `usage`                 | Invalid command or option                                                           |
| 2    | `network`               | The endpoint or Proof could not be reached                                          |
| 3    | `unauthorized`          | No login, or Proof refused the token; run `login`                                   |
| 4    | `environment_mismatch`  | The request is for a Proof environment you are not signed in to; run `login` for it |
| 5    | `approval_pending`      | The user has not approved yet; run `resume`                                         |
| 7    | `expired`               | The request expired before the user approved                                        |
| 8    | `cancelled`             | The request was cancelled                                                           |
| 9    | `proof_rejected`        | The endpoint rejected the presented credential                                      |
| 10   | `invalid_proof_request` | The endpoint's `PROOF-REQUEST` is not valid                                         |
| 11   | `rate_limited`          | Too many requests; `retry_after` is in seconds                                      |
| 12   | `presentation_failed`   | Proof answered with an error status or an unexpected body                           |

## Links

- [Read the x401 specification](https://x401.proof.com/spec/latest/)
- [Answer proof requests in code with x401-agent](https://github.com/proof/x401-agent)
- [Use x401 for your Cloudflare Worker endpoints](https://github.com/proof/x401-workers)

## License

[Apache-2.0](LICENSE)
