# anyoauth-sdk

AnyOAuth confidential-backend SDK 0.1.0. Generated from the OpenAPI contract.
Public endpoint methods accept a parameter object/map using the names below and return
JSON values validated by the generated descriptors in contract.json. Additional response
fields are accepted; required fields, types, nullability, constants and enums are checked.

Build and run from this repository root (runner reads one JSON object from stdin):

```json
[
  [
    "cargo",
    "build",
    "--locked",
    "--bin",
    "conformance"
  ],
  [
    "target/debug/conformance"
  ]
]
```

Input: {"action":"pkceChallenge","params":{"codeVerifier":"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}}
Output: {"ok":true,"result":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}

Other actions: exchangeCode, profile, revoke, providers, createTransaction,
authorizationUrl, validateCallback. Configuration: baseUrl (defaults to
https://api.anyoauth.com), clientId, clientSecret. Exchange parameters: code,
codeVerifier, redirectUri. Bearer operations: accessToken. Authorization:
provider, redirectUri, state, codeChallenge. Callback validation: callbackUrl,
redirectUri, state, expiresAt (Unix seconds).

Persist the transaction in the initiating browser's server session, bind the exact
registered callback, and atomically consume it even on denial. Exchange once;
identify users by subject and create your own application session. Null profile
fields remain null. Helpers do not provide storage or account linking.

Origins must be HTTPS or HTTP loopback with no path (except /), query, fragment,
or credentials. Registered callbacks must be HTTPS or HTTP loopback without
query, fragment, or credentials. Callback base strings must match exactly.
The HTTP timeout is 10 seconds, redirects are rejected, and requests are never
automatically retried. Errors expose status, code and message, without request
details. Local validation errors have status 0 and code invalid_argument;
network failures use transport_error and malformed responses protocol_error.
Never log codes, secrets, verifiers or tokens. These packages are not published.

After building, run the local mock-HTTP and helper checks with
`node test/conformance/check.mjs`. This needs Node.js only for the test harness;
the SDK and stdin runner use their native language runtime. Tests never use a live API.

License: MIT.

## Source and releases

Repository: https://github.com/AnyOAuth/anyoauth-rust

GitHub prerelease: https://github.com/AnyOAuth/anyoauth-rust/releases/tag/v0.1.0

Clone this repository, then run `node verify.mjs` with the native toolchain installed to build and execute the package's conformance suite. Source is generated in the AnyOAuth monorepo; propose changes there so every language stays aligned. GitHub hosts source archives and checksums. Package registry publication is separate.

This initial source release has full advertised-method conformance coverage. Runtime line/branch coverage for the whole language matrix remains a separate release gate; see https://anyoauth.com/docs/libraries/.
