# JWE interoperability spike

This is a disposable interoperability prototype, not production EnvelopeKit code. It uses the maintained `jose-jwt` .NET implementation and `jose` JavaScript implementation to check the same JWE/JWS profile in both directions.

The spike generates temporary P-256 keys, then checks:

1. A browser-compatible JavaScript client encrypts a JSON request using JWE `ECDH-ES` and `A256GCM`.
2. .NET decrypts the request, signs a JSON response using JWS `ES256`, and encrypts the signed response to a one-use client public key using JWE.
3. The JavaScript client decrypts the response and verifies the API signature.
4. A modified JWE authentication tag is rejected.

The spike first runs the browser-compatible Web API implementation under Node.js, then runs the same exchange in headless Chromium. This checks an actual browser engine, but does not yet cover other browser engines or mobile platforms.

## Run

Requirements: .NET 10 SDK and Node.js 24 and a Chromium browser installed by Playwright.

```sh
cd prototypes/jwe-interop/browser
npm ci
npx playwright install chromium --only-shell
npm run interop
```

All private keys and messages are generated in a temporary directory and removed at the end of the run. Do not use this prototype to protect real data.

## Current limits

This checks compact JWE and compact JWS only. It does not validate the signed key manifest, middleware, replay store, HTTP metadata binding, key rotation, or production error handling. Its JWE algorithms are a candidate profile, not a frozen EnvelopeKit protocol.
