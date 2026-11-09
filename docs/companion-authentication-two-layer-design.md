# Companion authentication: two-layer design

Status: approved for implementation

## Goal

Remove the reusable browser-readable `companion_secret` from `localStorage` while preserving pairing convenience and origin scoping.

## Layer 1 — persistent browser key

The browser generates an ECDSA P-256 key pair with Web Crypto:

- private key: `extractable: false`, retained as a `CryptoKey` in IndexedDB;
- public key: exported as the SEC1 uncompressed point and sent only during pairing;
- IndexedDB database/store: implementation-owned, with one key per exact browser origin;
- no private key, shared secret, bearer token, or HMAC secret is written to `localStorage`, URL query parameters, logs, or application telemetry.

If IndexedDB or Web Crypto key persistence is unavailable, pairing remains available only for the current page lifetime. The browser must show that persistence is unavailable and must never fall back silently to plaintext storage.

## Layer 2 — short-lived pairing/bootstrap

1. Browser creates a non-guessable 32-byte pairing nonce and a non-exportable key pair.
2. Browser sends the nonce, public key, and exact serialized `Origin` to `/api/pair/initiate`.
3. Companion creates a 120-second, one-use transaction, binds it to the origin and public-key fingerprint, and displays the existing six-character comparison code.
4. The user confirms the matching code in the Companion UI and browser UI.
5. Browser sends the pairing ID and public-key fingerprint to `/api/pair/confirm`.
6. Companion stores the public key in OS credential storage under the exact origin. The response contains only `{ paired: true }`; it never returns a reusable secret.
7. The transaction is deleted after success, cancellation, or expiry.

Pairing initiation remains rate-limited and limited to one pending transaction. Origin values are normalized and compared exactly; an origin must not be accepted from a URL parameter when a valid `Origin` header is present.

## Request authentication

Every authenticated HTTP request is signed by the non-exportable private key. The browser creates a fresh 128-bit nonce and timestamp for each request. The canonical payload is:

```text
origin\ntimestamp\nnonce\nMETHOD\npath-and-canonical-query\nsha256(request-body-bytes)
```

Headers:

- `X-Companion-Key`: base64 public key;
- `X-Companion-Signature`: base64 ECDSA signature;
- `X-Companion-Timestamp`: Unix seconds;
- `X-Companion-Nonce`: base64 request nonce;
- `X-Companion-Body-SHA256`: base64 SHA-256 body digest.

The Companion verifies that the presented public key is the key registered for the exact origin, verifies the signature, rejects timestamps outside the existing narrow skew window, and rejects nonce reuse for the lifetime of the replay cache. The replay cache is bounded and expires entries with the timestamp window.

The server must buffer and restore request bodies in authentication middleware before verification so the digest covers the bytes actually delivered to the handler. JSON and multipart callers must use the exact serialized body passed to the HTTP client.

## WebSocket authentication

WebSocket credentials must not be placed in the URL. The upgrade request is unauthenticated except for the exact `Origin` check; immediately after upgrade the browser sends a signed `auth` message using the same canonical method/path/body-hash rules. The Companion does not process subscription messages until authentication succeeds or the short handshake timeout expires.

## Viewer URLs

The current query-parameter HMAC mechanism must not be carried forward. For `<img>`/`iframe` viewers that cannot set headers, add a short-lived, single-use Companion-issued viewer ticket obtained through an authenticated HTTP request. The ticket is scoped to origin, method, path, body hash, and expiry, and is invalidated on first redemption. It is not a persistent credential.

## Unpair and migration

- Unpair deletes the OS-stored public key and clears the browser IndexedDB key for the current origin.
- Existing HMAC pairings are not silently upgraded or accepted indefinitely.
- During a release transition, the Companion may accept the old HMAC protocol only behind an explicit compatibility flag and must report `browser_update_required` after the migration window. The browser must never copy the legacy secret into the new store.
- A normal re-pair replaces any existing key for that exact origin after user confirmation.

## Threat model boundary

This prevents theft of a reusable private credential from browser storage, URLs, logs, and ordinary storage inspection. It does **not** make a live same-origin XSS harmless: malicious code executing in the page can still ask Web Crypto to perform legitimate signatures while it is running. CSP, dependency pinning, output encoding, and XSS prevention remain required separate controls.

## Acceptance criteria

- CodeQL no longer reports clear-text sensitive storage for Companion authentication.
- Browser tests cover key generation, IndexedDB persistence, failed persistence with memory-only fallback, origin isolation, canonical signing, and no secret-bearing URLs.
- Rust tests cover public-key pairing, invalid-key rejection, signature verification, timestamp rejection, nonce replay rejection, origin isolation, one-use pairing transactions, and unpair revocation.
- WebSocket tests prove authentication occurs in the first signed message.
- Existing local-drive workflows, pairing UI, settings, and origin-specific behavior continue to work.
- Legacy `localStorage` values are ignored and removed only as part of explicit unpair or migration handling; they are never read as authentication material.
