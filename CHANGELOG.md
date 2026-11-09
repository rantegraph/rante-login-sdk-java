# Changelog

## 1.0.0 (2026-11-09)

First release.

- **`RanteLoginClient`:** `createAuthorizationRequest`, `handleCallback`, `exchangeCode`, `validateIdToken`,
  `fetchUserInfo` and `fromBrowserSdkCookies`. Built on the Nimbus OAuth 2.0 / OpenID Connect SDK 11.38; Java 17 or
  later.
- **Client authentication:** `private_key_jwt` (RS256 or ES256) for server-side websites, and PKCE alone for
  browser-only websites.
- **Example:** `examples/httpserver`.
