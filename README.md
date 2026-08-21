# B2B Enterprise Federation & Provisioning Gateway

An API gateway for B2B SaaS: it sits in front of multi-tenant backend
microservices and handles corporate SSO (SAML 2.0, OIDC) and automated
directory sync (SCIM 2.0) from enterprise identity providers (Okta, Entra
ID, Ping Identity), then enforces attribute-based access control on every
request it proxies through.

Go stdlib only for the security-critical pieces — no SAML/XML-DSig/JWT
libraries. `crypto/x509`, `crypto/rsa`, `encoding/xml` do the work.

## Architecture

| Package | Responsibility |
|---|---|
| [`internal/store`](internal/store) | SQLite-backed persistence: users, groups, sessions, SAML/OIDC request tracking |
| [`internal/scim`](internal/scim) | SCIM 2.0 server: `/v2/Users`, `/v2/Groups`, filter grammar, PATCH ops |
| [`internal/saml`](internal/saml) | SAML 2.0 SP: metadata parsing, signed `AuthnRequest`, raw XML-DSig verification |
| [`internal/oidc`](internal/oidc) | OIDC RP: discovery, PKCE auth-code flow, manual RS256 ID token verification |
| [`internal/abac`](internal/abac) | ABAC policy engine: JSON policies, deterministic evaluator |
| [`internal/authz`](internal/authz) | Middleware bridging a session to an ABAC decision in front of the proxy |
| [`internal/proxy`](internal/proxy) | Multi-tenant reverse proxy to backend services |
| [`cmd/gateway`](cmd/gateway) | Wires it all together into one HTTP server |
| [`cmd/fakeidp`](cmd/fakeidp) | Dev-only simulated SAML IdP (mints signed responses) |
| [`cmd/mockoidc`](cmd/mockoidc) | Dev-only simulated OpenID Provider |
| [`cmd/mockbackend`](cmd/mockbackend) | Dev-only tenant "microservice" that echoes injected headers |

A request's life cycle: a user's browser is sent through `/saml/{tenant}/login`
or `/oidc/{tenant}/login`; the resulting SAMLResponse/ID token is verified and
turned into a `store.Session` carrying directory attributes (Department,
Groups, ...) mapped from the assertion/claims; subsequent calls to `/api/...`
carry that session's cookie, `internal/authz` evaluates the tenant's ABAC
policies against `{user, request, time}`, and — only on Allow — the request is
proxied to the tenant's backend with `X-B2BFP-*` identity headers injected.

## Quick start

```bash
go build -o bin/gateway.exe ./cmd/gateway
go build -o bin/fakeidp.exe ./cmd/fakeidp
go build -o bin/mockoidc.exe ./cmd/mockoidc
go build -o bin/mockbackend.exe ./cmd/mockbackend

./bin/fakeidp.exe init   # writes policies/fakeidp-metadata.xml + data/fakeidp.key.pem

./bin/mockbackend.exe &                                    # :9090, the "tenant backend"
./bin/mockoidc.exe -subject bob@acme-corp.example -department Engineering &  # :9091
./bin/gateway.exe -config config.json &                    # :8443
```

`config.json` ships with one demo tenant (`acme`) wired to all of the above.
Run `go test ./...` any time — the crypto-heavy packages (`saml`, `oidc`,
`abac`) carry real unit tests, including an attempted XML Signature Wrapping
attack that must be rejected (`internal/saml/signature_test.go`).

## Trying it end-to-end

### SCIM (simulating Okta/Entra/Ping provisioning)

```bash
TOKEN=dev-scim-token-change-me
BASE=http://localhost:8443/scim/acme/v2

curl -X POST "$BASE/Users" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/scim+json" -d '{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "alice@acme-corp.example",
  "name": {"givenName": "Alice", "familyName": "Doe"},
  "emails": [{"value": "alice@acme-corp.example", "primary": true}],
  "active": true,
  "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"department": "Engineering"}
}'

curl -G "$BASE/Users" -H "Authorization: Bearer $TOKEN" --data-urlencode 'filter=department eq "Engineering"'

# Okta-style deprovisioning: PATCH active=false
curl -X PATCH "$BASE/Users/<id>" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/scim+json" -d '{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [{"op": "replace", "value": {"active": false}}]
}'
```

### SAML (simulating a corporate IdP)

```bash
# 1. Trigger login — gateway redirects to the IdP with a signed AuthnRequest
curl -D - -o /dev/null "http://localhost:8443/saml/acme/login?returnTo=/api/reports/dashboard"
# capture the AuthnRequest's ID (decode SAMLRequest, or just read gateway logs)

# 2. Mint a matching signed SAMLResponse from the fake IdP
./bin/fakeidp.exe mint-response \
  -sp-entity-id http://localhost:8443/saml/acme/metadata \
  -acs-url http://localhost:8443/saml/acme/acs \
  -in-response-to '<AuthnRequest ID from step 1>' \
  -name-id alice@acme-corp.example -department Engineering \
  -out /tmp/post.html

# 3. POST it to the ACS endpoint (open /tmp/post.html in a browser, or curl it)
```

A real deployment points `saml_idp_metadata_file` at the customer's actual
IdP metadata XML instead of `fakeidp`'s output — nothing else changes.

### OIDC (simulating an OpenID Provider)

Just visit `http://localhost:8443/oidc/acme/login?returnTo=/api/reports/x` in
a browser — `mockoidc` skips its login UI and immediately redirects back
authenticated as whatever `-subject`/`-department` it was started with.

### Everything converges on the same ABAC gate

Both flows end in a `b2bfp_session` cookie. Use it against `/api/...`:

```bash
curl -b "b2bfp_session=<cookie>" http://127.0.0.1:8443/api/reports/dashboard
```

`internal/authz` resolves the session, maps the request path to an ABAC
resource via `resource_routes` in `config.json`, evaluates `policies/policies.json`,
and either 403s or forwards to `mockbackend`, which echoes back exactly the
`X-B2BFP-*` headers it received — the same headers a real backend would use
for tenant isolation and row-level authorization.

## ABAC policy format

```json
{
  "id": "allow-prod-db-engineering-vpc-hours",
  "effect": "Allow",
  "resource": "Production_DB",
  "condition": {
    "all": [
      { "attr": "user.Department", "op": "eq", "value": "Engineering" },
      { "attr": "request.Source_IP", "op": "matches", "value": "Vpc_Range" },
      { "attr": "time.Now", "op": "is", "value": "Business_Hours" }
    ]
  }
}
```

This is the literal example from the spec:
*"Allow access to resource 'Production_DB' IF user.Department == 'Engineering'
AND request.Source_IP matches Vpc_Range AND time.Now() is Business_Hours"*.
`Vpc_Range` and `Business_Hours` are resolved from `policies/environment.json`
(named CIDR ranges + a weekly recurring window in a fixed IANA timezone), so
policies stay declarative instead of embedding literals.

Evaluation (`internal/abac/evaluator.go`) is standard ABAC combining logic:
**explicit Deny beats explicit Allow**, and **no matching policy is a Deny**
(fail closed) — never an accidental Allow. Supported `op`s: `eq`/`ne`, `gt`/
`ge`/`lt`/`le`, `co`(ntains)/`in`, `matches` (CIDR, literal or named), `is`
(currently `Business_Hours`), `pr`/`exists`, `regex`. Conditions nest via
`all`/`any`/`not`. See `internal/abac/evaluator_test.go` for the full
behavior spec, including the weekday/weekend and in/out-of-hours boundary
cases.

## Configuration

- `config.json` — listen address, DB path, policy/environment file paths,
  per-tenant SCIM tokens / IdP metadata / OIDC issuer / backend URL, and
  `resource_routes` (API path prefix → ABAC resource name; unmatched paths
  are denied by default).
- `policies/policies.json` — the `PolicySet`.
- `policies/environment.json` — named CIDR ranges + business-hours schedule.
  **The shipped demo file sets `Vpc_Range` to `127.0.0.0/8` (loopback) so the
  walkthrough above works over `curl` from localhost — point it at your real
  VPC CIDRs before deploying.**

## Security notes (read before production use)

This codebase went through one internal review pass (see `git log`); every
finding from that pass was fixed and is now covered by a regression test.
That is not a substitute for an independent, external security review —
especially of `internal/saml` — before handling real production SSO
traffic.

**Fixed in the review pass**, each with a test proving it:
- The reverse proxy now strips the entire `X-B2BFP-*` header namespace from
  the client's original request before setting the gateway's own values
  (`internal/authz/middleware.go`) — previously it only overwrote the
  specific headers it knew about, so a client could smuggle e.g.
  `X-B2BFP-Groups` straight through to the backend
  (`TestEnforce_StripsClientSuppliedIdentityHeaders`).
- XML canonicalization and the SCIM filter parser both now enforce a
  recursion-depth limit (`internal/saml/canon.go`'s `maxCanonDepth`,
  `internal/scim/filter.go`'s `maxFilterDepth`). Both process
  attacker-reachable input via direct Go function recursion — the ACS
  endpoint canonicalizes a POSTed SAMLResponse *before* its signature is
  known to be valid — and Go's stack-overflow fatal error is not something
  `recover()` can catch, so unbounded depth was a full-process-crash DoS
  (`TestVerify_RejectsDeeplyNestedXMLWithoutStackOverflow`,
  `TestParseFilter_RejectsDeepNesting`).
- SAML response validation now requires (rather than optionally checks)
  `SubjectConfirmationData/@Recipient` and `Response/@Destination` to match
  this tenant's actual ACS URL, and requires `<Conditions>` with a matching
  `<AudienceRestriction>` to be present — an assertion that omitted them
  used to be accepted as unscoped/unbounded rather than rejected
  (`internal/saml/response.go`, `TestVerify_RejectsWrongRecipient` /
  `_RejectsWrongDestination` / `_RejectsMissingConditions` /
  `_RejectsMissingAudienceRestriction`).
- IdP-initiated SAML responses (no `InResponseTo`, so the SP-initiated
  flow's request-consumption replay defense never sees them) are now
  tracked by assertion ID in `used_saml_assertions` and rejected on reuse
  (`internal/store/sessions.go`'s `MarkAssertionUsed`,
  `TestMarkAssertionUsed_RejectsReplay`).
- SCIM request bodies are now capped at 5 MiB via `http.MaxBytesReader`
  (`internal/scim/server.go`) — previously `json.Decoder` read an
  unbounded body into memory.
- XML-DSig verification no longer accepts SHA-1 `DigestMethod`/
  `SignatureMethod` algorithms by default (`internal/saml/xmldsig.go`); add
  them back deliberately if a legacy IdP genuinely requires SHA-1.
- The session cookie's `Secure` flag now tracks `public_base_url`'s scheme
  instead of being hardcoded `true`, which used to silently break session
  persistence in real browsers (not `curl`, which ignores `Secure`)
  whenever `public_base_url` was `http://`, as the shipped demo config is.

**Still true, by design:**
- The hand-rolled XML-DSig verifier remains the highest-risk piece of this
  codebase. It implements a deliberately narrow subset of Exclusive XML
  Canonicalization — enough for the straightforward, single-assertion
  documents Okta/Entra/Ping actually emit — not the full spec (no
  `InclusiveNamespaces PrefixList`, no comment-preserving c14n). Its
  anti-XSW defenses (single-Assertion documents only, Reference URI must
  match the signed element's own ID, trust anchored in the tenant's
  pre-registered IdP certificate rather than any cert embedded in the
  response) are unit-tested, but XML-DSig has a long history of subtle
  real-world bugs — get an independent review and interop-test against
  your actual IdPs before trusting this in production.
- `internal/authz` only trusts `X-Forwarded-For` when `trust_forwarded_for`
  is explicitly enabled in config — enable it only when the gateway sits
  behind a proxy that itself sets/overwrites that header, never when clients
  can reach the gateway directly (otherwise any client can spoof its way
  into a VPC-range ABAC policy).
- OIDC ID token verification rejects anything but `RS256` outright — the
  classic `alg:none` / algorithm-confusion class of JWT bugs — and always
  verifies against the issuer's live JWKS, never a key embedded in the
  token.
- SCIM bearer tokens and OIDC client secrets in `config.json` are placeholders;
  use a real secrets manager in production.
- SP signing keys are auto-generated on first run under `data/saml-keys/` if
  absent, for a clean first checkout. Provision real, rotated keys via your
  own PKI for production tenants.
