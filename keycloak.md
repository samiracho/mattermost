# Keycloak JWT Bearer Authentication

This branch adds support for accepting **Keycloak-issued JWT access tokens**
directly as Mattermost bearer credentials. Any request carrying
`Authorization: Bearer <jwt>` is verified against the Keycloak realm's JWKS and
resolved to a Mattermost user (JIT-provisioned on first sight by default).

This is independent of the existing OAuth/OIDC *code flow*
([OpenIdSettings](server/public/model/config.go), [GitLabSettings](server/public/model/config.go)).
Both can be enabled at the same time — the JWT path is tried first inside
[`(*App).GetSession`](server/channels/app/session.go#L103-L120); if the bearer
token doesn't look like a JWT or the feature is disabled, the existing PAT /
session-token path runs unchanged.

The feature is implemented across:

- [server/public/model/config_keycloak.go](server/public/model/config_keycloak.go) — `KeycloakSettings` config block
- [server/public/model/keycloak.go](server/public/model/keycloak.go) — `UserAuthServiceKeycloak`, `SessionTypeKeycloakJWT`
- [server/channels/app/keycloakauth/](server/channels/app/keycloakauth/) — self-contained JWKS verifier
- [server/channels/app/session_keycloak.go](server/channels/app/session_keycloak.go) — session integration + JIT provisioning

## Keycloak side

1. Create (or reuse) a **realm** for Mattermost.
2. Create a **client** the consuming application will use to obtain access
   tokens. The token `aud` claim must equal the configured `Audience`. By
   default Keycloak puts the client_id in `azp` but not in `aud` unless you
   add an audience mapper:
   - In the client → *Client scopes* → `<client>-dedicated` → add a mapper of
     type **Audience**, with *Included Client Audience* set to your client_id
     and *Add to access token* enabled.
3. (Optional) Create realm roles you want to map to Mattermost
   `system_admin`. By default the verifier reads roles from
   `realm_access.roles` (the standard Keycloak realm-role claim).
4. Note the realm's OpenID discovery URL — it is the value to pass as
   `DiscoveryEndpoint`:
   `https://<keycloak-host>/realms/<realm>/.well-known/openid-configuration`

## Mattermost configuration

All knobs live under `KeycloakSettings` in `config.json`. The Viper-based env
override convention (`MM_<SECTION>_<FIELD>`) applies, so each field is also
settable via environment:

| Field | JSON / Env | Default | Notes |
|---|---|---|---|
| Enable feature | `KeycloakSettings.Enable` / `MM_KEYCLOAKSETTINGS_ENABLE` | `false` | Master switch. When `false`, the JWT path is skipped entirely. |
| OIDC discovery URL | `KeycloakSettings.DiscoveryEndpoint` / `MM_KEYCLOAKSETTINGS_DISCOVERYENDPOINT` | `""` | Either this or `JWKSEndpoint` must be set. The verifier reads `jwks_uri` from this document on first use. |
| JWKS URL (override) | `KeycloakSettings.JWKSEndpoint` / `MM_KEYCLOAKSETTINGS_JWKSENDPOINT` | `""` | If set, the verifier uses it directly and never fetches discovery. |
| Expected `iss` | `KeycloakSettings.Issuer` / `MM_KEYCLOAKSETTINGS_ISSUER` | `""` | **Required.** Must equal the `iss` claim Keycloak puts on its tokens, typically `https://<host>/realms/<realm>`. |
| Expected `aud` | `KeycloakSettings.Audience` / `MM_KEYCLOAKSETTINGS_AUDIENCE` | `""` | **Required.** Typically the Keycloak `client_id`. See the audience-mapper note above. |
| User-ID claim | `KeycloakSettings.UserIDClaim` / `MM_KEYCLOAKSETTINGS_USERIDCLAIM` | `sub` | Stored on `User.AuthData` and used as the lookup key for repeat logins. **Do not change after users have been provisioned**, or existing accounts will no longer be found. |
| Email claim | `KeycloakSettings.EmailClaim` / `MM_KEYCLOAKSETTINGS_EMAILCLAIM` | `email` | |
| Username claim | `KeycloakSettings.UsernameClaim` / `MM_KEYCLOAKSETTINGS_USERNAMECLAIM` | `preferred_username` | Source for the candidate username at provisioning time only — see [Username provisioning](#username-provisioning). |
| Name claim | `KeycloakSettings.NameClaim` / `MM_KEYCLOAKSETTINGS_NAMECLAIM` | `name` | Split on the first space → `FirstName` / `LastName`. |
| Clock skew (seconds) | `KeycloakSettings.ClockSkewSeconds` / `MM_KEYCLOAKSETTINGS_CLOCKSKEWSECONDS` | `30` | Leeway applied to `exp`/`nbf`/`iat`. |
| JIT provisioning | `KeycloakSettings.JITProvisioning` / `MM_KEYCLOAKSETTINGS_JITPROVISIONING` | `true` | When `false`, unknown users get `401` instead of being created. |
| JWKS refresh (minutes) | `KeycloakSettings.JWKSRefreshMinutes` / `MM_KEYCLOAKSETTINGS_JWKSREFRESHMINUTES` | `60` | Upper bound on the time between full JWKS refreshes. On a `kid` cache-miss, the verifier *also* refreshes immediately (rate-limited to once every 30s). |
| Roles claim (dotted path) | `KeycloakSettings.RolesClaim` / `MM_KEYCLOAKSETTINGS_ROLESCLAIM` | `realm_access.roles` | Dotted JSON path into the JWT claims that yields a `[]string` of Keycloak role names. For client roles, e.g. `resource_access.<client_id>.roles`. |
| Admin roles (CSV) | `KeycloakSettings.AdminRoles` / `MM_KEYCLOAKSETTINGS_ADMINROLES` | `""` | If any of the user's Keycloak roles match one of these, the synthetic session is granted `system_admin`. |
| Default roles (CSV) | `KeycloakSettings.DefaultRoles` / `MM_KEYCLOAKSETTINGS_DEFAULTROLES` | `system_user` | Baseline Mattermost roles every authenticated JWT user receives. |

Validation rules (enforced by [`KeycloakSettings.IsValid`](server/public/model/config_keycloak.go#L92-L114)):

- `Issuer` and `Audience` are required when `Enable=true`.
- At least one of `DiscoveryEndpoint` or `JWKSEndpoint` must be set.
- `ClockSkewSeconds` ≥ 0, `JWKSRefreshMinutes` > 0.

## How a request is authenticated

1. The bearer token is extracted from the `Authorization` header by
   [`ParseAuthTokenFromRequest`](server/channels/app/authentication.go#L441).
   JWT-shaped tokens (3 dot-separated segments) are now allowed through at
   full length; PATs (26 chars) are unchanged.
2. [`(*App).GetSession`](server/channels/app/session.go#L103-L120) calls
   `tryKeycloakJWTSession` first. If the feature is disabled or the token
   isn't JWT-shaped, it returns `(nil, nil)` and the existing PAT path runs.
3. The token signature is checked against the realm's JWKS, and `iss`,
   `aud`, `exp` (required), and `nbf`/`iat` (with leeway) are validated.
   Supported algorithms: `RS256/384/512`, `ES256/384/512`.
4. Claims are extracted and mapped to a Mattermost user (see below).
5. A **synthetic, non-persisted** `model.Session` is built and added to the
   in-memory session cache. `ExpiresAt` mirrors the JWT's own `exp`, so the
   session naturally drops out of cache on token expiry. Session
   `Props[SessionPropType] = "KeycloakJWT"`.
6. Idle-timeout enforcement is **skipped** for these sessions
   (see [`IsKeycloakJWTSession`](server/channels/app/session_keycloak.go#L96-L98)) — the JWT carries its own lifetime.

## Role mapping

Roles are evaluated **per request**, from the JWT itself, not from the
persisted `User.Roles`. This means removing an admin role in Keycloak takes
effect on the next request *without* any DB write.

```
session.Roles = DefaultRoles ∪ (AdminRoles ∩ token roles ? {system_admin} : ∅)
```

Empty admin/default entries are skipped; duplicates are de-duped. If the
roles claim is missing or empty, the user still gets `DefaultRoles`
(`system_user` by default).

## Username provisioning

On first sight of a `sub` not seen before (and `JITProvisioning=true`), a new
Mattermost user is created. The username is picked from the first non-empty
candidate that survives [`model.CleanUsername`](server/public/model/user.go#L1045-L1072):

1. `preferred_username` (or whatever `UsernameClaim` points to)
2. Local part of `email`
3. `sub` itself
4. Last-ditch: `kc-<sub>`

### The "admin" reserved-name case

`CleanUsername` strips a fixed list of [reserved names](server/public/model/utils.go#L685)
— `admin`, `api`, `channel`, `claim`, `error`, `files`, `help`, `landing`,
`login`, `mfa`, `oauth`, `plug`, `plugins`, `post`, etc. — from the candidate
*before* validating it. So a Keycloak user whose `preferred_username` is
literally `admin` will **not** become Mattermost user `admin`:

- `CleanUsername("admin")` → empty string after the reserved-name strip →
  `IsValidUsername("")` is `false` → fall through to the next candidate.
- Resolution order continues: `email` local part → `sub` → `kc-<sub>`.
- So `admin@example.com` would land as username `admin-example-com` (or
  whatever the email local-part cleans to).
- If a user *only* has `preferred_username=admin` and no usable email, the
  username derives from the Keycloak `sub` (typically a UUID), e.g.
  `kc-7b3...`.

After a candidate is picked, a collision check appends 6 hex chars of
`model.NewId()` and retries until the username is free — so re-provisioning
two distinct Keycloak users both named `john` will produce `john` and
`john-ab12cd`, not a conflict.

Becoming a Mattermost `system_admin` is governed exclusively by
`KeycloakSettings.AdminRoles`. There is **no path** by which the literal
string `admin` in the username claim grants elevated privileges.

### Email collisions

If a user with `claims.Email` already exists under a *different* auth
service, provisioning is refused with `401`
(`api.user.create_oauth_user.already_attached.app_error`). This mirrors the
existing `CreateOAuthUser` policy and prevents silently re-keying an
existing account onto Keycloak.

## Operational notes

- **Verifier caching.** The verifier and its JWKS cache are held in a
  package-level singleton in `session_keycloak.go`, keyed by a fingerprint
  of the verifier-relevant config fields. Unrelated config changes don't
  rebuild it (and don't flush JWKS). Rotating any of the
  `Issuer/Audience/*Endpoint/*Claim/Roles/Skew/Refresh` fields *does*.
- **Key rotation.** When Keycloak rotates signing keys, the next incoming
  token with an unknown `kid` triggers a JWKS refetch (rate-limited to once
  per 30s) — manual restarts are not required.
- **Token size.** JWTs up to 8192 bytes are accepted. Anything outside
  20–8192 bytes or not 3-segment is rejected before any network I/O.
- **Logs.** Verification failures are logged at `debug` with the underlying
  error; users only see a generic `401`. Newly provisioned users are logged
  at `info` with `user_id` and `auth_data` (the `sub`).
- **No DB writes per request.** Sessions are in-memory only; LoginAt /
  LastActivityAt are *not* updated. This is intentional — the JWT is the
  authority.

## Quick test

With the feature enabled and configured:

```bash
TOKEN=$(curl -s -X POST \
  "https://<keycloak>/realms/<realm>/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=<client>" \
  -d "username=<user>" \
  -d "password=<pw>" \
  | jq -r .access_token)

curl -H "Authorization: Bearer $TOKEN" https://<mattermost>/api/v4/users/me
```

The first call provisions the Mattermost user (if JIT is on); subsequent
calls reuse the cached synthetic session until the JWT's `exp` passes.

## Back-channel logout

Mattermost exposes an OIDC Back-Channel Logout 1.0 endpoint so Keycloak can
notify it when a user's session is terminated and cached synthetic sessions
should be evicted immediately rather than waiting for the JWT's `exp`.

- **Endpoint:** `POST <mattermost>/oauth/keycloak/backchannel_logout`
- **Content type:** `application/x-www-form-urlencoded`, single field
  `logout_token` (a JWT signed by the same Keycloak realm).
- **Auth:** none — the signed `logout_token` *is* the credential. The
  endpoint reuses the same `Issuer`, `Audience`, and JWKS as the bearer-auth
  path; it is **active iff `KeycloakSettings.Enable=true`** (otherwise it
  returns `404`).
- **What it evicts:** all cached sessions for the user identified by the
  token's `sub` claim, across all cluster nodes (via the existing
  `ClusterEventClearSessionCacheForUser` message).

### Configure Keycloak

In the client → *Settings*:

- **Backchannel logout URL:** `https://<mattermost-host>/oauth/keycloak/backchannel_logout`
- **Backchannel logout session required:** *off* (we only act on `sub`; the
  `sid` claim is accepted but ignored in this version).
- **Front-channel logout:** *off* (we don't implement front-channel).

### Behaviour caveat — bearer tokens stay cryptographically valid

Keycloak's logout terminates the *Keycloak SSO session*, not the access
tokens it already issued. Those tokens remain signed-and-not-yet-expired.
This endpoint evicts the cached Mattermost session, but a client that keeps
presenting the same bearer token would rebuild its cache entry on the next
request — because the JWT still verifies.

That means real logout enforcement depends on either:

- the client cooperating (browsers, native apps, CLIs that discard their
  token on logout) — which is the normal case, **or**
- pairing this with a **short access-token lifespan** in Keycloak (1–2
  minutes), so a non-cooperating client gets shut out at the next refresh.

A future `sid`/`jti`-based revocation set would let the verifier reject a
revoked token mid-lifetime; not implemented here.

### What's logged

- Audit record `keycloak_backchannel_logout` (success/fail) with `jti`,
  `sub`, and the resolved Mattermost `user_id`.
- Verification failures are logged at `debug` only — the source is an
  external IdP, so bad input is not a server-side error.

## Recommended Keycloak realm / client settings

The defaults Keycloak ships with are tuned for general-purpose use, not for
making bearer-token logout snappy. For deployments using this branch's
JWT-bearer auth, the following knobs are worth setting explicitly.

### Realm → Tokens

| Setting | Suggested | Why |
|---|---|---|
| **Access Token Lifespan** | 1–5 min | Upper bound on the post-logout grace window (a non-cooperating client can keep presenting its token until `exp`). Short = logout enforcement is fast. The cost is more refresh round-trips against Keycloak, which is cheap. |
| **SSO Session Idle** | e.g. 30 days | How long a user can be inactive before being forced to re-auth. This is the "remember me" feel you'd otherwise reach for `offline_access` to get. |
| **SSO Session Max** | e.g. 90 days | Hard cap. Even active users re-auth at this interval. |
| **Revoke Refresh Token** | ON | Enables refresh-token rotation. |
| **Refresh Token Max Reuse** | 0 | Strict one-shot RTs. A replay is detected → the token family is invalidated → the suspect device is forced to re-auth. |
| **Offline Session Idle / Max** | finite (e.g. 30 days), never "unlimited" | Only relevant if you allow `offline_access` at all (see below). Don't leave it at the default "0 = unlimited". |

### Realm / client → Client scopes

- **Remove `offline_access` from this client's *Default Client Scopes*** (and ideally from *Optional* too, unless a specific integration needs it). `offline_access` produces refresh tokens that *survive normal logout* — they sit in a separate "Offline sessions" tab in the admin console and bypass the back-channel logout chain unless explicitly revoked. For interactive web/mobile clients, prefer regular refresh tokens whose lifetime is governed by *SSO Session Idle / Max* above.
- Reserve `offline_access` for genuinely headless workloads (server-side jobs, CI bots, periodic sync daemons) where you also accept the harder revocation story.

### Client → Settings

- **Backchannel logout URL:** `https://<mattermost-host>/oauth/keycloak/backchannel_logout` (covered in [Back-channel logout](#back-channel-logout)).
- **Backchannel logout session required:** *off* in this version (we act on `sub`; `sid` is accepted but ignored).
- **Front-channel logout:** *off* (not implemented).

### Audience mapper

Keycloak doesn't put the `client_id` in `aud` by default. Add a mapper of
type **Audience** with *Included Client Audience* = your client_id, and
*Add to access token* enabled — otherwise `KeycloakSettings.Audience`
validation will reject every token. (Already noted in [Keycloak side](#keycloak-side).)

### Mobile-specific

- Store the refresh token in the OS-backed keystore (iOS Keychain, Android
  Keystore) — not `NSUserDefaults` / `SharedPreferences`.
- Implement RT rotation correctly: when you refresh, save the new RT
  *atomically* and discard the old one before any other code path can read
  it. A race here manifests as users reporting random logouts.
- Use the system browser (ASWebAuthenticationSession on iOS, Custom Tabs on
  Android) for the auth flow, per RFC 8252. Don't embed a WebView.

## Limitations / non-goals

- **Refresh tokens are not handled.** The client (browser, CLI, integration)
  is responsible for refreshing against Keycloak and presenting a fresh
  access token. Mattermost never sees the refresh token.
- **No `sid`-granular logout.** Back-channel logout uses user-level cache
  eviction (see above). A logout token carrying only `sid` and no `sub` is
  rejected with `400 invalid_request`.
- **No `jti` replay protection.** Replays are harmless (they just re-evict
  an already-evicted cache entry).
- **No group sync.** Only roles → system_admin is mapped. Team / channel
  membership is not driven by Keycloak group claims in this branch.
- **Encrypted (JWE) tokens are not supported** — only signed JWS access
  tokens, which is the Keycloak default.
