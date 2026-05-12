// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

// Package keycloakauth verifies Keycloak-issued JWT access tokens against
// the IdP's JWKS so that Mattermost can accept them directly as bearer
// credentials, eliminating the need for an intermediate Personal Access
// Token.
//
// The package is deliberately self-contained (no third-party JOSE
// dependency beyond the already-vendored github.com/golang-jwt/jwt/v5) and
// has no transitive dependency on the surrounding `app` package, so it
// can be lifted out or replaced without touching call sites.
package keycloakauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/mattermost/mattermost/server/public/model"
)

// Config is the verifier-relevant subset of model.KeycloakSettings. We
// take a flat snapshot rather than a *model.KeycloakSettings pointer so
// the verifier is decoupled from config-reload races and trivially
// constructible in tests.
type Config struct {
	DiscoveryEndpoint  string
	JWKSEndpoint       string
	Issuer             string
	Audience           string
	UserIDClaim        string
	EmailClaim         string
	UsernameClaim      string
	NameClaim          string
	RolesClaim         string
	AdminRoles         []string
	DefaultRoles       []string
	ClockSkew          time.Duration
	JWKSRefreshEvery   time.Duration
	JITProvisioning    bool
	JWKSRefreshMinGap  time.Duration // rate-limit kid-miss refreshes; default 30s
	HTTPClient         *http.Client  // injectable for tests; defaults to 10s timeout
}

// ConfigFromModel builds a verifier Config from the runtime model
// settings, applying the same defaults as model.KeycloakSettings.SetDefaults
// for any fields that arrive unset (defensive — SetDefaults should already
// have been called by the time we reach this code).
func ConfigFromModel(s *model.KeycloakSettings) Config {
	cs := derefInt(s.ClockSkewSeconds, 30)
	rm := derefInt(s.JWKSRefreshMinutes, 60)
	return Config{
		DiscoveryEndpoint: derefStr(s.DiscoveryEndpoint),
		JWKSEndpoint:      derefStr(s.JWKSEndpoint),
		Issuer:            derefStr(s.Issuer),
		Audience:          derefStr(s.Audience),
		UserIDClaim:       firstNonEmpty(derefStr(s.UserIDClaim), "sub"),
		EmailClaim:        firstNonEmpty(derefStr(s.EmailClaim), "email"),
		UsernameClaim:     firstNonEmpty(derefStr(s.UsernameClaim), "preferred_username"),
		NameClaim:         firstNonEmpty(derefStr(s.NameClaim), "name"),
		RolesClaim:        firstNonEmpty(derefStr(s.RolesClaim), "realm_access.roles"),
		AdminRoles:        splitCSV(derefStr(s.AdminRoles)),
		DefaultRoles:      splitCSV(firstNonEmpty(derefStr(s.DefaultRoles), "system_user")),
		ClockSkew:         time.Duration(cs) * time.Second,
		JWKSRefreshEvery:  time.Duration(rm) * time.Minute,
		JITProvisioning:   derefBool(s.JITProvisioning, true),
		JWKSRefreshMinGap: 30 * time.Second,
	}
}

// VerifiedClaims is what the verifier hands back to the App layer after a
// successful Verify(). All fields except Subject and Roles are
// best-effort: empty if the claim is absent in the token.
type VerifiedClaims struct {
	Subject           string
	Email             string
	PreferredUsername string
	Name              string
	ExpiresAt         time.Time
	// MattermostRoles is the result of the RolesClaim → AdminRoles
	// mapping. It is the space-separated string suitable for assignment
	// directly to model.Session.Roles / model.User.Roles. Always
	// contains at least the configured DefaultRoles.
	MattermostRoles string
}

// Verifier verifies Keycloak JWTs. It is safe for concurrent use.
type Verifier struct {
	cfg     Config
	http    *http.Client
	jwksURL string // resolved lazily from discovery on first use

	mu         sync.RWMutex
	keys       map[string]parsedKey
	lastFetch  time.Time
	jwksURLSet bool
}

// New constructs a Verifier. It does not perform any network I/O; the
// first call to Verify will lazily fetch the discovery document (if a
// JWKSEndpoint was not configured directly) and the JWKS itself.
func New(cfg Config) *Verifier {
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	v := &Verifier{
		cfg:  cfg,
		http: client,
		keys: map[string]parsedKey{},
	}
	if cfg.JWKSEndpoint != "" {
		v.jwksURL = cfg.JWKSEndpoint
		v.jwksURLSet = true
	}
	return v
}

// Verify parses, validates, and returns the claims of a Keycloak JWT.
// On any error the returned *VerifiedClaims is nil and the error is
// suitable for translating to a 401.
func (v *Verifier) Verify(ctx context.Context, tokenString string) (*VerifiedClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}),
		jwt.WithIssuer(v.cfg.Issuer),
		jwt.WithAudience(v.cfg.Audience),
		jwt.WithLeeway(v.cfg.ClockSkew),
		jwt.WithExpirationRequired(),
	)

	tok, err := parser.Parse(tokenString, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("keycloak: token header missing 'kid'")
		}
		return v.keyForKID(ctx, kid)
	})
	if err != nil {
		return nil, fmt.Errorf("keycloak: verify failed: %w", err)
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("keycloak: unexpected claims type")
	}
	return v.extract(claims)
}

// LogoutClaims is what VerifyLogoutToken returns on success. Subject is
// resolved via cfg.UserIDClaim (same as access tokens) so the caller can
// hand it straight to userService.GetUserByAuth. SID and JTI are extracted
// for logging / future per-session-id work; v1 only acts on Subject.
type LogoutClaims struct {
	Subject string
	SID     string
	JTI     string
}

// backchannelLogoutEvent is the fixed JSON Pointer (per OIDC Back-Channel
// Logout 1.0 §2.6) that MUST appear as a key in the token's `events` claim.
const backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// VerifyLogoutToken validates an OIDC back-channel logout token (a JWT
// posted by Keycloak when a session is terminated). It reuses the same
// JWKS plumbing as Verify but applies the spec-specific rules from §2.4:
//
//   - iss / aud / signature: same as an access token.
//   - `events` MUST contain backchannelLogoutEvent.
//   - `iat` MUST be present.
//   - `jti` MUST be present.
//   - `nonce` MUST NOT be present.
//   - At least one of `sub` or `sid` MUST be present.
//   - `exp` is NOT required (and is typically absent).
//
// On any error the returned *LogoutClaims is nil.
func (v *Verifier) VerifyLogoutToken(ctx context.Context, tokenString string) (*LogoutClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}),
		jwt.WithIssuer(v.cfg.Issuer),
		jwt.WithAudience(v.cfg.Audience),
		jwt.WithLeeway(v.cfg.ClockSkew),
	)

	tok, err := parser.Parse(tokenString, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("keycloak: logout token header missing 'kid'")
		}
		return v.keyForKID(ctx, kid)
	})
	if err != nil {
		return nil, fmt.Errorf("keycloak: logout verify failed: %w", err)
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("keycloak: unexpected claims type")
	}

	if _, ok := claims["nonce"]; ok {
		return nil, errors.New("keycloak: logout token must not contain 'nonce'")
	}

	iat, err := claims.GetIssuedAt()
	if err != nil || iat == nil {
		return nil, errors.New("keycloak: logout token missing 'iat'")
	}

	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil, errors.New("keycloak: logout token missing 'jti'")
	}

	evRaw, ok := claims["events"]
	if !ok {
		return nil, errors.New("keycloak: logout token missing 'events'")
	}
	ev, ok := evRaw.(map[string]any)
	if !ok {
		return nil, errors.New("keycloak: logout token 'events' is not an object")
	}
	if _, ok := ev[backchannelLogoutEvent]; !ok {
		return nil, fmt.Errorf("keycloak: logout token 'events' missing %q", backchannelLogoutEvent)
	}

	sub, _ := lookupString(claims, v.cfg.UserIDClaim)
	sid, _ := claims["sid"].(string)
	if sub == "" && sid == "" {
		return nil, errors.New("keycloak: logout token must carry 'sub' or 'sid'")
	}

	return &LogoutClaims{Subject: sub, SID: sid, JTI: jti}, nil
}

// LooksLikeJWT is a cheap pre-check used by the session pipeline to
// decide whether to even attempt JWT verification on an incoming bearer
// token. Three non-empty dot-separated segments and a reasonable upper
// length bound is sufficient to skip PAT tokens and session IDs.
func LooksLikeJWT(token string) bool {
	if len(token) < 20 || len(token) > 8192 {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
	}
	return true
}

// --- internals ---------------------------------------------------------

type parsedKey struct {
	id     string
	alg    string
	public any // *rsa.PublicKey or *ecdsa.PublicKey
}

func (v *Verifier) keyForKID(ctx context.Context, kid string) (any, error) {
	v.mu.RLock()
	if k, ok := v.keys[kid]; ok {
		v.mu.RUnlock()
		return k.public, nil
	}
	v.mu.RUnlock()

	// Miss: refresh JWKS (rate-limited) and try again.
	if err := v.refreshJWKS(ctx, false); err != nil {
		return nil, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if k, ok := v.keys[kid]; ok {
		return k.public, nil
	}
	return nil, fmt.Errorf("keycloak: signing key not found for kid=%q", kid)
}

func (v *Verifier) refreshJWKS(ctx context.Context, force bool) error {
	v.mu.Lock()
	if !force && !v.lastFetch.IsZero() && time.Since(v.lastFetch) < v.cfg.JWKSRefreshMinGap {
		v.mu.Unlock()
		return nil
	}
	v.mu.Unlock()

	if !v.jwksURLSet {
		u, err := v.resolveJWKSURL(ctx)
		if err != nil {
			return err
		}
		v.mu.Lock()
		v.jwksURL = u
		v.jwksURLSet = true
		v.mu.Unlock()
	}

	keys, err := v.fetchJWKS(ctx, v.jwksURL)
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.keys = keys
	v.lastFetch = time.Now()
	v.mu.Unlock()
	return nil
}

func (v *Verifier) resolveJWKSURL(ctx context.Context) (string, error) {
	if v.cfg.DiscoveryEndpoint == "" {
		return "", errors.New("keycloak: neither JWKSEndpoint nor DiscoveryEndpoint is configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.DiscoveryEndpoint, nil)
	if err != nil {
		return "", err
	}
	resp, err := v.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("keycloak: discovery fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("keycloak: discovery returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("keycloak: discovery decode: %w", err)
	}
	if doc.JWKSURI == "" {
		return "", errors.New("keycloak: discovery doc has no jwks_uri")
	}
	return doc.JWKSURI, nil
}

// jwk is the subset of RFC 7517 we care about.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	// RSA
	N string `json:"n"`
	E string `json:"e"`
	// EC
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (v *Verifier) fetchJWKS(ctx context.Context, url string) (map[string]parsedKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keycloak: jwks fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keycloak: jwks returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("keycloak: jwks decode: %w", err)
	}
	out := make(map[string]parsedKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := parsePublicKey(k)
		if err != nil {
			// Skip unknown/malformed keys rather than failing the
			// whole refresh — Keycloak realms can carry encryption
			// keys we don't care about.
			continue
		}
		out[k.Kid] = parsedKey{id: k.Kid, alg: k.Alg, public: pub}
	}
	if len(out) == 0 {
		return nil, errors.New("keycloak: jwks contained no usable signing keys")
	}
	return out, nil
}

func parsePublicKey(k jwk) (any, error) {
	switch k.Kty {
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		y, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported key type %q", k.Kty)
	}
}

func (v *Verifier) extract(claims jwt.MapClaims) (*VerifiedClaims, error) {
	sub, _ := lookupString(claims, v.cfg.UserIDClaim)
	if sub == "" {
		return nil, errors.New("keycloak: token has empty user-id claim")
	}
	email, _ := lookupString(claims, v.cfg.EmailClaim)
	uname, _ := lookupString(claims, v.cfg.UsernameClaim)
	name, _ := lookupString(claims, v.cfg.NameClaim)

	var exp time.Time
	if expAt, err := claims.GetExpirationTime(); err == nil && expAt != nil {
		exp = expAt.Time
	}

	kcRoles := lookupStringSlice(claims, v.cfg.RolesClaim)
	mmRoles := mapRoles(kcRoles, v.cfg.AdminRoles, v.cfg.DefaultRoles)

	return &VerifiedClaims{
		Subject:           sub,
		Email:             email,
		PreferredUsername: uname,
		Name:              name,
		ExpiresAt:         exp,
		MattermostRoles:   mmRoles,
	}, nil
}

// mapRoles applies the Keycloak-roles → Mattermost-roles policy: always
// include DefaultRoles; if any Keycloak role is in the admin set, also
// include system_admin.
func mapRoles(kcRoles, adminRoles, defaultRoles []string) string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(defaultRoles)+1)
	for _, r := range defaultRoles {
		if r == "" {
			continue
		}
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	if hasAny(kcRoles, adminRoles) {
		if _, ok := seen[model.SystemAdminRoleId]; !ok {
			out = append(out, model.SystemAdminRoleId)
		}
	}
	return strings.Join(out, " ")
}

// lookupString resolves a dotted JSON path against MapClaims, returning a
// string value if the leaf is a string. Empty path or non-string leaf
// returns ("", false).
func lookupString(claims jwt.MapClaims, path string) (string, bool) {
	v := walk(claims, path)
	s, ok := v.(string)
	return s, ok
}

// lookupStringSlice resolves a dotted JSON path against MapClaims and
// coerces the leaf to []string. Returns nil if the path is missing or
// the leaf is not an array of strings.
func lookupStringSlice(claims jwt.MapClaims, path string) []string {
	v := walk(claims, path)
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func walk(claims jwt.MapClaims, path string) any {
	if path == "" {
		return nil
	}
	var cur any = map[string]any(claims)
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[seg]
		if !ok {
			return nil
		}
	}
	return cur
}

func hasAny(have, want []string) bool {
	if len(have) == 0 || len(want) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(want))
	for _, w := range want {
		if w != "" {
			set[w] = struct{}{}
		}
	}
	for _, h := range have {
		if _, ok := set[h]; ok {
			return true
		}
	}
	return false
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
func derefInt(p *int, def int) int {
	if p == nil {
		return def
	}
	return *p
}
func derefBool(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
