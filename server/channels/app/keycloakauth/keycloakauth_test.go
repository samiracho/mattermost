// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package keycloakauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeIdP runs an httptest server exposing /.well-known/openid-configuration
// and a /jwks endpoint backed by an in-memory RSA keypair.
type fakeIdP struct {
	srv         *httptest.Server
	priv        *rsa.PrivateKey
	kid         string
	rotationsTo *rsa.PrivateKey // optional second key, served after Rotate()
	rotatedKid  string
	jwksHits    int64
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &fakeIdP{priv: priv, kid: "k1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   base,
			"jwks_uri": base + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&idp.jwksHits, 1)
		keys := []map[string]string{rsaJWK(idp.priv, idp.kid)}
		if idp.rotationsTo != nil {
			keys = append(keys, rsaJWK(idp.rotationsTo, idp.rotatedKid))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})
	idp.srv = httptest.NewServer(mux)
	return idp
}

func (i *fakeIdP) Close() { i.srv.Close() }

func (i *fakeIdP) Issuer() string   { return i.srv.URL }
func (i *fakeIdP) Discovery() string { return i.srv.URL + "/.well-known/openid-configuration" }

func (i *fakeIdP) Rotate(t *testing.T) {
	t.Helper()
	p, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	i.rotationsTo = p
	i.rotatedKid = "k2"
}

func (i *fakeIdP) Mint(t *testing.T, claims jwt.MapClaims, opts ...mintOption) string {
	t.Helper()
	o := mintOptions{kid: i.kid, signer: i.priv}
	for _, fn := range opts {
		fn(&o)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = o.kid
	signed, err := tok.SignedString(o.signer)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

type mintOptions struct {
	kid    string
	signer *rsa.PrivateKey
}
type mintOption func(*mintOptions)

func withKid(k string) mintOption       { return func(o *mintOptions) { o.kid = k } }
func withSigner(p *rsa.PrivateKey) mintOption { return func(o *mintOptions) { o.signer = p } }

func rsaJWK(p *rsa.PrivateKey, kid string) map[string]string {
	return map[string]string{
		"kty": "RSA",
		"alg": "RS256",
		"use": "sig",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(p.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.E)).Bytes()),
	}
}

func baseClaims(idp *fakeIdP, aud string) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss":                idp.Issuer(),
		"aud":                aud,
		"sub":                "kc-user-1",
		"email":              "alice@example.com",
		"preferred_username": "alice",
		"name":               "Alice Anderson",
		"iat":                now.Unix(),
		"nbf":                now.Unix() - 5,
		"exp":                now.Add(5 * time.Minute).Unix(),
		"realm_access":       map[string]any{"roles": []any{"chat-user"}},
	}
}

func newVerifier(idp *fakeIdP, mutate func(*Config)) *Verifier {
	cfg := Config{
		DiscoveryEndpoint: idp.Discovery(),
		Issuer:            idp.Issuer(),
		Audience:          "mychat-client",
		UserIDClaim:       "sub",
		EmailClaim:        "email",
		UsernameClaim:     "preferred_username",
		NameClaim:         "name",
		RolesClaim:        "realm_access.roles",
		AdminRoles:        []string{"chat-admin"},
		DefaultRoles:      []string{"system_user"},
		ClockSkew:         30 * time.Second,
		JWKSRefreshMinGap: 0, // allow back-to-back refresh in tests
	}
	if mutate != nil {
		mutate(&cfg)
	}
	return New(cfg)
}

func TestVerify_HappyPath(t *testing.T) {
	idp := newFakeIdP(t)
	defer idp.Close()
	v := newVerifier(idp, nil)

	token := idp.Mint(t, baseClaims(idp, "mychat-client"))
	got, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Subject != "kc-user-1" {
		t.Errorf("Subject = %q, want kc-user-1", got.Subject)
	}
	if got.Email != "alice@example.com" {
		t.Errorf("Email = %q", got.Email)
	}
	if got.PreferredUsername != "alice" {
		t.Errorf("PreferredUsername = %q", got.PreferredUsername)
	}
	if got.MattermostRoles != "system_user" {
		t.Errorf("MattermostRoles = %q, want plain system_user (no admin role on this token)", got.MattermostRoles)
	}
	if got.ExpiresAt.IsZero() {
		t.Error("ExpiresAt zero")
	}
}

func TestVerify_AdminRoleMapping(t *testing.T) {
	idp := newFakeIdP(t)
	defer idp.Close()
	v := newVerifier(idp, nil)

	claims := baseClaims(idp, "mychat-client")
	claims["realm_access"] = map[string]any{"roles": []any{"chat-user", "chat-admin"}}
	token := idp.Mint(t, claims)

	got, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !strings.Contains(got.MattermostRoles, "system_admin") {
		t.Errorf("expected system_admin in roles, got %q", got.MattermostRoles)
	}
	if !strings.Contains(got.MattermostRoles, "system_user") {
		t.Errorf("expected system_user in roles, got %q", got.MattermostRoles)
	}
}

func TestVerify_ClientRolesViaCustomClaim(t *testing.T) {
	idp := newFakeIdP(t)
	defer idp.Close()
	v := newVerifier(idp, func(c *Config) {
		c.RolesClaim = "resource_access.mychat-client.roles"
	})

	claims := baseClaims(idp, "mychat-client")
	claims["resource_access"] = map[string]any{
		"mychat-client": map[string]any{"roles": []any{"chat-admin"}},
	}
	token := idp.Mint(t, claims)
	got, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !strings.Contains(got.MattermostRoles, "system_admin") {
		t.Errorf("expected system_admin via client-roles claim, got %q", got.MattermostRoles)
	}
}

func TestVerify_ExpiredToken(t *testing.T) {
	idp := newFakeIdP(t)
	defer idp.Close()
	v := newVerifier(idp, nil)

	claims := baseClaims(idp, "mychat-client")
	claims["exp"] = time.Now().Add(-1 * time.Hour).Unix()
	token := idp.Mint(t, claims)

	if _, err := v.Verify(context.Background(), token); err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestVerify_WrongAudience(t *testing.T) {
	idp := newFakeIdP(t)
	defer idp.Close()
	v := newVerifier(idp, nil)

	token := idp.Mint(t, baseClaims(idp, "someone-else"))
	if _, err := v.Verify(context.Background(), token); err == nil {
		t.Fatal("expected error for wrong audience")
	}
}

func TestVerify_WrongIssuer(t *testing.T) {
	idp := newFakeIdP(t)
	defer idp.Close()
	v := newVerifier(idp, func(c *Config) { c.Issuer = "https://not-the-idp" })

	token := idp.Mint(t, baseClaims(idp, "mychat-client"))
	if _, err := v.Verify(context.Background(), token); err == nil {
		t.Fatal("expected error for wrong issuer")
	}
}

func TestVerify_TamperedSignature(t *testing.T) {
	idp := newFakeIdP(t)
	defer idp.Close()
	v := newVerifier(idp, nil)

	token := idp.Mint(t, baseClaims(idp, "mychat-client"))
	// flip a character in the signature segment
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected token shape")
	}
	sig := []byte(parts[2])
	sig[0] ^= 0x01
	parts[2] = string(sig)
	tampered := strings.Join(parts, ".")
	if _, err := v.Verify(context.Background(), tampered); err == nil {
		t.Fatal("expected error for tampered signature")
	}
}

func TestVerify_UnknownKidTriggersJWKSRefresh(t *testing.T) {
	idp := newFakeIdP(t)
	defer idp.Close()
	v := newVerifier(idp, nil)

	// First verify primes the JWKS cache.
	if _, err := v.Verify(context.Background(), idp.Mint(t, baseClaims(idp, "mychat-client"))); err != nil {
		t.Fatalf("priming verify: %v", err)
	}
	primeHits := atomic.LoadInt64(&idp.jwksHits)

	// Now rotate IdP keys. Mint a token signed with the new key.
	idp.Rotate(t)
	rotatedToken := idp.Mint(t, baseClaims(idp, "mychat-client"), withSigner(idp.rotationsTo), withKid(idp.rotatedKid))

	if _, err := v.Verify(context.Background(), rotatedToken); err != nil {
		t.Fatalf("verify after rotation: %v", err)
	}
	if atomic.LoadInt64(&idp.jwksHits) <= primeHits {
		t.Errorf("expected JWKS refresh on unknown kid; hits %d → %d", primeHits, atomic.LoadInt64(&idp.jwksHits))
	}
}

func TestVerify_MalformedToken(t *testing.T) {
	idp := newFakeIdP(t)
	defer idp.Close()
	v := newVerifier(idp, nil)

	cases := []string{"", "not-a-jwt", "a.b", "a.b.c.d"}
	for _, c := range cases {
		if _, err := v.Verify(context.Background(), c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func TestLooksLikeJWT(t *testing.T) {
	yes := []string{
		strings.Repeat("a", 10) + "." + strings.Repeat("b", 10) + "." + strings.Repeat("c", 10),
	}
	no := []string{
		"",
		"abcdef",                                          // too short
		"abc.def",                                         // 2 segments
		"abc.def.ghi.jkl",                                 // 4 segments
		strings.Repeat("a", 26),                           // looks like a Mattermost PAT ID
		"x." + strings.Repeat("a", 5) + "." + strings.Repeat("b", 5), // first seg too short still passes — we only test non-empty
	}
	for _, s := range yes {
		if !LooksLikeJWT(s) {
			t.Errorf("LooksLikeJWT(%q) = false, want true", s)
		}
	}
	for _, s := range no[:5] { // skip last case which is actually a valid shape
		if LooksLikeJWT(s) {
			t.Errorf("LooksLikeJWT(%q) = true, want false", s)
		}
	}
}

func TestClockSkew(t *testing.T) {
	idp := newFakeIdP(t)
	defer idp.Close()
	v := newVerifier(idp, func(c *Config) { c.ClockSkew = 2 * time.Minute })

	claims := baseClaims(idp, "mychat-client")
	// nbf 1 minute in the future — outside the strict window but inside our skew tolerance.
	claims["nbf"] = time.Now().Add(1 * time.Minute).Unix()
	token := idp.Mint(t, claims)
	if _, err := v.Verify(context.Background(), token); err != nil {
		t.Fatalf("expected token to pass with 2m skew, got %v", err)
	}
}

func TestMapRoles_NoAdmin(t *testing.T) {
	got := mapRoles([]string{"chat-user"}, []string{"chat-admin"}, []string{"system_user"})
	if got != "system_user" {
		t.Errorf("got %q", got)
	}
}

func TestMapRoles_AdminMatched(t *testing.T) {
	got := mapRoles([]string{"chat-admin"}, []string{"chat-admin"}, []string{"system_user"})
	if !strings.Contains(got, "system_admin") {
		t.Errorf("expected system_admin, got %q", got)
	}
}

func TestMapRoles_NoDefaultRoles(t *testing.T) {
	got := mapRoles([]string{"chat-admin"}, []string{"chat-admin"}, nil)
	if got != "system_admin" {
		t.Errorf("got %q, want system_admin", got)
	}
}

func baseLogoutClaims(idp *fakeIdP, aud string) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss":    idp.Issuer(),
		"aud":    aud,
		"sub":    "kc-user-1",
		"iat":    now.Unix(),
		"jti":    "logout-jti-1",
		"events": map[string]any{backchannelLogoutEvent: map[string]any{}},
	}
}

func TestVerifyLogoutToken_HappyPath(t *testing.T) {
	idp := newFakeIdP(t)
	defer idp.Close()
	v := newVerifier(idp, nil)

	tok := idp.Mint(t, baseLogoutClaims(idp, "mychat-client"))
	got, err := v.VerifyLogoutToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("verify logout: %v", err)
	}
	if got.Subject != "kc-user-1" {
		t.Errorf("Subject = %q", got.Subject)
	}
	if got.JTI != "logout-jti-1" {
		t.Errorf("JTI = %q", got.JTI)
	}
}

func TestVerifyLogoutToken_SidOnly(t *testing.T) {
	idp := newFakeIdP(t)
	defer idp.Close()
	v := newVerifier(idp, nil)

	claims := baseLogoutClaims(idp, "mychat-client")
	delete(claims, "sub")
	claims["sid"] = "session-42"
	tok := idp.Mint(t, claims)

	got, err := v.VerifyLogoutToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("verify logout: %v", err)
	}
	if got.SID != "session-42" || got.Subject != "" {
		t.Errorf("got Subject=%q SID=%q", got.Subject, got.SID)
	}
}

func TestVerifyLogoutToken_NoExpRequired(t *testing.T) {
	idp := newFakeIdP(t)
	defer idp.Close()
	v := newVerifier(idp, nil)

	claims := baseLogoutClaims(idp, "mychat-client")
	if _, ok := claims["exp"]; ok {
		t.Fatal("logout claims should not contain exp by default")
	}
	tok := idp.Mint(t, claims)
	if _, err := v.VerifyLogoutToken(context.Background(), tok); err != nil {
		t.Fatalf("logout without exp should verify: %v", err)
	}
}

func TestVerifyLogoutToken_RejectsNonce(t *testing.T) {
	idp := newFakeIdP(t)
	defer idp.Close()
	v := newVerifier(idp, nil)

	claims := baseLogoutClaims(idp, "mychat-client")
	claims["nonce"] = "deadbeef"
	tok := idp.Mint(t, claims)

	if _, err := v.VerifyLogoutToken(context.Background(), tok); err == nil {
		t.Fatal("expected error for token with nonce")
	}
}

func TestVerifyLogoutToken_MissingEvents(t *testing.T) {
	idp := newFakeIdP(t)
	defer idp.Close()
	v := newVerifier(idp, nil)

	claims := baseLogoutClaims(idp, "mychat-client")
	delete(claims, "events")
	tok := idp.Mint(t, claims)

	if _, err := v.VerifyLogoutToken(context.Background(), tok); err == nil {
		t.Fatal("expected error for missing events")
	}
}

func TestVerifyLogoutToken_WrongEventsKey(t *testing.T) {
	idp := newFakeIdP(t)
	defer idp.Close()
	v := newVerifier(idp, nil)

	claims := baseLogoutClaims(idp, "mychat-client")
	claims["events"] = map[string]any{"http://example.com/some-other-event": map[string]any{}}
	tok := idp.Mint(t, claims)

	if _, err := v.VerifyLogoutToken(context.Background(), tok); err == nil {
		t.Fatal("expected error for wrong events key")
	}
}

func TestVerifyLogoutToken_MissingJTI(t *testing.T) {
	idp := newFakeIdP(t)
	defer idp.Close()
	v := newVerifier(idp, nil)

	claims := baseLogoutClaims(idp, "mychat-client")
	delete(claims, "jti")
	tok := idp.Mint(t, claims)

	if _, err := v.VerifyLogoutToken(context.Background(), tok); err == nil {
		t.Fatal("expected error for missing jti")
	}
}

func TestVerifyLogoutToken_MissingSubAndSid(t *testing.T) {
	idp := newFakeIdP(t)
	defer idp.Close()
	v := newVerifier(idp, nil)

	claims := baseLogoutClaims(idp, "mychat-client")
	delete(claims, "sub")
	tok := idp.Mint(t, claims)

	if _, err := v.VerifyLogoutToken(context.Background(), tok); err == nil {
		t.Fatal("expected error when both sub and sid are absent")
	}
}

func TestVerifyLogoutToken_WrongAudience(t *testing.T) {
	idp := newFakeIdP(t)
	defer idp.Close()
	v := newVerifier(idp, nil)

	tok := idp.Mint(t, baseLogoutClaims(idp, "someone-else"))
	if _, err := v.VerifyLogoutToken(context.Background(), tok); err == nil {
		t.Fatal("expected error for wrong audience")
	}
}

func TestVerifyLogoutToken_BadSignature(t *testing.T) {
	idp := newFakeIdP(t)
	defer idp.Close()
	v := newVerifier(idp, nil)

	tok := idp.Mint(t, baseLogoutClaims(idp, "mychat-client"))
	parts := strings.Split(tok, ".")
	sig := []byte(parts[2])
	sig[0] ^= 0x01
	parts[2] = string(sig)
	tampered := strings.Join(parts, ".")
	if _, err := v.VerifyLogoutToken(context.Background(), tampered); err == nil {
		t.Fatal("expected error for tampered signature")
	}
}

func TestVerifyLogoutToken_ExpiredExpStillRejected(t *testing.T) {
	idp := newFakeIdP(t)
	defer idp.Close()
	v := newVerifier(idp, nil)

	// Logout tokens don't need exp, but if one is present jwt/v5 still
	// validates it — make sure we don't accidentally bypass that.
	claims := baseLogoutClaims(idp, "mychat-client")
	claims["exp"] = time.Now().Add(-1 * time.Hour).Unix()
	tok := idp.Mint(t, claims)
	if _, err := v.VerifyLogoutToken(context.Background(), tok); err == nil {
		t.Fatal("expected error for token with expired exp")
	}
}

func TestWalk_DottedPath(t *testing.T) {
	claims := jwt.MapClaims{
		"realm_access": map[string]any{
			"roles": []any{"a", "b"},
		},
	}
	got := lookupStringSlice(claims, "realm_access.roles")
	if fmt.Sprint(got) != "[a b]" {
		t.Errorf("got %v", got)
	}
	if v := lookupStringSlice(claims, "missing.path"); v != nil {
		t.Errorf("expected nil for missing path, got %v", v)
	}
}
