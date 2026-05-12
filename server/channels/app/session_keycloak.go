// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

// This file isolates everything related to accepting Keycloak-issued JWTs
// as Mattermost bearer credentials. The intent is to keep the merge
// surface against upstream session.go to a single 3-line insertion in
// (*App).GetSession plus a one-line idle-timeout exclusion; all of the
// substantive logic lives here.

package app

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/mlog"
	"github.com/mattermost/mattermost/server/public/shared/request"
	"github.com/mattermost/mattermost/server/v8/channels/app/keycloakauth"
)

// Package-level verifier singleton. Held here (rather than on Channels or
// Server) so that adding/removing the feature touches zero existing
// structs.
var (
	keycloakVerifierMu          sync.Mutex
	keycloakVerifierFingerprint string
	keycloakVerifier            *keycloakauth.Verifier
)

// tryKeycloakJWTSession is the JWT-bearer branch invoked from GetSession.
// Return contract:
//
//	(session, nil) — token verified, virtual session built and cached.
//	(nil, appErr)  — token looked like a JWT but verification or
//	                  provisioning failed; caller should NOT fall through
//	                  to the PAT path, return the 401 as-is.
//	(nil, nil)     — feature disabled or the bearer token doesn't look
//	                  like a JWT; caller should try the next auth path.
func (a *App) tryKeycloakJWTSession(rctx request.CTX, tokenString string) (*model.Session, *model.AppError) {
	cfg := a.Config().KeycloakSettings
	if cfg.Enable == nil || !*cfg.Enable {
		return nil, nil
	}
	if !keycloakauth.LooksLikeJWT(tokenString) {
		return nil, nil
	}

	v := a.GetOrBuildKeycloakVerifier(&cfg)
	claims, err := v.Verify(rctx.Context(), tokenString)
	if err != nil {
		rctx.Logger().Debug("Keycloak JWT verification failed", mlog.Err(err))
		return nil, model.NewAppError("tryKeycloakJWTSession", "api.context.invalid_token.error", map[string]any{"Token": "<jwt>"}, "keycloak: "+err.Error(), http.StatusUnauthorized)
	}

	user, appErr := a.findOrProvisionKeycloakUser(rctx, claims)
	if appErr != nil {
		return nil, appErr
	}
	if user.DeleteAt != 0 {
		return nil, model.NewAppError("tryKeycloakJWTSession", "api.context.invalid_token.error", nil, "keycloak: user is deactivated", http.StatusUnauthorized)
	}

	// Build a synthetic, non-persisted session. The cache layer will
	// hold it for ServiceSettings.SessionCacheInMinutes; once the JWT's
	// own exp passes, model.Session.IsExpired() short-circuits subsequent
	// requests in (*App).GetSession.
	session := &model.Session{
		Id:        synthesizeSessionID(tokenString),
		Token:     tokenString,
		UserId:    user.Id,
		Roles:     rolesForJWTSession(claims, user),
		IsOAuth:   false,
		ExpiresAt: claims.ExpiresAt.UnixMilli(),
	}
	session.AddProp(model.SessionPropType, model.SessionTypeKeycloakJWT)
	if user.IsBot {
		session.AddProp(model.SessionPropIsBot, model.SessionPropIsBotValue)
	}
	session.AddProp(model.SessionPropIsGuest, strconv.FormatBool(user.IsGuest()))

	if err := a.ch.srv.platform.AddSessionToCache(session); err != nil {
		rctx.Logger().Warn("Failed to add Keycloak JWT session to cache", mlog.Err(err), mlog.String("user_id", user.Id))
	}
	return session, nil
}

// IsKeycloakJWTSession reports whether a session was produced by the
// Keycloak JWT path. Exposed so the GetSession idle-timeout check can
// skip these (their LastActivityAt is always zero by design — the JWT
// itself carries the lifetime).
func IsKeycloakJWTSession(s *model.Session) bool {
	return s != nil && s.Props[model.SessionPropType] == model.SessionTypeKeycloakJWT
}

// --- verifier lifecycle -----------------------------------------------

// GetOrBuildKeycloakVerifier returns the shared Keycloak JWT verifier,
// rebuilding it lazily if the verifier-relevant config fields have changed.
// Exported so the back-channel logout endpoint in package web can reuse the
// exact same JWKS cache and config snapshot as the bearer-token path.
func (a *App) GetOrBuildKeycloakVerifier(cfg *model.KeycloakSettings) *keycloakauth.Verifier {
	fp := keycloakFingerprint(cfg)
	keycloakVerifierMu.Lock()
	defer keycloakVerifierMu.Unlock()
	if keycloakVerifier != nil && keycloakVerifierFingerprint == fp {
		return keycloakVerifier
	}
	keycloakVerifier = keycloakauth.New(keycloakauth.ConfigFromModel(cfg))
	keycloakVerifierFingerprint = fp
	return keycloakVerifier
}

// keycloakFingerprint summarises only those config fields the Verifier
// actually depends on, so rotating an unrelated setting doesn't force a
// rebuild (and drop the JWKS cache).
func keycloakFingerprint(s *model.KeycloakSettings) string {
	h := sha256.New()
	add := func(p *string) {
		if p != nil {
			h.Write([]byte(*p))
		}
		h.Write([]byte{0})
	}
	addInt := func(p *int) {
		if p != nil {
			_, _ = h.Write([]byte(strconv.Itoa(*p)))
		}
		h.Write([]byte{0})
	}
	add(s.DiscoveryEndpoint)
	add(s.JWKSEndpoint)
	add(s.Issuer)
	add(s.Audience)
	add(s.UserIDClaim)
	add(s.EmailClaim)
	add(s.UsernameClaim)
	add(s.NameClaim)
	add(s.RolesClaim)
	add(s.AdminRoles)
	add(s.DefaultRoles)
	addInt(s.ClockSkewSeconds)
	addInt(s.JWKSRefreshMinutes)
	return hex.EncodeToString(h.Sum(nil))
}

// --- user provisioning ------------------------------------------------

func (a *App) findOrProvisionKeycloakUser(rctx request.CTX, claims *keycloakauth.VerifiedClaims) (*model.User, *model.AppError) {
	authData := claims.Subject

	if existing, err := a.ch.srv.userService.GetUserByAuth(&authData, model.UserAuthServiceKeycloak); err == nil && existing != nil {
		return existing, nil
	}

	jitEnabled := a.Config().KeycloakSettings.JITProvisioning != nil && *a.Config().KeycloakSettings.JITProvisioning
	if !jitEnabled {
		return nil, model.NewAppError("findOrProvisionKeycloakUser", "api.context.invalid_token.error", nil, "keycloak: user not provisioned and JIT disabled", http.StatusUnauthorized)
	}

	if !*a.Config().TeamSettings.EnableUserCreation {
		return nil, model.NewAppError("findOrProvisionKeycloakUser", "api.user.create_user.disabled.app_error", nil, "", http.StatusUnauthorized)
	}

	// If a user with this email already exists under a different auth
	// service, mirror CreateOAuthUser's policy: refuse rather than
	// silently re-key them.
	if claims.Email != "" {
		if existingByEmail, _ := a.ch.srv.userService.GetUserByEmail(claims.Email); existingByEmail != nil {
			if existingByEmail.AuthService == model.UserAuthServiceKeycloak {
				// Race: created between the GetByAuth and this lookup.
				return existingByEmail, nil
			}
			return nil, model.NewAppError("findOrProvisionKeycloakUser", "api.user.create_oauth_user.already_attached.app_error", map[string]any{"Service": model.UserAuthServiceKeycloak, "Auth": existingByEmail.AuthService}, "email="+claims.Email, http.StatusUnauthorized)
		}
	}

	username := pickUsername(rctx.Logger(), claims)
	for taken := true; taken; {
		taken = a.ch.srv.userService.IsUsernameTaken(username)
		if taken {
			username = username + model.NewId()[:6]
		}
	}

	first, last := splitName(claims.Name)
	newUser := &model.User{
		Username:      username,
		Email:         claims.Email,
		EmailVerified: true,
		AuthService:   model.UserAuthServiceKeycloak,
		AuthData:      &authData,
		FirstName:     first,
		LastName:      last,
		Roles:         claims.MattermostRoles,
	}

	created, appErr := a.CreateUser(rctx, newUser)
	if appErr != nil {
		return nil, appErr
	}
	rctx.Logger().Info("Provisioned Mattermost user from Keycloak JWT", mlog.String("user_id", created.Id), mlog.String("auth_data", authData))
	return created, nil
}

// rolesForJWTSession returns the role string to attach to the synthetic
// session. The JWT's mapped roles are authoritative per-request, so
// admin removal in Keycloak takes effect on the next request without any
// DB write. We fall back to the user's persisted Roles if the JWT didn't
// carry any (which shouldn't happen because mapRoles always seeds with
// DefaultRoles, but defence in depth is cheap).
func rolesForJWTSession(claims *keycloakauth.VerifiedClaims, user *model.User) string {
	if claims.MattermostRoles != "" {
		return claims.MattermostRoles
	}
	return user.GetRawRoles()
}

// --- helpers ----------------------------------------------------------

func synthesizeSessionID(tokenString string) string {
	sum := sha256.Sum256([]byte("kc-jwt|" + tokenString))
	return hex.EncodeToString(sum[:13]) // 26 hex chars, matches model.NewId() length
}

func pickUsername(logger mlog.LoggerIFace, c *keycloakauth.VerifiedClaims) string {
	candidates := []string{c.PreferredUsername, emailLocalPart(c.Email), c.Subject}
	for _, raw := range candidates {
		if raw == "" {
			continue
		}
		clean := model.CleanUsername(logger, raw)
		if clean != "" {
			return clean
		}
	}
	// Last-ditch: use the auth-data sub directly, lightly cleaned.
	return model.CleanUsername(logger, "kc-"+c.Subject)
}

func emailLocalPart(email string) string {
	at := strings.IndexByte(email, '@')
	if at <= 0 {
		return ""
	}
	return email[:at]
}

// splitName naively splits "First Last" into first/last; if the claim is
// a single token, the entire value becomes FirstName.
func splitName(name string) (string, string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", ""
	}
	if i := strings.IndexByte(name, ' '); i > 0 {
		return name[:i], strings.TrimSpace(name[i+1:])
	}
	return name, ""
}
