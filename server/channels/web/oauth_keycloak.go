// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

// This file isolates the Keycloak OIDC back-channel logout handler. The
// endpoint accepts a signed `logout_token` POSTed by Keycloak when a user's
// session is terminated and evicts all of that user's cached synthetic JWT
// sessions across the cluster. Kept in its own file (matching the pattern
// in channels/app/session_keycloak.go and public/model/config_keycloak.go)
// so the upstream-touching edit in oauth.go is a single route line.

package web

import (
	"encoding/json"
	"net/http"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/mlog"
)

func handleKeycloakBackchannelLogout(c *Context, w http.ResponseWriter, r *http.Request) {
	cfg := c.App.Config().KeycloakSettings
	if cfg.Enable == nil || !*cfg.Enable {
		http.NotFound(w, r)
		return
	}

	auditRec := c.MakeAuditRecord("keycloak_backchannel_logout", model.AuditStatusFail)
	defer c.LogAuditRec(auditRec)

	if err := r.ParseForm(); err != nil {
		writeLogoutError(w, c.Logger, http.StatusBadRequest, "invalid_request", "could not parse form body", err)
		return
	}
	tokenString := r.FormValue("logout_token")
	if tokenString == "" {
		writeLogoutError(w, c.Logger, http.StatusBadRequest, "invalid_request", "missing logout_token", nil)
		return
	}

	v := c.App.GetOrBuildKeycloakVerifier(&cfg)
	claims, err := v.VerifyLogoutToken(r.Context(), tokenString)
	if err != nil {
		writeLogoutError(w, c.Logger, http.StatusBadRequest, "invalid_request", "logout token verification failed", err)
		return
	}
	auditRec.AddMeta("jti", claims.JTI)
	if claims.SID != "" {
		auditRec.AddMeta("sid", claims.SID)
	}

	// v1: user-level eviction. A logout token carrying only `sid` (no `sub`)
	// cannot be mapped to a Mattermost user without a sid→session index,
	// which we have intentionally deferred. Reject it explicitly so the IdP
	// surfaces the misconfiguration rather than silently no-op'ing.
	if claims.Subject == "" {
		writeLogoutError(w, c.Logger, http.StatusBadRequest, "invalid_request", "logout token must carry 'sub' (sid-only logout is not supported)", nil)
		return
	}
	auditRec.AddMeta("sub", claims.Subject)

	user, appErr := c.App.GetUserByAuth(&claims.Subject, model.UserAuthServiceKeycloak)
	if appErr != nil || user == nil {
		// Per OIDC back-channel logout §2.8, the IdP should not be able to
		// probe for user existence; treat "not found" as a successful
		// no-op. Cache eviction was the only side-effect anyway.
		w.Header().Set("Cache-Control", "no-store")
		auditRec.AddMeta("result", "user_not_found")
		auditRec.Success()
		w.WriteHeader(http.StatusOK)
		return
	}
	auditRec.AddMeta("user_id", user.Id)

	// Scope gating: a Keycloak backchannel logout_token can carry sub, sid,
	// or both (OIDC Back-Channel Logout §2.4). We persist the user-wide
	// "tokens not before" timestamp ONLY when the payload is sub-only,
	// because that's KC's emission shape for the admin /users/:id/logout
	// path (scope='all' / kick / disable / hard-delete). A sid-present
	// payload — either sid-only (rejected earlier) or sub+sid — signals a
	// single-session end_session and MUST NOT log the user out of other
	// devices. For those, cache eviction alone (below) is correct: the
	// signed-out device has already thrown away its tokens, so simply
	// dropping its cached synthetic session is sufficient.
	if claims.SID == "" {
		nowMs := model.GetMillis()
		if mErr := c.App.MarkKeycloakTokensRevoked(c.AppContext, user, nowMs); mErr != nil {
			c.Logger.Warn("failed to mark keycloak tokens revoked", mlog.Err(mErr))
		}
		auditRec.AddMeta("revoked_at_ms", nowMs)
	} else {
		auditRec.AddMeta("scope", "single_session")
	}

	// ClearSessionCacheForUser purges all sessions for the user from the
	// local cache and broadcasts ClusterEventClearSessionCacheForUser to
	// peer nodes — so JWT-session entries get evicted cluster-wide. This
	// also evicts PAT / regular sessions for the same user, which is fine:
	// the persisted ones will be re-hydrated on the next request from the
	// session store. Run AFTER the Props write so any request racing past
	// the cache eviction re-mints via tryKeycloakJWTSession and sees the
	// fresh Props value on its user lookup.
	c.App.ClearSessionCacheForUser(user.Id)

	w.Header().Set("Cache-Control", "no-store")
	auditRec.Success()
	w.WriteHeader(http.StatusOK)
}

// writeLogoutError emits an OIDC-shaped error response and logs at debug
// (the source of these requests is an external IdP — bad input is not a
// server problem and shouldn't spam the warn/error log).
func writeLogoutError(w http.ResponseWriter, logger mlog.LoggerIFace, status int, code, desc string, cause error) {
	if cause != nil {
		logger.Debug("Keycloak back-channel logout rejected", mlog.String("code", code), mlog.String("desc", desc), mlog.Err(cause))
	} else {
		logger.Debug("Keycloak back-channel logout rejected", mlog.String("code", code), mlog.String("desc", desc))
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": desc,
	})
}
