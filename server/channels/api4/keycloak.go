// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

// API endpoints supporting the Keycloak-JWT bearer integration (see
// channels/app/keycloakauth/). Kept in its own file so the merge surface
// against upstream is a single InitKeycloak() call from api.go.

package api4

import (
	"net/http"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/mlog"
)

func (api *API) InitKeycloak() {
	// POST /api/v4/users/{user_id}/keycloak/tokens/revoke — server-to-server
	// endpoint for api-management's scope='all' / kick / disable / hard-delete
	// paths. Persists user.Props[KeycloakTokensNotBeforePropKey] = now so the
	// JWT-bearer verifier (tryKeycloakJWTSession) rejects pre-revocation
	// access tokens on next request, then evicts cached synthetic sessions
	// cluster-wide.
	//
	// Decoupled from /oauth/keycloak/backchannel_logout on purpose: KC fires
	// the backchannel for every session-ending event (end_session, admin
	// /users/:id/logout, idle timeout), and when backchannel.logout.session.required
	// is false on the client there's no way to tell scope='this' apart from
	// scope='all' in the resulting logout_token — so we let api-management
	// be the source of truth for "user-wide revoke" and call this endpoint
	// only when it has decided so.
	api.BaseRoutes.User.Handle("/keycloak/tokens/revoke", api.APISessionRequired(revokeKeycloakUserTokens)).Methods(http.MethodPost)
}

func revokeKeycloakUserTokens(c *Context, w http.ResponseWriter, r *http.Request) {
	cfg := c.App.Config().KeycloakSettings
	if cfg.Enable == nil || !*cfg.Enable {
		http.NotFound(w, r)
		return
	}

	c.RequireUserId()
	if c.Err != nil {
		return
	}
	// system_admin only — api-management calls this with the
	// mattermost-service client JWT that carries the mattermost-admin realm
	// role, which the verifier maps to system_admin per-request.
	if !c.App.SessionHasPermissionTo(*c.AppContext.Session(), model.PermissionManageSystem) {
		c.SetPermissionError(model.PermissionManageSystem)
		return
	}

	auditRec := c.MakeAuditRecord("keycloak_revoke_user_tokens", model.AuditStatusFail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("user_id", c.Params.UserId)

	user, appErr := c.App.GetUser(c.Params.UserId)
	if appErr != nil {
		c.Err = appErr
		return
	}
	if user.AuthService != model.UserAuthServiceKeycloak {
		// Refuse to write Props on non-keycloak users — the gate is only
		// consulted in the JWT-bearer path, so writing it elsewhere would
		// be dead state at best, confusing at worst.
		c.Err = model.NewAppError("revokeKeycloakUserTokens", "api.user.revoke_keycloak_tokens.wrong_auth_service.app_error", nil, "auth_service="+user.AuthService, http.StatusBadRequest)
		return
	}

	nowMs := model.GetMillis()
	if appErr := c.App.MarkKeycloakTokensRevoked(c.AppContext, user, nowMs); appErr != nil {
		c.Err = appErr
		return
	}
	auditRec.AddMeta("revoked_at_ms", nowMs)

	// Evict cached synthetic sessions cluster-wide so the next request
	// re-mints via tryKeycloakJWTSession and sees the fresh Props value.
	// Run AFTER the Props write to close the race window where an
	// in-flight request slipping past the cache evict could re-cache the
	// pre-revocation session.
	c.App.ClearSessionCacheForUser(user.Id)

	c.Logger.Info("Keycloak tokens revoked", mlog.String("user_id", user.Id), mlog.Int("revoked_at_ms", nowMs))
	auditRec.Success()
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
