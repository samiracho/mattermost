// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package model

import "net/http"

// KeycloakSettings configures direct acceptance of Keycloak-issued JWT
// access tokens as Mattermost bearer credentials. It is independent of the
// OAuth code-flow handled by OpenIdSettings / GitLabSettings: when enabled,
// any request carrying `Authorization: Bearer <jwt>` is verified against
// Keycloak's JWKS and resolved to a Mattermost user (JIT-provisioned on
// first sight if JITProvisioning is true).
//
// This struct lives in its own file so that the merge surface against
// upstream config.go remains a single field declaration plus two wiring
// lines in SetDefaults/IsValid.
type KeycloakSettings struct {
	Enable             *bool   `access:"authentication_openid"`
	DiscoveryEndpoint  *string `access:"authentication_openid"` // telemetry: none
	JWKSEndpoint       *string `access:"authentication_openid"` // telemetry: none; optional override, derived from discovery if empty
	Issuer             *string `access:"authentication_openid"` // telemetry: none; expected "iss" claim
	Audience           *string `access:"authentication_openid"` // telemetry: none; expected "aud" claim (Keycloak client_id)
	UserIDClaim        *string `access:"authentication_openid"` // telemetry: none; default "sub"
	EmailClaim         *string `access:"authentication_openid"` // telemetry: none; default "email"
	UsernameClaim      *string `access:"authentication_openid"` // telemetry: none; default "preferred_username"
	NameClaim          *string `access:"authentication_openid"` // telemetry: none; default "name"
	ClockSkewSeconds   *int    `access:"authentication_openid"`
	JITProvisioning    *bool   `access:"authentication_openid"`
	JWKSRefreshMinutes *int    `access:"authentication_openid"`

	// Role mapping. RolesClaim is a dotted JSON path applied to the JWT
	// claims to extract a []string of Keycloak role names (default
	// "realm_access.roles"). AdminRoles is a comma-separated set of
	// Keycloak role names that, when present in the token, grant
	// system_admin in the synthetic session. DefaultRoles is the baseline
	// Mattermost role set every authenticated JWT user receives (default
	// "system_user").
	RolesClaim   *string `access:"authentication_openid"` // telemetry: none
	AdminRoles   *string `access:"authentication_openid"` // telemetry: none
	DefaultRoles *string `access:"authentication_openid"` // telemetry: none
}

func (s *KeycloakSettings) SetDefaults() {
	if s.Enable == nil {
		s.Enable = NewPointer(false)
	}
	if s.DiscoveryEndpoint == nil {
		s.DiscoveryEndpoint = NewPointer("")
	}
	if s.JWKSEndpoint == nil {
		s.JWKSEndpoint = NewPointer("")
	}
	if s.Issuer == nil {
		s.Issuer = NewPointer("")
	}
	if s.Audience == nil {
		s.Audience = NewPointer("")
	}
	if s.UserIDClaim == nil {
		s.UserIDClaim = NewPointer("sub")
	}
	if s.EmailClaim == nil {
		s.EmailClaim = NewPointer("email")
	}
	if s.UsernameClaim == nil {
		s.UsernameClaim = NewPointer("preferred_username")
	}
	if s.NameClaim == nil {
		s.NameClaim = NewPointer("name")
	}
	if s.ClockSkewSeconds == nil {
		s.ClockSkewSeconds = NewPointer(30)
	}
	if s.JITProvisioning == nil {
		s.JITProvisioning = NewPointer(true)
	}
	if s.JWKSRefreshMinutes == nil {
		s.JWKSRefreshMinutes = NewPointer(60)
	}
	if s.RolesClaim == nil {
		s.RolesClaim = NewPointer("realm_access.roles")
	}
	if s.AdminRoles == nil {
		s.AdminRoles = NewPointer("")
	}
	if s.DefaultRoles == nil {
		s.DefaultRoles = NewPointer("system_user")
	}
}

func (s *KeycloakSettings) IsValid() *AppError {
	if s.Enable == nil || !*s.Enable {
		return nil
	}
	if s.Issuer == nil || *s.Issuer == "" {
		return NewAppError("Config.IsValid", "model.config.is_valid.keycloak_issuer.app_error", nil, "", http.StatusBadRequest)
	}
	if s.Audience == nil || *s.Audience == "" {
		return NewAppError("Config.IsValid", "model.config.is_valid.keycloak_audience.app_error", nil, "", http.StatusBadRequest)
	}
	hasDiscovery := s.DiscoveryEndpoint != nil && *s.DiscoveryEndpoint != ""
	hasJWKS := s.JWKSEndpoint != nil && *s.JWKSEndpoint != ""
	if !hasDiscovery && !hasJWKS {
		return NewAppError("Config.IsValid", "model.config.is_valid.keycloak_endpoint.app_error", nil, "", http.StatusBadRequest)
	}
	if s.ClockSkewSeconds != nil && *s.ClockSkewSeconds < 0 {
		return NewAppError("Config.IsValid", "model.config.is_valid.keycloak_clock_skew.app_error", nil, "", http.StatusBadRequest)
	}
	if s.JWKSRefreshMinutes != nil && *s.JWKSRefreshMinutes <= 0 {
		return NewAppError("Config.IsValid", "model.config.is_valid.keycloak_jwks_refresh.app_error", nil, "", http.StatusBadRequest)
	}
	return nil
}
