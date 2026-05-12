// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package model

// Keycloak JWT bearer-auth identifiers. Kept in their own file to minimise
// the surface area touched in upstream files and ease future merges.
const (
	UserAuthServiceKeycloak = "keycloak"
	SessionTypeKeycloakJWT  = "KeycloakJWT"
)
