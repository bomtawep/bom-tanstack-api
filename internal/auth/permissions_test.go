// internal/auth/permissions_test.go
package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasPermission_AdminHasAllUserPermissions(t *testing.T) {
	for _, p := range []Permission{PermUserCreate, PermUserRead, PermUserUpdate, PermUserDelete} {
		assert.True(t, HasPermission(RoleAdmin, p), "admin should have %s", p)
	}
}

func TestHasPermission_ManagerOnlyHasRead(t *testing.T) {
	assert.True(t, HasPermission(RoleManager, PermUserRead))
	assert.False(t, HasPermission(RoleManager, PermUserCreate))
	assert.False(t, HasPermission(RoleManager, PermUserUpdate))
	assert.False(t, HasPermission(RoleManager, PermUserDelete))
}

func TestHasPermission_StaffAndViewerHaveNoUserPermissions(t *testing.T) {
	for _, role := range []Role{RoleStaff, RoleViewer} {
		for _, p := range []Permission{PermUserCreate, PermUserRead, PermUserUpdate, PermUserDelete} {
			assert.False(t, HasPermission(role, p), "%s should not have %s", role, p)
		}
	}
}

func TestHasPermission_UnknownRoleHasNoPermissions(t *testing.T) {
	assert.False(t, HasPermission(Role("nonexistent"), PermUserRead))
}
