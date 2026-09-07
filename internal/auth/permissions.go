// internal/auth/permissions.go
package auth

type Role string

const (
	RoleAdmin   Role = "admin"
	RoleManager Role = "manager"
	RoleStaff   Role = "staff"
	RoleViewer  Role = "viewer"
)

type Permission string

const (
	PermUserCreate Permission = "user:create"
	PermUserRead   Permission = "user:read"
	PermUserUpdate Permission = "user:update"
	PermUserDelete Permission = "user:delete"
)

var rolePermissions = map[Role][]Permission{
	RoleAdmin:   {PermUserCreate, PermUserRead, PermUserUpdate, PermUserDelete},
	RoleManager: {PermUserRead},
	RoleStaff:   {},
	RoleViewer:  {},
}

func HasPermission(role Role, perm Permission) bool {
	for _, p := range rolePermissions[role] {
		if p == perm {
			return true
		}
	}
	return false
}
