package rbac

const (
	MANAGER   Role = "manager"
	DEVELOPER Role = "developer"
	VIEWER    Role = "viewer"
)

const (
	PermissionKindRead   PermissionKind = "read"
	PermissionKindWrite  PermissionKind = "write"
	PermissionKindDelete PermissionKind = "delete"
	PermissionKindAssign PermissionKind = "assign"
)

var buildGuardByRole = defineAbilities(func(can, cannot DefineRuleFunc) {
	// scope: Manager
	can(MANAGER, PermissionKindWrite, "Project")
	can(MANAGER, PermissionKindDelete, "Project")
	can(MANAGER, PermissionKindAssign, "Task")
	can(MANAGER, PermissionKindRead, "Project")
	// scope: Developer
	can(DEVELOPER, PermissionKindWrite, "CodeRepository")
	can(DEVELOPER, PermissionKindAssign, "Task")
	can(DEVELOPER, PermissionKindRead, "Project")
	cannot(DEVELOPER, PermissionKindDelete, "Project")
	// scope: Viewer
	can(VIEWER, PermissionKindRead, "Project")
	can(VIEWER, PermissionKindRead, "Task")
	cannot(VIEWER, PermissionKindWrite, "CodeRepository")
	cannot(VIEWER, PermissionKindAssign, "Task")
})
