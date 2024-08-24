package rbac

type Role string
type PermissionKind string

type Ability struct {
	Action   string
	Resource string
}

type AbilityMap map[Role]map[string]bool

type DefineRuleFunc func(role Role, action PermissionKind, resource string)
type DefineCallback func(can, cannot DefineRuleFunc)
type GuardFunc func(action PermissionKind, resource string) bool

func defineAbilities(defineFunc DefineCallback) func(role Role) GuardFunc {
	abilities := make(AbilityMap)

	createKey := func(action PermissionKind, resource string) string {
		return string(action) + "::" + resource
	}

	can := func(role Role, action PermissionKind, resource string) {
		if _, exists := abilities[role]; !exists {
			abilities[role] = make(map[string]bool)
		}
		abilities[role][createKey(action, resource)] = true
	}

	cannot := func(role Role, action PermissionKind, resource string) {
		if _, exists := abilities[role]; !exists {
			abilities[role] = make(map[string]bool)
		}
		abilities[role][createKey(action, resource)] = false
	}

	defineFunc(can, cannot)

	return func(role Role) GuardFunc {
		return func(action PermissionKind, resource string) bool {
			if allowed, exists := abilities[role][createKey(action, resource)]; exists {
				return allowed
			}
			return false
		}
	}
}
