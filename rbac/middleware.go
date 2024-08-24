package rbac

import (
	"context"
	"net/http"
)

const guardKey = "guard"

func getGuard(ctx context.Context) GuardFunc {
	if guard, ok := ctx.Value(guardKey).(GuardFunc); ok {
		return guard
	}
	return func(action PermissionKind, resource string) bool {
		return false
	}
}

func RBACMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := Role(r.Header.Get("x-user-role"))
		if role == "" {
			role = VIEWER
		}
		guard := buildGuardByRole(role)
		r = r.WithContext(context.WithValue(r.Context(), guardKey, guard))
		next.ServeHTTP(w, r)
	})
}

func Authorize(action PermissionKind, resource string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		guard := getGuard(r.Context())
		if guard(action, resource) {
			handler(w, r)
		} else {
			http.Error(w, "Forbidden", http.StatusForbidden)
		}
	}
}
