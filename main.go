package main

import (
	"net/http"
	"rbacoon/rbac"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	r := chi.NewRouter()

	r.Use(middleware.StripSlashes)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Use(rbac.RBACMiddleware)

	r.Post("/projects",
		rbac.Authorize(
			rbac.PermissionKindWrite,
			"Project",
			func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("Project created successfully"))
			},
		),
	)

	r.Put("/tasks/{taskID}/assign",
		rbac.Authorize(
			rbac.PermissionKindAssign,
			"Task",
			func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("Task assigned successfully"))
			},
		),
	)

	r.Get("/projects/{projectID}",
		rbac.Authorize(rbac.PermissionKindRead,
			"Project",
			func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("Project details displayed"))
			},
		),
	)

	http.ListenAndServe(":3333", r)
}
