// Provides email magic-link authentication for Go applications.
//
// An application constructs one AuthService, mounts its handlers, and wraps protected routes with RequireAuth.
// The identity is the normalised email address of the user.
// There are no passwords, users, or profiles in this project.
// However the application may use the identity as the basis for profiles as required.
//
// Sessions are persisted through sessionstore.SessionStore.
package auth
