package carbon

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// User is the signed-in caller (each app's spec: components/schemas/User).
type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type userKey struct{}

// NewVerifier trusts ID tokens from the Identity Platform pool in projectID
// (issuer https://securetoken.google.com/<project>, audience <project>).
func NewVerifier(ctx context.Context, projectID string) (*oidc.IDTokenVerifier, error) {
	p, err := oidc.NewProvider(ctx, "https://securetoken.google.com/"+projectID)
	if err != nil {
		return nil, err
	}
	return p.Verifier(&oidc.Config{ClientID: projectID}), nil
}

// RequireUser rejects requests without a valid bearer ID token for a verified
// email (each app's spec: components/securitySchemes/bearerAuth).
func RequireUser(v *oidc.IDTokenVerifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, raw, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		if !strings.EqualFold(scheme, "Bearer") || raw == "" {
			unauthorized(w)
			return
		}
		tok, err := v.Verify(r.Context(), raw)
		if err != nil {
			unauthorized(w)
			return
		}
		var c struct {
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
		}
		if err := tok.Claims(&c); err != nil || c.Email == "" || !c.EmailVerified {
			unauthorized(w)
			return
		}
		ctx := context.WithValue(r.Context(), userKey{}, User{ID: tok.Subject, Email: c.Email})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireApp rejects users who may not use app: the central "who can use
// which app" control (app:<app> in OpenFGA).
func requireApp(f *FGA, app, name string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok, err := f.Check(r.Context(), UserRef(r), "user", "app:"+app)
		if err != nil {
			ServerError(w, r, err)
			return
		}
		if !ok {
			WriteError(w, http.StatusForbidden, "you don't have access to "+name)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// CurrentUser is the caller RequireUser verified.
func CurrentUser(r *http.Request) User {
	return r.Context().Value(userKey{}).(User)
}

// UserRef is the caller as an OpenFGA user: "user:<uid>".
func UserRef(r *http.Request) string { return "user:" + CurrentUser(r).ID }

// unauthorized writes components/responses/Unauthorized.
func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	WriteError(w, http.StatusUnauthorized, "missing, invalid or expired bearer token")
}

// WriteError writes components/schemas/Error: {"message": ...}.
func WriteError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, map[string]string{"message": message})
}

// ServerError logs the cause and returns components/responses/Error.
func ServerError(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("%s %s: %v", r.Method, r.URL.Path, err)
	WriteError(w, http.StatusInternalServerError, "internal error")
}

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
