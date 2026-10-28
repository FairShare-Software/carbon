package carbon_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FairShare-Software/carbon"
	"github.com/FairShare-Software/carbon/carbontest"
	"github.com/go-jose/go-jose/v4/jwt"
)

// testMux is an app whose one route echoes the caller.
func testMux(f *carbon.FGA) *http.ServeMux {
	p := &carbon.Platform{Verifier: carbontest.Verifier(), FGA: f, Web: carbon.WebConfig{ProjectID: "p", APIKey: "k", AuthDomain: "p.firebaseapp.com"}}
	api := http.NewServeMux()
	api.HandleFunc("GET /me", func(w http.ResponseWriter, r *http.Request) {
		carbon.WriteJSON(w, http.StatusOK, carbon.CurrentUser(r))
	})
	return p.Mux("test", "Test", api)
}

func TestRequireUser(t *testing.T) {
	with := func(f func(*carbontest.Claims)) string {
		c := carbontest.ValidClaims("uid-123")
		f(&c)
		return "Bearer " + carbontest.Sign(t, carbontest.Key, c)
	}
	valid := carbontest.Bearer(t, "uid-123")
	tests := []struct {
		name   string
		header string
		want   int
	}{
		{"valid token", valid, http.StatusOK},
		{"lowercase scheme", "bearer " + strings.TrimPrefix(valid, "Bearer "), http.StatusOK},
		{"no header", "", http.StatusUnauthorized},
		{"not bearer", "Basic abc", http.StatusUnauthorized},
		{"garbage token", "Bearer not-a-jwt", http.StatusUnauthorized},
		{"expired", with(func(c *carbontest.Claims) { c.Expiry = jwt.NewNumericDate(time.Now().Add(-time.Minute)) }), http.StatusUnauthorized},
		{"other project audience", with(func(c *carbontest.Claims) { c.Audience = jwt.Audience{"other-project"} }), http.StatusUnauthorized},
		{"other issuer", with(func(c *carbontest.Claims) { c.Issuer = "https://securetoken.google.com/other-project" }), http.StatusUnauthorized},
		{"unverified email", with(func(c *carbontest.Claims) { c.EmailVerified = false }), http.StatusUnauthorized},
		{"no email", with(func(c *carbontest.Claims) { c.Email = "" }), http.StatusUnauthorized},
	}
	mux := testMux(carbontest.AllowAll(t))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/me", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status %d, want %d (%s)", rec.Code, tt.want, rec.Body.String())
			}
			if tt.want == http.StatusUnauthorized {
				if rec.Header().Get("WWW-Authenticate") != "Bearer" {
					t.Fatal("missing WWW-Authenticate: Bearer")
				}
				var e struct{ Message string }
				if json.Unmarshal(rec.Body.Bytes(), &e) != nil || e.Message == "" {
					t.Fatalf("body %q is not an Error", rec.Body.String())
				}
				return
			}
			if body := rec.Body.String(); body != `{"id":"uid-123","email":"uid-123@example.com"}`+"\n" {
				t.Fatalf("body %q", body)
			}
		})
	}
}

func TestWrongSigningKey(t *testing.T) {
	stranger, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+carbontest.Sign(t, stranger, carbontest.ValidClaims("uid-123")))
	rec := httptest.NewRecorder()
	testMux(carbontest.AllowAll(t)).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", rec.Code)
	}
}

// Every route except /health and /config needs a token, including ones that don't exist.
func TestDenyByDefault(t *testing.T) {
	mux := testMux(carbontest.AllowAll(t))
	for path, want := range map[string]int{"/health": 200, "/config": 200, "/anything": 401, "/me": 401} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != want {
			t.Errorf("%s: got %d, want %d", path, rec.Code, want)
		}
	}
}

func TestHandler(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html>"), 0o644)
	h := carbon.Handler(testMux(carbontest.AllowAll(t)), dir, "p.firebaseapp.com")
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}

	if rec := get("/api/config"); rec.Code != http.StatusOK || rec.Body.String() != `{"projectId":"p","apiKey":"k","authDomain":"p.firebaseapp.com","google":false}`+"\n" {
		t.Fatalf("config: %d %q", rec.Code, rec.Body.String())
	}
	if rec := get("/api/me"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("api still needs a token: %d", rec.Code)
	}
	rec := get("/")
	if rec.Code != http.StatusOK || rec.Body.String() != "<!doctype html>" {
		t.Fatalf("web app: %d %q", rec.Code, rec.Body.String())
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-src https://p.firebaseapp.com") {
		t.Fatalf("csp %q", csp)
	}
}

// Against a real OpenFGA: app access, expiry, reads and batched deletes.
func TestFGA(t *testing.T) {
	ctx := context.Background()
	past := time.Now().Add(-time.Hour)
	f := carbontest.FGA(t,
		carbon.Tuple{User: "organization:acme#member", Relation: "user", Object: "app:test"},
		carbon.Tuple{User: "user:ann", Relation: "member", Object: "organization:acme"},
		carbon.Tuple{User: "user:gus", Relation: "user", Object: "app:test", ExpiresAt: &past},
	)

	mux := testMux(f)
	for uid, want := range map[string]int{"ann": 200, "gus": 403, "nobody": 403} {
		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		req.Header.Set("Authorization", carbontest.Bearer(t, uid))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("%s: got %d, want %d", uid, rec.Code, want)
		}
	}

	got, err := f.Read(ctx, "user:gus", "", "app:test")
	if err != nil || len(got) != 1 || got[0].ExpiresAt == nil || !got[0].ExpiresAt.Equal(past.Truncate(time.Second)) {
		t.Fatalf("read %+v, %v", got, err)
	}

	var many []carbon.Tuple
	for i := range 150 {
		many = append(many, carbon.Tuple{User: fmt.Sprintf("user:u%d", i), Relation: "member", Object: "organization:big"})
	}
	for batch := range 2 {
		if err := f.Write(ctx, many[batch*75:(batch+1)*75]...); err != nil {
			t.Fatal(err)
		}
	}
	if ids, err := f.ListObjects(ctx, "user:u149", "member", "organization"); err != nil || len(ids) != 1 || ids[0] != "big" {
		t.Fatalf("list %v, %v", ids, err)
	}
	if err := f.Delete(ctx, many...); err != nil {
		t.Fatal(err)
	}
	if left, err := f.Read(ctx, "", "member", "organization:big"); err != nil || len(left) != 0 {
		t.Fatalf("left %d, %v", len(left), err)
	}
}

// Against the fake Identity Platform: lookups, account creation and links.
func TestIdentity(t *testing.T) {
	ctx := context.Background()
	var sent []string
	id := carbontest.Identity(t, &sent, "ann")
	if uid, created, err := id.EnsureUser(ctx, "ann@example.com"); uid != "ann" || created || err != nil {
		t.Fatalf("existing: %q %v %v", uid, created, err)
	}
	if uid, created, err := id.EnsureUser(ctx, "bo@example.com"); uid != "bo" || !created || err != nil {
		t.Fatalf("new: %q %v %v", uid, created, err)
	}
	if emails, err := id.Emails(ctx, []string{"ann", "bo", "ghost"}); err != nil || len(emails) != 2 || emails["bo"] != "bo@example.com" {
		t.Fatalf("emails %v, %v", emails, err)
	}
	if err := id.SendSignInLink(ctx, "bo@example.com", "https://example.com"); err != nil || strings.Join(sent, ",") != "bo@example.com https://example.com" {
		t.Fatalf("sent %v, %v", sent, err)
	}
}
