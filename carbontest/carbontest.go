// Package carbontest stands in for Identity Platform in tests and connects to
// the real Postgres and OpenFGA that CI runs next to them.
//
// Integration tests run when TEST_DATABASE_URL and TEST_OPENFGA_URL are set;
// they're skipped otherwise, except in CI, where a missing one fails:
//
//	docker run -d --rm -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:18
//	docker run -d --rm -p 8080:8080 openfga/openfga:v1.22.0 run
//	TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable \
//	TEST_OPENFGA_URL=http://localhost:8080 go test ./...
package carbontest

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FairShare-Software/carbon"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Project is the Identity Platform project test tokens are issued for.
const Project = "test-project"

// Key signs tokens Verifier trusts.
var Key = mustKey()

func mustKey() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}

// Verifier trusts tokens signed with Key for Project, like carbon.NewVerifier.
func Verifier() *oidc.IDTokenVerifier {
	keys := &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&Key.PublicKey}}
	return oidc.NewVerifier("https://securetoken.google.com/"+Project, keys, &oidc.Config{ClientID: Project})
}

// Claims are an Identity Platform ID token's.
type Claims struct {
	jwt.Claims
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified"`
}

// ValidClaims are uid's for an hour, with a verified <uid>@example.com.
func ValidClaims(uid string) Claims {
	now := time.Now()
	return Claims{
		Claims: jwt.Claims{
			Issuer:   "https://securetoken.google.com/" + Project,
			Audience: jwt.Audience{Project},
			Subject:  uid,
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
		},
		Email:         uid + "@example.com",
		EmailVerified: true,
	}
}

// Sign returns c as a signed ID token.
func Sign(t testing.TB, key *rsa.PrivateKey, c Claims) string {
	t.Helper()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Signed(s).Claims(c).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// Bearer is an Authorization header for uid (<uid>@example.com).
func Bearer(t testing.TB, uid string) string {
	return "Bearer " + Sign(t, Key, ValidClaims(uid))
}

// AllowAll is a stand-in OpenFGA that allows every check and lists nothing, for
// tests of authentication alone.
func AllowAll(t testing.TB) *carbon.FGA {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"allowed":true,"objects":[]}`))
	}))
	t.Cleanup(srv.Close)
	return &carbon.FGA{HTTP: srv.Client(), URL: srv.URL, Store: "test"}
}

// env returns TEST_<name>, skipping the test without it (failing in CI).
func env(t testing.TB, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI must set %s", name) // never skip silently in CI
		}
		t.Skipf("set %s to run integration tests", name)
	}
	return v
}

// DB connects to TEST_DATABASE_URL and applies db/migrations. Tables keep rows
// from earlier tests: truncate the ones a test depends on.
func DB(t testing.TB) *pgxpool.Pool {
	t.Helper()
	url := env(t, "TEST_DATABASE_URL")
	ctx := context.Background()
	db, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if err := carbon.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	return db
}

// FGA creates a fresh store at TEST_OPENFGA_URL with the central model
// (testdata/model.json, from iron's authz/model.fga) and tuples.
func FGA(t testing.TB, tuples ...carbon.Tuple) *carbon.FGA {
	t.Helper()
	url := env(t, "TEST_OPENFGA_URL")
	ctx := context.Background()
	f := &carbon.FGA{HTTP: http.DefaultClient, URL: url}
	var store struct{ ID string }
	if err := f.Do(ctx, http.MethodPost, "/stores", map[string]string{"name": fmt.Sprintf("test-%d", time.Now().UnixNano())}, &store); err != nil {
		t.Fatal(err)
	}
	f.Store = store.ID
	model, err := os.ReadFile("testdata/model.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Do(ctx, http.MethodPost, "/stores/"+f.Store+"/authorization-models", json.RawMessage(model), nil); err != nil {
		t.Fatal(err)
	}
	if len(tuples) > 0 {
		if err := f.Write(ctx, tuples...); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// Identity stands in for the Identity Platform admin API. A user's ID is the
// part of their email before "@"; users in known exist from the start. Sign-in
// links it sends are appended to *sent as "<email> <continueUrl>".
func Identity(t testing.TB, sent *[]string, known ...string) *carbon.Identity {
	var mu sync.Mutex
	users := map[string]bool{}
	for _, uid := range known {
		users[uid] = true
	}
	found := func(uid string) []map[string]string {
		if !users[uid] {
			return nil
		}
		return []map[string]string{{"localId": uid, "email": uid + "@example.com"}}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var body struct {
			Email       any      `json:"email"`
			LocalID     []string `json:"localId"`
			RequestType string   `json:"requestType"`
			ContinueURL string   `json:"continueUrl"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		switch r.URL.Path {
		case "/projects/" + Project + "/accounts:lookup":
			out := []map[string]string{}
			if emails, ok := body.Email.([]any); ok {
				out = append(out, found(strings.Split(emails[0].(string), "@")[0])...)
			}
			for _, uid := range body.LocalID {
				out = append(out, found(uid)...)
			}
			json.NewEncoder(w).Encode(map[string]any{"users": out})
		case "/projects/" + Project + "/accounts":
			uid := strings.Split(body.Email.(string), "@")[0]
			users[uid] = true
			fmt.Fprintf(w, `{"localId":%q}`, uid)
		case "/projects/" + Project + "/accounts:sendOobCode":
			if body.RequestType != "EMAIL_SIGNIN" {
				http.Error(w, "unexpected requestType", http.StatusBadRequest)
				return
			}
			*sent = append(*sent, body.Email.(string)+" "+body.ContinueURL)
			fmt.Fprintf(w, `{"email":%q}`, body.Email)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return &carbon.Identity{HTTP: srv.Client(), BaseURL: srv.URL, Project: Project}
}
