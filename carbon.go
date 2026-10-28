// Package carbon is the shared server side of FairShare apps: sign-in with
// Identity Platform, authorization in the central OpenFGA store, Postgres with
// goose migrations, and one origin serving the API at /api and the web app at /.
package carbon

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/cloudsqlconn"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
)

// Platform is what an app's handlers need. Main builds it from the environment;
// tests fill in what they use.
type Platform struct {
	DB       *pgxpool.Pool
	Verifier *oidc.IDTokenVerifier
	FGA      *FGA
	Identity *Identity
	Web      WebConfig
}

// WebConfig is the public sign-in config the web app loads before sign-in
// (each app's spec: components/schemas/Config).
type WebConfig struct {
	ProjectID  string `json:"projectId"`
	APIKey     string `json:"apiKey"`
	AuthDomain string `json:"authDomain"`
	Google     bool   `json:"google"`
}

// Mux serves GET /health and GET /config to anyone, and api to signed-in users
// who may use app (app:<app> in OpenFGA). Deny by default: every other path,
// ones that don't exist included, needs both. name is how the 403 names the app.
func (p *Platform) Mux(app, name string, api http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("GET /config", func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, http.StatusOK, p.Web)
	})
	mux.Handle("/", RequireUser(p.Verifier, requireApp(p.FGA, app, name, api)))
	return mux
}

// Handler serves api under /api (the spec's server URL) and the built web app
// from webDir everywhere else, on one origin so there is no CORS.
func Handler(api http.Handler, webDir, authDomain string) http.Handler {
	// The web app holds ID tokens: allow scripts only from this origin (and
	// Google's loader for the sign-in popup), and network calls only to the API
	// and Identity Platform's sign-in endpoints.
	csp := "default-src 'self'; script-src 'self' https://apis.google.com; " +
		"connect-src 'self' https://identitytoolkit.googleapis.com https://securetoken.googleapis.com; " +
		"frame-src https://" + authDomain + "; " +
		"img-src 'self' data:; style-src 'self' 'unsafe-inline'; " +
		"object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
	files := http.FileServer(http.Dir(webDir))
	root := http.NewServeMux()
	root.Handle("/api/", http.StripPrefix("/api", api))
	root.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		files.ServeHTTP(w, r)
	})
	return root
}

// Main runs an app. `<binary> migrate` applies MIGRATIONS_DIR and exits;
// otherwise it serves mux(platform) under /api and WEB_DIR at / on PORT.
// It exits if Postgres, the token issuer or the OpenFGA store is unreachable.
//
// Environment: DATABASE_URL, IDENTITY_PROJECT_ID and OPENFGA_URL are required;
// INSTANCE_CONNECTION_NAME, APP_DB_USER, MIGRATIONS_DIR, IDENTITY_API_KEY,
// IDENTITY_AUTH_DOMAIN, IDENTITY_GOOGLE, WEB_DIR and PORT are optional.
func Main(mux func(*Platform) http.Handler) {
	if os.Getenv("DATABASE_URL") == "" {
		log.Fatal("DATABASE_URL is required")
	}
	ctx := context.Background()
	db, err := OpenDB(ctx)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer db.Close()
	log.Print("connected to database")

	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		if err := Migrate(ctx, db); err != nil {
			log.Fatalf("migrate: %v", err)
		}
		return
	}

	projectID, fgaURL := os.Getenv("IDENTITY_PROJECT_ID"), os.Getenv("OPENFGA_URL")
	if projectID == "" || fgaURL == "" {
		log.Fatal("IDENTITY_PROJECT_ID and OPENFGA_URL are required")
	}
	web := WebConfig{
		ProjectID:  projectID,
		APIKey:     os.Getenv("IDENTITY_API_KEY"),
		AuthDomain: os.Getenv("IDENTITY_AUTH_DOMAIN"),
		Google:     os.Getenv("IDENTITY_GOOGLE") == "true",
	}
	if web.AuthDomain == "" {
		web.AuthDomain = projectID + ".firebaseapp.com"
	}
	webDir := os.Getenv("WEB_DIR")
	if webDir == "" {
		webDir = "web/dist"
	}
	verifier, err := NewVerifier(ctx, projectID)
	if err != nil {
		log.Fatalf("identity: %v", err)
	}
	// Cloud Run IAM guards OpenFGA: send a Google ID token. A local OpenFGA
	// (http://localhost...) takes plain requests.
	fgaHTTP := http.DefaultClient
	if strings.HasPrefix(fgaURL, "https://") {
		if fgaHTTP, err = idtoken.NewClient(ctx, fgaURL); err != nil {
			log.Fatalf("openfga client: %v", err)
		}
	}
	fga, err := NewFGA(ctx, fgaHTTP, fgaURL, "fairshare")
	if err != nil {
		log.Fatalf("openfga: %v", err)
	}
	adminHTTP, err := google.DefaultClient(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		log.Fatalf("identity admin client: %v", err)
	}
	p := &Platform{
		DB:       db,
		Verifier: verifier,
		FGA:      fga,
		Identity: &Identity{HTTP: adminHTTP, BaseURL: "https://identitytoolkit.googleapis.com/v1", Project: projectID},
		Web:      web,
	}

	addr := ":" + os.Getenv("PORT")
	if addr == ":" {
		addr = ":8080"
	}
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, Handler(mux(p), webDir, web.AuthDomain)))
}

// OpenDB connects to DATABASE_URL. When INSTANCE_CONNECTION_NAME is set (Cloud
// Run), it dials through the Cloud SQL Go connector with IAM database auth:
// the service account is the Postgres user and there is no password.
func OpenDB(ctx context.Context) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil {
		return nil, err
	}
	// ponytail: db-f1-micro allows ~25 connections, shared by every app and
	// instance; raise with the instance tier.
	cfg.MaxConns = 4
	if inst := os.Getenv("INSTANCE_CONNECTION_NAME"); inst != "" {
		// Lazy refresh: Cloud Run throttles CPU between requests.
		d, err := cloudsqlconn.NewDialer(ctx, cloudsqlconn.WithIAMAuthN(), cloudsqlconn.WithLazyRefresh())
		if err != nil {
			return nil, err
		}
		cfg.ConnConfig.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.Dial(ctx, inst)
		}
	}
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.Ping(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// Migrate applies goose migrations from MIGRATIONS_DIR (default db/migrations),
// then grants APP_DB_USER (the app's runtime user) DML on every table. The
// migrator owns the schema; the app can read and write rows but not change it.
func Migrate(ctx context.Context, db *pgxpool.Pool) error {
	dir := os.Getenv("MIGRATIONS_DIR")
	if dir == "" {
		dir = "db/migrations"
	}
	sqlDB := stdlib.OpenDBFromPool(db)
	defer sqlDB.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, os.DirFS(dir))
	switch {
	case errors.Is(err, goose.ErrNoMigrations):
		log.Print("no migrations")
		return nil // no tables yet, so nothing to grant
	case err != nil:
		return err
	default:
		results, err := p.Up(ctx)
		for _, r := range results {
			log.Print(r)
		}
		if err != nil {
			return err
		}
	}

	user := os.Getenv("APP_DB_USER")
	if user == "" {
		return nil
	}
	// Re-granted every run so new tables are always covered. goose's own
	// bookkeeping table stays off limits to the app.
	app := pgx.Identifier{user}.Sanitize()
	_, err = db.Exec(ctx, `
		GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO `+app+`;
		GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO `+app+`;
		REVOKE ALL ON TABLE goose_db_version FROM `+app)
	if err == nil {
		log.Printf("granted table access to %s", user)
	}
	return err
}
