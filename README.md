# carbon

The shared Go server code of FairShare apps (Mercury, the console, and apps
made from the [hydrogen](https://github.com/FairShare-Software/hydrogen)
template):

- `carbon.Main` runs an app from its environment: Postgres (Cloud SQL with IAM
  auth on Cloud Run), the `migrate` subcommand (goose), Identity Platform token
  verification, the central OpenFGA store, and one origin serving the API at
  `/api` and the web app at `/` with a strict CSP.
- `Platform.Mux` serves `/health` and `/config`, and denies everything else to
  callers without a valid token and access to the app (`app:<id>` in OpenFGA).
- `FGA`: check, list, read, write and delete tuples. `Identity`: invite people
  (create the account, email a sign-in link) and look up emails.
- `carbontest`: signed test tokens, a fake Identity Platform, and fresh
  Postgres and OpenFGA stores for integration tests.

```go
func main() {
	carbon.Main(func(p *carbon.Platform) http.Handler {
		api := http.NewServeMux()
		api.HandleFunc("GET /me", func(w http.ResponseWriter, r *http.Request) {
			carbon.WriteJSON(w, http.StatusOK, carbon.CurrentUser(r))
		})
		return p.Mux("myapp", "My App", api)
	})
}
```

## Develop

```sh
docker run -d --rm -p 8080:8080 openfga/openfga:v1.22.0 run
TEST_OPENFGA_URL=http://localhost:8080 go test ./...
```

Tests use a small stand-in model (`testdata/model.fga`); the real one is in
iron's `authz/`.

## Release

Tag `vX.Y.Z` on main and push the tag. Apps update with
`go get github.com/FairShare-Software/carbon@vX.Y.Z`. Breaking changes need a
minor bump while we're on v0.
