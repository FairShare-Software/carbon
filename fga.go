package carbon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

// FGA talks to the central OpenFGA service (HTTP API). On Cloud Run the
// http.Client adds a Google ID token; OpenFGA only accepts listed callers.
type FGA struct {
	HTTP  *http.Client
	URL   string
	Store string // store ID
}

// Tuple is an OpenFGA relationship, e.g. user:<uid> viewer project:<id>.
// ExpiresAt sets the not_expired condition from authz/model.fga in iron.
type Tuple struct {
	User      string
	Relation  string
	Object    string
	ExpiresAt *time.Time
}

// NewFGA resolves the store by name; apps use its latest authorization model.
func NewFGA(ctx context.Context, c *http.Client, url, storeName string) (*FGA, error) {
	f := &FGA{HTTP: c, URL: strings.TrimRight(url, "/")}
	var res struct {
		Stores []struct{ ID, Name string } `json:"stores"`
	}
	if err := f.Do(ctx, http.MethodGet, "/stores?name="+storeName, nil, &res); err != nil {
		return nil, err
	}
	for _, s := range res.Stores {
		if s.Name == storeName {
			f.Store = s.ID
			return f, nil
		}
	}
	return nil, fmt.Errorf("openfga store %q not found", storeName)
}

// conditionContext supplies current_time for the not_expired condition.
func conditionContext() map[string]any {
	return map[string]any{"current_time": time.Now().UTC().Format(time.RFC3339)}
}

func (f *FGA) Check(ctx context.Context, user, relation, object string) (bool, error) {
	req := map[string]any{
		"tuple_key": map[string]string{"user": user, "relation": relation, "object": object},
		"context":   conditionContext(),
	}
	var res struct {
		Allowed bool `json:"allowed"`
	}
	err := f.Do(ctx, http.MethodPost, "/stores/"+f.Store+"/check", req, &res)
	return res.Allowed, err
}

// ListObjects returns object IDs (without the "<type>:" prefix).
// ponytail: OpenFGA caps results (default 1000); paginate via the DB if a user can see more.
func (f *FGA) ListObjects(ctx context.Context, user, relation, objectType string) ([]string, error) {
	req := map[string]any{"user": user, "relation": relation, "type": objectType, "context": conditionContext()}
	var res struct {
		Objects []string `json:"objects"`
	}
	if err := f.Do(ctx, http.MethodPost, "/stores/"+f.Store+"/list-objects", req, &res); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(res.Objects))
	for _, o := range res.Objects {
		ids = append(ids, strings.TrimPrefix(o, objectType+":"))
	}
	return ids, nil
}

// Read returns tuples matching a filter. object is "<type>:<id>" or "<type>:"
// (all objects of that type, which then requires user).
func (f *FGA) Read(ctx context.Context, user, relation, object string) ([]Tuple, error) {
	key := map[string]string{"object": object}
	if user != "" {
		key["user"] = user
	}
	if relation != "" {
		key["relation"] = relation
	}
	var out []Tuple
	token := ""
	for {
		req := map[string]any{"tuple_key": key, "page_size": 100}
		if token != "" {
			req["continuation_token"] = token
		}
		var res struct {
			Tuples []struct {
				Key struct {
					User, Relation, Object string
					Condition              *struct {
						Name    string `json:"name"`
						Context struct {
							ExpiresAt *time.Time `json:"expires_at"`
						} `json:"context"`
					} `json:"condition"`
				} `json:"key"`
			} `json:"tuples"`
			ContinuationToken string `json:"continuation_token"`
		}
		if err := f.Do(ctx, http.MethodPost, "/stores/"+f.Store+"/read", req, &res); err != nil {
			return nil, err
		}
		for _, t := range res.Tuples {
			tt := Tuple{User: t.Key.User, Relation: t.Key.Relation, Object: t.Key.Object}
			if c := t.Key.Condition; c != nil && c.Name == "not_expired" {
				tt.ExpiresAt = c.Context.ExpiresAt
			}
			out = append(out, tt)
		}
		if res.ContinuationToken == "" {
			return out, nil
		}
		token = res.ContinuationToken
	}
}

// Delete removes tuples in order; ones that don't exist are ignored. OpenFGA
// takes at most 100 per write, so more go in batches: not atomic, but a retry
// finishes a partial delete.
func (f *FGA) Delete(ctx context.Context, tuples ...Tuple) error {
	for batch := range slices.Chunk(tuples, 100) {
		keys := make([]map[string]string, 0, len(batch))
		for _, t := range batch {
			keys = append(keys, map[string]string{"user": t.User, "relation": t.Relation, "object": t.Object})
		}
		req := map[string]any{"deletes": map[string]any{"tuple_keys": keys, "on_missing": "ignore"}}
		if err := f.Do(ctx, http.MethodPost, "/stores/"+f.Store+"/write", req, nil); err != nil {
			return err
		}
	}
	return nil
}

// Write adds tuples (at most 100); ones that already exist are left as they are.
func (f *FGA) Write(ctx context.Context, tuples ...Tuple) error {
	keys := make([]map[string]any, 0, len(tuples))
	for _, t := range tuples {
		k := map[string]any{"user": t.User, "relation": t.Relation, "object": t.Object}
		if t.ExpiresAt != nil {
			k["condition"] = map[string]any{
				"name":    "not_expired",
				"context": map[string]any{"expires_at": t.ExpiresAt.UTC().Format(time.RFC3339)},
			}
		}
		keys = append(keys, k)
	}
	req := map[string]any{"writes": map[string]any{"tuple_keys": keys, "on_duplicate": "ignore"}}
	return f.Do(ctx, http.MethodPost, "/stores/"+f.Store+"/write", req, nil)
}

// Do sends one OpenFGA API request (path from /stores on) and decodes the
// reply into out, if given.
func (f *FGA) Do(ctx context.Context, method, path string, body, out any) error {
	var r io.Reader = http.NoBody
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, f.URL+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := f.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		var e struct{ Message string }
		json.NewDecoder(res.Body).Decode(&e)
		return fmt.Errorf("openfga %s %s: %s %s", method, path, res.Status, e.Message)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(res.Body).Decode(out)
}
