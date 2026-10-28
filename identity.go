package carbon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
)

// Identity pre-creates Identity Platform accounts for invited people (self
// sign-up is disabled), emails them a sign-in link and looks up emails.
// Needs firebaseauth.users.get, .create and .sendEmail only.
type Identity struct {
	HTTP    *http.Client // adds the service account's OAuth token on Cloud Run
	BaseURL string       // https://identitytoolkit.googleapis.com/v1
	Project string
}

// EnsureUser returns the user ID for email, creating the account if needed
// (created is then true). The person signs in with an email link, which
// verifies the address.
func (a *Identity) EnsureUser(ctx context.Context, email string) (uid string, created bool, err error) {
	uid, err = a.Lookup(ctx, email)
	if err != nil || uid != "" {
		return uid, false, err
	}
	var res struct {
		LocalID string `json:"localId"`
	}
	if err := a.post(ctx, "/accounts", map[string]any{"email": email}, &res); err != nil {
		return "", false, err
	}
	return res.LocalID, true, nil
}

// SendSignInLink emails a sign-in link (Identity Platform's built-in email)
// that returns the person to continueURL, which must be an authorized domain.
func (a *Identity) SendSignInLink(ctx context.Context, email, continueURL string) error {
	return a.post(ctx, "/accounts:sendOobCode", map[string]any{
		"requestType":        "EMAIL_SIGNIN",
		"email":              email,
		"continueUrl":        continueURL,
		"canHandleCodeInApp": true,
	}, new(struct{}))
}

// Emails maps user IDs to email addresses. Unknown IDs are left out.
func (a *Identity) Emails(ctx context.Context, uids []string) (map[string]string, error) {
	out := map[string]string{}
	// Identity Platform looks up at most 100 localIds per request.
	for batch := range slices.Chunk(uids, 100) {
		var res struct {
			Users []struct {
				LocalID string `json:"localId"`
				Email   string `json:"email"`
			} `json:"users"`
		}
		if err := a.post(ctx, "/accounts:lookup", map[string]any{"localId": batch}, &res); err != nil {
			return nil, err
		}
		for _, u := range res.Users {
			out[u.LocalID] = u.Email
		}
	}
	return out, nil
}

// Lookup returns the user ID for email, or "" if there is no account.
func (a *Identity) Lookup(ctx context.Context, email string) (string, error) {
	var found struct {
		Users []struct {
			LocalID string `json:"localId"`
		} `json:"users"`
	}
	if err := a.post(ctx, "/accounts:lookup", map[string]any{"email": []string{email}}, &found); err != nil {
		return "", err
	}
	if len(found.Users) == 0 {
		return "", nil
	}
	return found.Users[0].LocalID, nil
}

func (a *Identity) post(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.BaseURL+"/projects/"+a.Project+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := a.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		var e struct {
			Error struct{ Message string } `json:"error"`
		}
		json.NewDecoder(res.Body).Decode(&e)
		return fmt.Errorf("identity platform %s: %s %s", path, res.Status, e.Error.Message)
	}
	return json.NewDecoder(res.Body).Decode(out)
}
