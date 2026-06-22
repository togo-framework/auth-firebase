// Package firebase verifies Firebase Authentication ID tokens and issues a togo
// session. The frontend signs in with the Firebase SDK and POSTs the ID token to
// /api/auth/firebase; this driver verifies it (RS256 against Google's public
// certs, with issuer/audience checks) and find-or-creates the user via auth.
//
// Install: `togo install togo-framework/auth-firebase`. Env: FIREBASE_PROJECT_ID.
package firebase

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/togo-framework/auth"
	"github.com/togo-framework/togo"
)

const (
	certsURL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
	issuer   = "https://securetoken.google.com/"
)

func init() {
	togo.RegisterProviderFunc("auth-firebase", togo.PriorityLate+20, func(k *togo.Kernel) error {
		svc, ok := auth.FromKernel(k)
		if !ok {
			if k.Log != nil {
				k.Log.Warn("auth-firebase: auth plugin not installed; skipping")
			}
			return nil
		}
		project := os.Getenv("FIREBASE_PROJECT_ID")
		v := &verifier{client: &http.Client{Timeout: 10 * time.Second}}
		k.Router.Post("/api/auth/firebase", func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				IDToken string `json:"id_token"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.IDToken == "" {
				http.Error(w, "id_token required", http.StatusBadRequest)
				return
			}
			email, err := v.verify(r.Context(), body.IDToken, project)
			if err != nil || email == "" {
				http.Error(w, "invalid firebase token", http.StatusUnauthorized)
				return
			}
			id, err := svc.FindOrCreateByEmail(r.Context(), email)
			if err != nil {
				http.Error(w, "login failed", http.StatusInternalServerError)
				return
			}
			token, err := svc.IssueSession(w, *id)
			if err != nil {
				http.Error(w, "session failed", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"token": token, "user": id})
		})
		return nil
	})
}

type verifier struct {
	client *http.Client
	mu     sync.RWMutex
	keys   map[string]*rsa.PublicKey
	exp    time.Time
}

func (v *verifier) verify(ctx context.Context, token, project string) (string, error) {
	if project == "" {
		return "", errors.New("FIREBASE_PROJECT_ID not set")
	}
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return v.key(ctx, kid)
	}, jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(issuer+project),
		jwt.WithAudience(project))
	if err != nil {
		return "", err
	}
	email, _ := claims["email"].(string)
	return email, nil
}

func (v *verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	if v.keys != nil && time.Now().Before(v.exp) {
		if k, ok := v.keys[kid]; ok {
			v.mu.RUnlock()
			return k, nil
		}
	}
	v.mu.RUnlock()
	if err := v.refresh(ctx); err != nil {
		return nil, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, errors.New("unknown key id")
}

func (v *verifier) refresh(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, certsURL, nil)
	resp, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var certs map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&certs); err != nil {
		return err
	}
	keys := make(map[string]*rsa.PublicKey, len(certs))
	for kid, certPEM := range certs {
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if pk, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			keys[kid] = pk
		}
	}
	v.mu.Lock()
	v.keys = keys
	v.exp = time.Now().Add(1 * time.Hour)
	v.mu.Unlock()
	return nil
}
