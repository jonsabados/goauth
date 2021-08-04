package google

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/jonsabados/goauth"
)

// WebSignInTokenAuthenticator can be used to validate authentication tokens retrieved from google sign-in for web
// see (https://developers.google.com/identity/sign-in/web)
type WebSignInTokenAuthenticator struct {
	certFetcher CertFetcher
	ClientID    string
}

// Authenticate validates a JWT token and returns a populated goauth.Principal if valid, or zero value and  an error if
// not (or if an error occurred while fetching google certificates). The returned principal will not have any roles
// assigned, so you should take steps to populate those roles if need be.
func (w *WebSignInTokenAuthenticator) Authenticate(ctx context.Context, token string) (goauth.Principal, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return goauth.Principal{}, garbageTokenError(token, "format")
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return goauth.Principal{}, garbageTokenError(token, "signature malformed")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return goauth.Principal{}, garbageTokenError(token, "payload malformed")
	}

	signedContent := parts[0] + "." + parts[1]
	hash := sha256.New()
	hash.Write([]byte(signedContent))
	hashSum := hash.Sum(nil)

	certs, err := w.certFetcher.FetchCerts(ctx)
	if err != nil {
		return goauth.Principal{}, errors.Wrap(err, "error fetching certificates")
	}

	valid := false
	for _, c := range certs.Certs {
		err := rsa.VerifyPKCS1v15(c.PublicKey.(*rsa.PublicKey), crypto.SHA256, hashSum, signature)
		if err == nil {
			valid = true
			break
		}
	}
	if !valid {
		return goauth.Principal{}, errors.Errorf("invalid signature on token %s", token)
	}

	payload := new(googleToken)
	err = json.Unmarshal(payloadBytes, payload)
	if err != nil {
		return goauth.Principal{}, garbageTokenError(token, "malformed token, payload should be json")
	}

	if payload.Aud != w.ClientID {
		return goauth.Principal{}, errors.Errorf("invalid audience: %s", payload.Aud)
	}

	if payload.Exp < time.Now().Unix() {
		return goauth.Principal{}, errors.Errorf("expired token, expiration: %s", time.Unix(payload.Exp, 0).Format(time.RFC3339))
	}

	return goauth.Principal{
		UserID: payload.Sub,
		Email:  payload.Email,
		Name:   payload.Name,
	}, nil
}

// NewWebSignInTokenAuthenticator provides a WebSignInTokenAuthenticator using the given CertFetcher and ClientID.
// You probably want to use a CachingCertFetcher instead of just a CertFetcher
func NewWebSignInTokenAuthenticator(certFetcher CertFetcher, clientID string) *WebSignInTokenAuthenticator {
	return &WebSignInTokenAuthenticator{
		certFetcher,
		clientID,
	}
}

func garbageTokenError(reason string, token string) error {
	return errors.Errorf("garbage token: %s (%s)", token, reason)
}

type googleToken struct {
	Iss           string `json:"iss"`
	Azp           string `json:"azp"`
	Aud           string `json:"aud"`
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	AtHash        string `json:"at_hash"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Locale        string `json:"locale"`
	Iat           int64  `json:"iat"`
	Exp           int64  `json:"exp"`
	Jti           string `json:"jti"`
}
