package google

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/jonsabados/goauth"
)

func TestWebSignInTokenAuthenticator_HappyPath_FirstKey(t *testing.T) {
	asserter := assert.New(t)

	reader := rand.Reader
	bitSize := 2048

	start := time.Now()
	expires := time.Now().Add(time.Hour)
	clientID := "testyMcTesterson"
	subject := "12345"
	email := "test@test.com"
	name := "Bob McTester"

	keyOne, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		panic(err)
	}
	keyTwo, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		panic(err)
	}

	mockCertFetcher := testCertFetcher{
		fetchCerts: func(ctx context.Context) (PublicCerts, error) {
			return PublicCerts{
				Certs: []*x509.Certificate{
					createCert(keyOne, 123, start, expires),
					createCert(keyTwo, 456, start, expires),
				},
				Expiration: expires,
			}, nil
		},
	}

	jwtPayload := fmt.Sprintf(`{
  "iss": "foo.bar.com",
  "azp": "whatever",
  "aud": "%s",
  "sub": "%s",
  "email": "%s",
  "email_verified": true,
  "at_hash": "9SrKH5GRtXul1yRpWCyLow",
  "name": "%s",
  "picture": "https://some.google.link/blah",
  "given_name": "Bob",
  "family_name": "McTester",
  "locale": "en",
  "iat": %d,
  "exp": %d,
  "jti": "123abc56"
}`, clientID, subject, email, name, start.Unix(), expires.Unix())

	jwtHeader := `{"alg":"RS256","kid":"a41a3570b8e3ae1b72caabcaa7b8d2db2065d7c1","typ":"JWT"}`

	unsigned := fmt.Sprintf("%s.%s", base64.RawURLEncoding.EncodeToString([]byte(jwtHeader)), base64.RawURLEncoding.EncodeToString([]byte(jwtPayload)))
	hasher := crypto.SHA256.New()
	hasher.Write([]byte(unsigned))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, keyOne, crypto.SHA256, hasher.Sum(nil))
	if err != nil {
		panic(err)
	}

	jwt := fmt.Sprintf("%s.%s", unsigned, base64.RawURLEncoding.EncodeToString(sigBytes))


	testInstance := NewWebSignInTokenAuthenticator(mockCertFetcher, clientID)
	res, err := testInstance.Authenticate(context.Background(), jwt)

	asserter.NoError(err)
	asserter.Equal(goauth.Principal{
		UserID: subject,
		Email:  email,
		Name:   name,
	}, res)
}

func TestWebSignInTokenAuthenticator_InvalidSigner(t *testing.T) {
	asserter := assert.New(t)

	reader := rand.Reader
	bitSize := 2048

	start := time.Now()
	expires := time.Now().Add(time.Hour)
	clientID := "testyMcTesterson"
	subject := "12345"
	email := "test@test.com"
	name := "Bob McTester"

	keyOne, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		panic(err)
	}
	keyTwo, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		panic(err)
	}

	mockCertFetcher := testCertFetcher{
		fetchCerts: func(ctx context.Context) (PublicCerts, error) {
			return PublicCerts{
				Certs: []*x509.Certificate{
					createCert(keyOne, 123, start, expires),
				},
				Expiration: expires,
			}, nil
		},
	}

	jwtPayload := fmt.Sprintf(`{
  "iss": "foo.bar.com",
  "azp": "whatever",
  "aud": "%s",
  "sub": "%s",
  "email": "%s",
  "email_verified": true,
  "at_hash": "9SrKH5GRtXul1yRpWCyLow",
  "name": "%s",
  "picture": "https://some.google.link/blah",
  "given_name": "Bob",
  "family_name": "McTester",
  "locale": "en",
  "iat": %d,
  "exp": %d,
  "jti": "123abc56"
}`, clientID, subject, email, name, start.Unix(), expires.Unix())
	jwtHeader := `{"alg":"RS256","kid":"a41a3570b8e3ae1b72caabcaa7b8d2db2065d7c1","typ":"JWT"}`
	unsigned := fmt.Sprintf("%s.%s", base64.RawURLEncoding.EncodeToString([]byte(jwtHeader)), base64.RawURLEncoding.EncodeToString([]byte(jwtPayload)))
	hasher := crypto.SHA256.New()
	hasher.Write([]byte(unsigned))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, keyTwo, crypto.SHA256, hasher.Sum(nil))
	if err != nil {
		panic(err)
	}
	jwt := fmt.Sprintf("%s.%s", unsigned, base64.RawURLEncoding.EncodeToString(sigBytes))

	testInstance := NewWebSignInTokenAuthenticator(mockCertFetcher, clientID)
	_, err = testInstance.Authenticate(context.Background(), jwt)

	asserter.EqualError(err, fmt.Sprintf("invalid signature on token %s", jwt))
}

func TestWebSignInTokenAuthenticator_NotJson(t *testing.T) {
	asserter := assert.New(t)

	reader := rand.Reader
	bitSize := 2048

	start := time.Now()
	expires := time.Now().Add(time.Hour)
	clientID := "testyMcTesterson"
	subject := "12345"
	email := "test@test.com"
	name := "Bob McTester"

	keyOne, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		panic(err)
	}

	mockCertFetcher := testCertFetcher{
		fetchCerts: func(ctx context.Context) (PublicCerts, error) {
			return PublicCerts{
				Certs: []*x509.Certificate{
					createCert(keyOne, 123, start, expires),
				},
				Expiration: expires,
			}, nil
		},
	}

	jwtPayload := fmt.Sprintf(`{
  "iss": "foo.bar.com",
  "azp": "whatever""", -- to many quotes and stuff
  "aud": "%s",
  "sub": "%s",
  "email": "%s",
  "email_verified": true,
  "at_hash": "9SrKH5GRtXul1yRpWCyLow",
  "name": "%s",
  "picture": "https://some.google.link/blah",
  "given_name": "Bob",
  "family_name": "McTester",
  "locale": "en",
  "iat": %d,
  "exp": %d,
  "jti": "123abc56"
}`, clientID, subject, email, name, start.Unix(), expires.Unix())
	jwtHeader := `{"alg":"RS256","kid":"a41a3570b8e3ae1b72caabcaa7b8d2db2065d7c1","typ":"JWT"}`
	unsigned := fmt.Sprintf("%s.%s", base64.RawURLEncoding.EncodeToString([]byte(jwtHeader)), base64.RawURLEncoding.EncodeToString([]byte(jwtPayload)))
	hasher := crypto.SHA256.New()
	hasher.Write([]byte(unsigned))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, keyOne, crypto.SHA256, hasher.Sum(nil))
	if err != nil {
		panic(err)
	}
	jwt := fmt.Sprintf("%s.%s", unsigned, base64.RawURLEncoding.EncodeToString(sigBytes))

	testInstance := NewWebSignInTokenAuthenticator(mockCertFetcher, clientID)
	_, err = testInstance.Authenticate(context.Background(), jwt)

	asserter.EqualError(err, fmt.Sprintf("garbage token: malformed token, payload should be json (%s)", jwt))
}

func TestWebSignInTokenAuthenticator_InvalidAudience(t *testing.T) {
	asserter := assert.New(t)

	reader := rand.Reader
	bitSize := 2048

	start := time.Now()
	expires := time.Now().Add(time.Hour)
	clientID := "testyMcTesterson"
	subject := "12345"
	email := "test@test.com"
	name := "Bob McTester"

	keyOne, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		panic(err)
	}

	mockCertFetcher := testCertFetcher{
		fetchCerts: func(ctx context.Context) (PublicCerts, error) {
			return PublicCerts{
				Certs: []*x509.Certificate{
					createCert(keyOne, 123, start, expires),
				},
				Expiration: expires,
			}, nil
		},
	}

	jwtPayload := fmt.Sprintf(`{
  "iss": "foo.bar.com",
  "azp": "whatever",
  "aud": "%s-whoops",
  "sub": "%s",
  "email": "%s",
  "email_verified": true,
  "at_hash": "9SrKH5GRtXul1yRpWCyLow",
  "name": "%s",
  "picture": "https://some.google.link/blah",
  "given_name": "Bob",
  "family_name": "McTester",
  "locale": "en",
  "iat": %d,
  "exp": %d,
  "jti": "123abc56"
}`, clientID, subject, email, name, start.Unix(), expires.Unix())
	jwtHeader := `{"alg":"RS256","kid":"a41a3570b8e3ae1b72caabcaa7b8d2db2065d7c1","typ":"JWT"}`
	unsigned := fmt.Sprintf("%s.%s", base64.RawURLEncoding.EncodeToString([]byte(jwtHeader)), base64.RawURLEncoding.EncodeToString([]byte(jwtPayload)))
	hasher := crypto.SHA256.New()
	hasher.Write([]byte(unsigned))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, keyOne, crypto.SHA256, hasher.Sum(nil))
	if err != nil {
		panic(err)
	}
	jwt := fmt.Sprintf("%s.%s", unsigned, base64.RawURLEncoding.EncodeToString(sigBytes))


	testInstance := NewWebSignInTokenAuthenticator(mockCertFetcher, clientID)
	_, err = testInstance.Authenticate(context.Background(), jwt)

	asserter.EqualError(err, fmt.Sprintf("invalid audience: %s-whoops", clientID))
}

func TestWebSignInTokenAuthenticator_Expired(t *testing.T) {
	asserter := assert.New(t)

	reader := rand.Reader
	bitSize := 2048

	start := time.Now()
	expires := time.Now().Add(-time.Second)
	clientID := "testyMcTesterson"
	subject := "12345"
	email := "test@test.com"
	name := "Bob McTester"

	keyOne, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		panic(err)
	}

	mockCertFetcher := testCertFetcher{
		fetchCerts: func(ctx context.Context) (PublicCerts, error) {
			return PublicCerts{
				Certs: []*x509.Certificate{
					createCert(keyOne, 123, start, expires),
				},
				Expiration: expires,
			}, nil
		},
	}

	jwtPayload := fmt.Sprintf(`{
  "iss": "foo.bar.com",
  "azp": "whatever",
  "aud": "%s",
  "sub": "%s",
  "email": "%s",
  "email_verified": true,
  "at_hash": "9SrKH5GRtXul1yRpWCyLow",
  "name": "%s",
  "picture": "https://some.google.link/blah",
  "given_name": "Bob",
  "family_name": "McTester",
  "locale": "en",
  "iat": %d,
  "exp": %d,
  "jti": "123abc56"
}`, clientID, subject, email, name, start.Unix(), expires.Unix())
	jwtHeader := `{"alg":"RS256","kid":"a41a3570b8e3ae1b72caabcaa7b8d2db2065d7c1","typ":"JWT"}`
	unsigned := fmt.Sprintf("%s.%s", base64.RawURLEncoding.EncodeToString([]byte(jwtHeader)), base64.RawURLEncoding.EncodeToString([]byte(jwtPayload)))
	hasher := crypto.SHA256.New()
	hasher.Write([]byte(unsigned))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, keyOne, crypto.SHA256, hasher.Sum(nil))
	if err != nil {
		panic(err)
	}
	jwt := fmt.Sprintf("%s.%s", unsigned, base64.RawURLEncoding.EncodeToString(sigBytes))

	testInstance := NewWebSignInTokenAuthenticator(mockCertFetcher, clientID)
	_, err = testInstance.Authenticate(context.Background(), jwt)

	asserter.EqualError(err, fmt.Sprintf("expired token, expiration: %s", expires.Format(time.RFC3339)))
}

func TestWebSignInTokenAuthenticator_Garbage(t *testing.T) {
	asserter := assert.New(t)

	reader := rand.Reader
	bitSize := 2048

	start := time.Now()
	expires := time.Now().Add(-time.Second)
	clientID := "testyMcTesterson"

	keyOne, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		panic(err)
	}

	mockCertFetcher := testCertFetcher{
		fetchCerts: func(ctx context.Context) (PublicCerts, error) {
			return PublicCerts{
				Certs: []*x509.Certificate{
					createCert(keyOne, 123, start, expires),
				},
				Expiration: expires,
			}, nil
		},
	}

	testInstance := NewWebSignInTokenAuthenticator(mockCertFetcher, clientID)
	_, err = testInstance.Authenticate(context.Background(), "wtfisthis?")
	asserter.EqualError(err, "garbage token: format (wtfisthis?)")

	_, err = testInstance.Authenticate(context.Background(), "YWJj.YWJj.###")
	asserter.EqualError(err, "garbage token: signature malformed (YWJj.YWJj.###)")

	_, err = testInstance.Authenticate(context.Background(), "YWJj.###.YWJj")
	asserter.EqualError(err, "garbage token: payload malformed (YWJj.###.YWJj)")
}

func createCert(key *rsa.PrivateKey, serial int, start time.Time, expires time.Time) *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(int64(serial)),
		Subject: pkix.Name{
			Organization: []string{"Testing FTW"},
		},
		NotBefore: start,
		NotAfter:  expires,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	bytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	parsedCert, err := x509.ParseCertificate(bytes)
	if err != nil {
		panic(err)
	}
	return parsedCert
}


type testCertFetcher struct {
	fetchCerts func(ctx context.Context) (PublicCerts, error)
}

func (t testCertFetcher) FetchCerts(ctx context.Context) (PublicCerts, error) {
	return t.fetchCerts(ctx)
}