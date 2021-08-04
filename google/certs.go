package google

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/pkg/errors"
)

const CertEndpoint = "https://www.googleapis.com/oauth2/v1/certs"

// HttpClientFactory provides http clients given a context.
type HttpClientFactory interface {
	HTTPClient(ctx context.Context) *http.Client
}

type CertFetcher interface {
	FetchCerts(ctx context.Context) (PublicCerts, error)
}

// PublicCerts carry the public certificates that can be used to validate JWT tokens signed by google, as well
// as an expiration date after which they should refresh.
type PublicCerts struct {
	Certs      []*x509.Certificate
	Expiration time.Time
}

// CertFetchingError represents an error when reading googles public cert if the http status is not as expected
type CertFetchingError struct {
	StatusCode   int
	ResponseBody string
}

// Error formats the CertFetchingError into a string with status code and response body
func (c CertFetchingError) Error() string {
	return fmt.Sprintf("unexpected response code: %d, body: %s", c.StatusCode, c.ResponseBody)
}

type certFetcher struct {
	certURL string
	httpClientFactory HttpClientFactory
}

func (c *certFetcher) FetchCerts(ctx context.Context) (PublicCerts, error) {
	httpClient := c.httpClientFactory.HTTPClient(ctx)
	res, err := httpClient.Get(c.certURL)
	if err != nil {
		return PublicCerts{}, errors.Wrap(err, "error fetching google certificates")
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return PublicCerts{}, errors.Wrap(err, "error parsing google certs")
	}
	if res.StatusCode != http.StatusOK {
		return PublicCerts{}, CertFetchingError{res.StatusCode, string(body)}
	}
	// Thu, 25 Jun 2020 02:12:50 GMT
	expiresStr := res.Header.Get("Expires")
	expireDate, err := time.Parse(time.RFC1123, expiresStr)
	if err != nil {
		// this isn't really fatal, if we can read the rest of the response just warn and give an expiration of now
		expireDate = time.Now()
	}
	// response is json with cert key => cert pem so just read into a map since keys aren't known
	mappedCerts := make(map[string]string)
	err = json.Unmarshal(body, &mappedCerts)
	if err != nil {
		return PublicCerts{}, errors.WithStack(err)
	}
	if len(mappedCerts) == 0 {
		return PublicCerts{}, errors.New("no certs found in response body")
	}
	certs := make([]*x509.Certificate, len(mappedCerts))
	i := 0
	for _, v := range mappedCerts {
		cert, err := parseCert(v)
		if err != nil {
			return PublicCerts{}, errors.WithStack(err)
		}
		certs[i] = cert
		i++
	}
	return PublicCerts{
		Certs:      certs,
		Expiration: expireDate,
	}, nil
}

func parseCert(cert string) (*x509.Certificate, error) {
	pemVal, rest := pem.Decode([]byte(cert))
	if len(rest) > 0 {
		return nil, errors.New(fmt.Sprintf("multiple certs or invalid body in %s", cert))
	}
	parsedCert, err := x509.ParseCertificate(pemVal.Bytes)
	if err != nil {
		return nil, err
	}
	return parsedCert, nil
}


func NewCertFetcher(httpClientFactory HttpClientFactory) CertFetcher {
	return &certFetcher{
		certURL:           CertEndpoint,
		httpClientFactory: httpClientFactory,
	}
}