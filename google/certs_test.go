package google

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/jonsabados/goauth/httputil"
)

func Test_CertFetcher_NetworkError(t *testing.T) {
	asserter := assert.New(t)

	ts := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		asserter.Fail("wtf?")
	}))
	ts.Close()

	testInstance := &certFetcher{
		ts.URL,
		httputil.NewStaticHTTPClientFactory(http.DefaultClient),
	}
	_, err := testInstance.FetchCerts(context.Background())
	asserter.Error(err)
}

func Test_CertFetcher_NetworkGood(t *testing.T) {
	testCases := []struct {
		desc             string
		responseCode     int
		responseFixture  string
		expirationHeader string
		expectedSerials  []string
		expectError      bool
	}{
		{
			"internal server error",
			http.StatusInternalServerError,
			"fixture/error.json",
			"Thu, 25 Jun 2020 12:01:01 MST",
			nil,
			true,
		},
		{
			"garbage response",
			http.StatusOK,
			"fixture/garbage.html",
			"Thu, 25 Jun 2020 12:01:01 MST",
			nil,
			true,
		},
		{
			"unexpected json",
			http.StatusOK,
			"fixture/error.json",
			"Thu, 25 Jun 2020 12:01:01 MST",
			nil,
			true,
		},
		{
			"empty json",
			http.StatusOK,
			"fixture/empty.json",
			"Thu, 25 Jun 2020 12:01:01 MST",
			nil,
			true,
		},
		{
			"happy path",
			http.StatusOK,
			"fixture/googlecerts.json",
			"Thu, 25 Jun 2020 12:01:01 MST",
			[]string{
				"swjeSaDD1xCYlGMO3fPrpieIhRXTHfWqEL0EA7L3JMKPs2Dae3P/vtqN2qL7fq3Ft48xCz0swmE5Ci8OEBQZi+RB+A4t0MxMO9K3LJk1wmqyZdj0d7LZ3WFq5hyym7dQzes/4z/4UcYMel/z/jjmKM7qBvtm8a68vpAcZooMy/f13hIotTdYPwJ8fACB8EYOYVzz0gyKPFAXbXvNC64dR2IF4lR0/ql9IdgZkxqCeCyf/KQtNQ3D4p8yqvdMcJV0Va3r8Teh72zyj1U/QLnCJVURL/ircP3UDGZzN7bym/r5JQhuOHjGWTqPTsGgV0/ZkQA4pOxOvt1PUO0F1UsQTQ==",
				"uK2uXX3c28Xpjyx0rUjmC7cBSJ5j7OUJfL4EQsZbXm1I514GD+GCnn/UhYqirv3hTdH0F22aiGJdgDwofZBr5iKAVf4Z2VHaQ8sE1taMH+cAqZEquJLmDuRTRKoJh6ZW116+8cuAVtDdfBGH8INTy8hedusJh+uUTqO+xg/dEt8EQHQlvO4DlQc5iqV/dAb1TnAdl9SyKV68naxts/B+Cy8P1FrVv7LHcXBDHYTo8jquhZRnz+GuxKrhqS2W8Nyfqj+k9xYZqd/usvvu6XUmb/wDDatw9i8zUDURKulcUeCA7OKyOGjNr6pKIkKnMPDHDoCA6N6aTrZBG1fuj3G8eg==",
			},
			false,
		},
		{
			"missing expiration",
			http.StatusOK,
			"fixture/googlecerts.json",
			"",
			[]string{
				"swjeSaDD1xCYlGMO3fPrpieIhRXTHfWqEL0EA7L3JMKPs2Dae3P/vtqN2qL7fq3Ft48xCz0swmE5Ci8OEBQZi+RB+A4t0MxMO9K3LJk1wmqyZdj0d7LZ3WFq5hyym7dQzes/4z/4UcYMel/z/jjmKM7qBvtm8a68vpAcZooMy/f13hIotTdYPwJ8fACB8EYOYVzz0gyKPFAXbXvNC64dR2IF4lR0/ql9IdgZkxqCeCyf/KQtNQ3D4p8yqvdMcJV0Va3r8Teh72zyj1U/QLnCJVURL/ircP3UDGZzN7bym/r5JQhuOHjGWTqPTsGgV0/ZkQA4pOxOvt1PUO0F1UsQTQ==",
				"uK2uXX3c28Xpjyx0rUjmC7cBSJ5j7OUJfL4EQsZbXm1I514GD+GCnn/UhYqirv3hTdH0F22aiGJdgDwofZBr5iKAVf4Z2VHaQ8sE1taMH+cAqZEquJLmDuRTRKoJh6ZW116+8cuAVtDdfBGH8INTy8hedusJh+uUTqO+xg/dEt8EQHQlvO4DlQc5iqV/dAb1TnAdl9SyKV68naxts/B+Cy8P1FrVv7LHcXBDHYTo8jquhZRnz+GuxKrhqS2W8Nyfqj+k9xYZqd/usvvu6XUmb/wDDatw9i8zUDURKulcUeCA7OKyOGjNr6pKIkKnMPDHDoCA6N6aTrZBG1fuj3G8eg==",
			},
			false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			asserter := assert.New(t)

			expectedPath := "/testingfun"

			ts := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				defer request.Body.Close()

				asserter.Equal(expectedPath, request.URL.Path)

				if tc.expirationHeader != "" {
					writer.Header().Add("Expires", tc.expirationHeader)
				}

				writer.WriteHeader(tc.responseCode)
				res, err := ioutil.ReadFile(tc.responseFixture)
				if asserter.NoError(err) {
					_, err = writer.Write(res)
					asserter.NoError(err)
				}
			}))
			defer ts.Close()

			testInstance := &certFetcher{
				fmt.Sprintf("%s/testingfun", ts.URL),
				httputil.NewStaticHTTPClientFactory(http.DefaultClient),
			}
			res, err := testInstance.FetchCerts(context.Background())
			if tc.expectError {
				asserter.Error(err)
			} else {
				if !asserter.NoError(err) {
					return
				}
				serials := make([]string, len(res.Certs))
				for i, cert := range res.Certs {
					serials[i] = base64.StdEncoding.EncodeToString(cert.Signature)
				}
				sort.Strings(serials)
				asserter.Equal(tc.expectedSerials, serials)

				if tc.expirationHeader != "" {
					expectedTime, err := time.Parse(time.RFC1123, tc.expirationHeader)
					if asserter.NoError(err) {
						asserter.Equal(expectedTime, res.Expiration)
					}
				} else {
					asserter.WithinDuration(time.Now(), res.Expiration, time.Second*1)
				}
			}
		})
	}
}
