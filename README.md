# Authentication Utilities for Go

This package provides functionality for authenticating tokens issued via google web sign on in go, as well as a lambda handler suitable for use as a custom API gateway authorizer.

## JWT validation

Golang has libraries that work just fine for basic validation of JWT tokens, but the JWT tokens you get with google web sign on have a bunch of useful information that the canned libraries don't let you get at. In theory you could use the canned libraries to validate, then parse the JWT token by hand but doing it from scratch seemed like a good learning exercise. **Danger: this has only been vetted for use in some toy sites, so use at your own risk**. See [google/auth.go](google/auth.go) for details.

## AWS

A lambda handler is defined in [aws/auth.go](aws/auth.go) that works as a custom authorizer for use with API Gateway. There is also some stuff in [aws/httputil.go](aws/httputil.go) for getting http calls registered in X-Ray. Example usage:

```go
package main

import (
	"context"
	"net/http"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-xray-sdk-go/xray"
	"github.com/jonsabados/goauth"
	"github.com/jonsabados/goauth/aws"
	"github.com/jonsabados/goauth/google"
)

type authCallback struct {
	ctx          context.Context
}

func (a *authCallback) ErrorEncountered(err error) {
	// log stuff
}

func (a *authCallback) AuthFailed() error {
	// do stuff
	return nil
}

func (a *authCallback) AuthPass(p goauth.Principal) error {
	// do stuff
	return nil
}

type endpointMapper struct {
}

func (e *endpointMapper) AllowedEndpoints(_ context.Context, _ goauth.Principal) ([]aws.AllowedEndpoint, error) {
	// allow profile for everyone. Do whatever you need here based on the principal
	return []aws.AllowedEndpoint{
		{
			Method: http.MethodGet,
			Path:   "profile",
		},
		{
			Method: http.MethodPut,
			Path:   "profile",
		},
	}, nil
}

func main() {
	err := xray.Configure(xray.Config{
		LogLevel: "warn",
	})
	if err != nil {
		panic(err)
	}

	googleClientID := os.Getenv("GOOGLE_CLIENT_ID")

	conf := aws.AuthorizerLambdaConfig{}
	conf.AllowAnonymous = true
	conf.CallbackFactory = func(ctx context.Context) aws.AuthorizerCallback {
		return &authCallback{ctx}
	}

	certFetcher := google.NewCachingCertFetcher(google.NewCertFetcher(aws.NewXRAYAwareHTTPClientFactory(http.DefaultClient)))
	authorizer := google.NewWebSignInTokenAuthenticator(certFetcher, googleClientID)
	conf.Authorizer = authorizer

	region := os.Getenv("AWS_REGION")
	accountID := os.Getenv("ACCOUNT_ID")
	apiID := os.Getenv("API_ID")
	stage := os.Getenv("STAGE")
	conf.PolicyBuilder = aws.NewGatewayPolicyBuilder(region, accountID, apiID, stage, &endpointMapper{})

	handler := aws.NewAuthorizerLambdaHandler(conf)
	lambda.Start(handler)
}
```