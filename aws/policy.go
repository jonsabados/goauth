package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/pkg/errors"

	"github.com/jonsabados/goauth"
)

// Allowed Endpoint represents a resource a principal is allowed to access. Used in building policy documents, * globs are supported.
type AllowedEndpoint struct {
	Method string
	Path   string
}

// EndpointMapper takes a principle and returns the endpoints they are allowed to access
type EndpointMapper interface {
	AllowedEndpoints(ctx context.Context, principal goauth.Principal) ([]AllowedEndpoint, error)
}

// GatewayPolicyBuilder builds policy documents that can be used with custom authorizer lambda's
type GatewayPolicyBuilder struct {
	Region         string
	AccountID      string
	ApiID          string
	Stage          string
	endpointMapper EndpointMapper
}

func (g *GatewayPolicyBuilder) BuildPolicy(ctx context.Context, principal goauth.Principal) (events.APIGatewayCustomAuthorizerPolicy, error) {
	statement := make([]events.IAMPolicyStatement, 0)
	allowedEndpoints, err := g.endpointMapper.AllowedEndpoints(ctx, principal)
	if err != nil {
		return events.APIGatewayCustomAuthorizerPolicy{}, errors.Wrap(err, "error mapping allowed endpoints")
	}
	for _, e := range allowedEndpoints {
		statement = append(statement, createAllowStatement(fmt.Sprintf("arn:aws:execute-api:%s:%s:%s/%s/%s/%s", g.Region, g.AccountID, g.ApiID, g.Stage, e.Method, e.Path)))
	}
	return events.APIGatewayCustomAuthorizerPolicy{
		Version:   "2012-10-17",
		Statement: statement,
	}, nil
}

func NewGatewayPolicyBuilder(region, accountID, apiID, stage string, endpointMapper EndpointMapper) *GatewayPolicyBuilder {
	return &GatewayPolicyBuilder{
		region,
		accountID,
		apiID,
		stage,
		endpointMapper,
	}
}

func createAllowStatement(arn string) events.IAMPolicyStatement {
	return events.IAMPolicyStatement{
		Action:   []string{"execute-api:Invoke"},
		Effect:   "Allow",
		Resource: []string{arn},
	}
}
