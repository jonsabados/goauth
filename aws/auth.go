package aws

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/pkg/errors"

	"github.com/jonsabados/goauth"
)

type Authorizer interface {
	Authenticate(ctx context.Context, token string) (goauth.Principal, error)
}

type PolicyBuilder interface {
	BuildPolicy(ctx context.Context, principal goauth.Principal) (events.APIGatewayCustomAuthorizerPolicy, error)
}

type AuthorizerCallback interface {
	AuthFailed()
	AuthPass(p goauth.Principal)
}

type AuthorizerLambdaConfig struct {
	AllowAnonymous  bool
	Authorizer      Authorizer
	CallbackFactory func(ctx context.Context) AuthorizerCallback
	PolicyBuilder   PolicyBuilder
}

func NewAuthorizerLambdaHandler(config AuthorizerLambdaConfig) func(ctx context.Context, request events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	return func(ctx context.Context, request events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
		callbacks := config.CallbackFactory(ctx)

		var principal goauth.Principal
		if strings.HasPrefix(request.AuthorizationToken, "Bearer ") {
			var err error
			principal, err = config.Authorizer.Authenticate(ctx, strings.Replace(request.AuthorizationToken, "Bearer ", "", 1))
			if err != nil {
				callbacks.AuthFailed()
				return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized")
			} else {
				callbacks.AuthPass(principal)
			}
		} else if request.AuthorizationToken == "anonymous" && config.AllowAnonymous {
			principal = goauth.Anonymous
		} else {
			return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized")
		}

		policy, err := config.PolicyBuilder.BuildPolicy(ctx, principal)
		if err != nil {
			return events.APIGatewayCustomAuthorizerResponse{}, errors.Wrap(err, "error building policy")
		}

		principalStr, err := json.Marshal(principal)
		if err != nil {
			panic(err)
		}

		return events.APIGatewayCustomAuthorizerResponse{
			PrincipalID:    principal.UserID,
			PolicyDocument: policy,
			Context: map[string]interface{}{
				"principal": principalStr,
			},
		}, nil
	}
}
