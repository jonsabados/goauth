package aws

import (
	"context"
	"encoding/base64"
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
	AuthFailed() error
	AuthPass(p goauth.Principal) error
	ErrorEncountered(err error)
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
				err := callbacks.AuthFailed()
				if err != nil {
					callbacks.ErrorEncountered(err)
					return events.APIGatewayCustomAuthorizerResponse{}, err
				}
				return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized")
			} else {
				err := callbacks.AuthPass(principal)
				if err != nil {
					callbacks.ErrorEncountered(err)
					return events.APIGatewayCustomAuthorizerResponse{}, err
				}
			}
		} else if request.AuthorizationToken == "anonymous" && config.AllowAnonymous {
			principal = goauth.Anonymous
			err := callbacks.AuthPass(principal)
			if err != nil {
				callbacks.ErrorEncountered(err)
				return events.APIGatewayCustomAuthorizerResponse{}, err
			}
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

func ExtractPrincipal(request events.APIGatewayProxyRequest) (goauth.Principal, error) {
	encodedPrincipal := request.RequestContext.Authorizer["principal"]
	principal, err := base64.StdEncoding.DecodeString(encodedPrincipal.(string))
	if err != nil {
		return goauth.Principal{}, errors.WithStack(err)
	}
	ret := goauth.Principal{}
	err = json.Unmarshal(principal, &ret)
	if err != nil {
		return goauth.Principal{}, errors.WithStack(err)
	}
	return ret, nil
}
