package httputil

import (
	"context"
	"net/http"
)

type StaticHTTPClientFactory struct {
	Client *http.Client
}

func (s *StaticHTTPClientFactory) HTTPClient(context.Context) *http.Client {
	return s.Client
}

func NewStaticHTTPClientFactory(c *http.Client) *StaticHTTPClientFactory {
	return &StaticHTTPClientFactory{c}
}