package main

import (
	"net/http"

	"github.com/saschazar21/go-oidc-demo/endpoints"
	"github.com/saschazar21/go-oidc-demo/internal/serverless"
)

func main() {
	serverless.Start(http.HandlerFunc(endpoints.HandleIndex))
}
