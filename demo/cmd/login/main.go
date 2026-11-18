package main

import (
	"net/http"

	"github.com/saschazar21/go-oidc-demo/internal/serverless"
	"github.com/saschazar21/go-oidc-provider/endpoints"
)

func main() {
	serverless.Start(http.HandlerFunc(endpoints.HandleLogin))
}
