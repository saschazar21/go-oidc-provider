//go:build !vercel

// Package serverless selects the platform adapter for the demo's HTTP handlers.
package serverless

import (
	"net/http"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
)

// Start serves a handler using Netlify's API Gateway request format.
func Start(handler http.Handler) {
	lambda.Start(httpadapter.New(handler).ProxyWithContext)
}
