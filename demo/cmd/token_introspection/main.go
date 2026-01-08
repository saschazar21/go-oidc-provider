package main

import (
	"net/http"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
	"github.com/saschazar21/go-oidc-provider/endpoints"
)

func main() {
	lambda.Start(httpadapter.New(http.HandlerFunc(endpoints.HandleTokenIntrospection)).ProxyWithContext)
}
