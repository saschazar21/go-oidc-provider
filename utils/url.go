package utils

import (
	"os"
)

// GetDeploymentURL returns the deployment URL based on the CONTEXT environment variable.
// In production, it uses the URL environment variable.
// In other contexts (like deploy previews), it uses the DEPLOY_PRIME_URL variable.
func GetDeploymentURL() string {
	if os.Getenv(CONTEXT_ENV) == "production" {
		return os.Getenv(URL_ENV)
	}
	return os.Getenv(DEPLOY_PRIME_URL_ENV)
}
