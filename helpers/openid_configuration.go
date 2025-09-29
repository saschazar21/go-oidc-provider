package helpers

import (
	"fmt"
	"log"
	"net/http"

	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/idtoken"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
)

func populateSigningAlgs(existing *[]utils.SigningAlgorithm, available []utils.SigningAlgorithm) error {
	if len(*existing) > 0 && !utils.ContainsValue(*existing, "none") {
		return fmt.Errorf("pre-existing signing algorithms must not contain any values other than \"none\"")
	}

	*existing = append(*existing, available...)

	return nil
}

func reduceSigningAlgs(keys *map[string]interface{}) []utils.SigningAlgorithm {
	var algs []utils.SigningAlgorithm

	for alg, key := range *keys {
		if key != nil {
			algs = append(algs, utils.SigningAlgorithm(alg))
		}
	}

	return algs
}

func NewOpenIDConfiguration(customConfig ...*models.OpenIDConfiguration) (*models.OpenIDConfiguration, errors.HTTPError) {
	var err error
	config := &models.OpenIDConfiguration{}

	if len(customConfig) > 0 && customConfig[0] != nil {
		config = customConfig[0]
	}

	keys, err := idtoken.LoadKeys()
	if err != nil {
		msg := "Keyring initialization failed"
		log.Printf("%s: %v", msg, err)

		return nil, errors.JSONError{
			StatusCode:  http.StatusInternalServerError,
			ErrorCode:   errors.SERVER_ERROR,
			Description: &msg,
		}
	}

	algs := reduceSigningAlgs(&keys)

	signingAlgSlices := []*[]utils.SigningAlgorithm{
		&config.IDTokenSigningAlgValuesSupported,
		&config.UserInfoSigningAlgValuesSupported,
		&config.RequestObjectSigningAlgValuesSupported,
		&config.TokenEndpointAuthSigningAlgValuesSupported,
	}

	for _, slice := range signingAlgSlices {
		if err := populateSigningAlgs(slice, algs); err != nil {
			msg := "Failed to populate signing algorithms"
			log.Printf("%s: %v", msg, err)

			return nil, errors.JSONError{
				StatusCode:  http.StatusInternalServerError,
				ErrorCode:   errors.SERVER_ERROR,
				Description: &msg,
			}
		}
	}

	config, err = models.NewOpenIDConfiguration(config)
	if err != nil {
		return nil, err.(errors.HTTPError)
	}

	return config, nil
}
