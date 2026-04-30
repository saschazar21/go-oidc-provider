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

func populateSigningAlgs(existing *[]utils.SigningAlgorithm, available []utils.SigningAlgorithm, allowNone bool) error {
	if len(*existing) > 0 {
		for _, alg := range *existing {
			if alg == "none" && allowNone {
				continue
			}

			if !utils.ContainsValue(available, alg) {
				return fmt.Errorf("unsupported signing algorithm: %s", alg)
			}
		}
	}

	for _, alg := range available {
		if !utils.ContainsValue(*existing, alg) {
			*existing = append(*existing, alg)
		}
	}

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

	type signingAlgEntry struct {
		allowNone bool
		slice     *[]utils.SigningAlgorithm
	}

	signingAlgSlices := []signingAlgEntry{
		{allowNone: true, slice: &config.IDTokenSigningAlgValuesSupported},
		{allowNone: true, slice: &config.UserInfoSigningAlgValuesSupported},
		{allowNone: true, slice: &config.RequestObjectSigningAlgValuesSupported},
		{allowNone: false, slice: &config.TokenEndpointAuthSigningAlgValuesSupported},
	}

	for _, entry := range signingAlgSlices {
		if err := populateSigningAlgs(entry.slice, algs, entry.allowNone); err != nil {
			msg := "Failed to populate signing algorithms"
			log.Printf("%s: %v (config: %v, available: %v)", msg, err, *entry.slice, algs)

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
