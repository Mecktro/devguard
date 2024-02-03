package auth

import (
	"github.com/ory/client-go"
)

func GetOryApiClient(url string) *client.APIClient {
	cfg := client.NewConfiguration()
	cfg.Servers = client.ServerConfigurations{
		{URL: url},
	}

	ory := client.NewAPIClient(cfg)
	return ory
}
