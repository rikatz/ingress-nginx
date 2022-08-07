package grpcclient

import (
	"encoding/json"
	"fmt"

	v1 "k8s.io/api/core/v1"
	"k8s.io/ingress-nginx/internal/ingress/controller/config"
	"k8s.io/ingress-nginx/pkg/apis/ingress"
	"k8s.io/klog/v2"
)

// GetConfigBackend gets the well known ingress configuration file derived from Ingress Configmap
// TODO: We can instead watch for changes on this configmap and keep it in memory instead of do calls every time we
// need to reconfigure it
func (c *Client) GetConfigBackend() (config.Configuration, error) {

	var backendcfg config.Configuration
	cfg, err := c.ConfigurationClient.GetBackendConfiguration(c.ctx, c.Backendname)
	if err != nil {
		return backendcfg, fmt.Errorf("error obtaining backend configuration: %w", err)
	}

	if err := json.Unmarshal(cfg.GetConfiguration(), &backendcfg); err != nil {
		klog.Fatalf("error unmarshalling config: %s", err)
	}
	return backendcfg, nil
}

// GetConfigMap helps to get a configmap from the control plane
func (c *Client) GetConfigMap(configtype string, cmname string) (*v1.ConfigMap, error) {
	var configtypeOp ingress.ConfigType

	configtypeOp.Backend = c.Backendname
	configtypeOp.Configtype = configtype
	configtypeOp.Configmapname = cmname

	cfg, err := c.ConfigurationClient.GetConfigmap(c.ctx, &configtypeOp)
	if err != nil {
		klog.Fatalf("error getting config: %s", err)
	}

	var configmap v1.ConfigMap

	if err := json.Unmarshal(cfg.GetConfiguration(), &configmap); err != nil {
		klog.Fatalf("error unmarshalling config: %s", err)
	}

	return &configmap, nil
}
