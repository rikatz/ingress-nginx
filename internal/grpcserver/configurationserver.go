package grpcserver

import "k8s.io/ingress-nginx/pkg/apis/ingress"

// ConfigurationServer defines a new gRPC Service responsible for the configuration exchange between control-plane and data-plane
type ConfigurationServer struct {
	ingress.UnimplementedConfigurationServer
}
