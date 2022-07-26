/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"fmt"

	api "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/ingress-nginx/pkg/apis/ingress"
)

// TODO: Add unit tests here
// newUpstream creates an upstream without servers.
func newUpstream(name string) *ingress.Backend {
	return &ingress.Backend{
		Name:      name,
		Endpoints: []ingress.Endpoint{},
		Service:   &api.Service{},
		SessionAffinity: ingress.SessionAffinityConfig{
			CookieSessionAffinity: ingress.CookieSessionAffinity{
				Locations: make(map[string][]string),
			},
		},
	}
}

// upstreamName returns a formatted upstream name based on namespace, service, and port
func upstreamName(namespace string, service *networking.IngressServiceBackend) string {
	if service != nil {
		if service.Port.Number > 0 {
			return fmt.Sprintf("%s-%s-%d", namespace, service.Name, service.Port.Number)
		}
		if service.Port.Name != "" {
			return fmt.Sprintf("%s-%s-%s", namespace, service.Name, service.Port.Name)
		}
	}
	return fmt.Sprintf("%s-INVALID", namespace)
}

// upstreamServiceNameAndPort verifies if service is not nil, and then return the
// correct serviceName and Port
func upstreamServiceNameAndPort(service *networking.IngressServiceBackend) (string, intstr.IntOrString) {
	if service != nil {
		if service.Port.Number > 0 {
			return service.Name, intstr.FromInt(int(service.Port.Number))
		}
		if service.Port.Name != "" {
			return service.Name, intstr.FromString(service.Port.Name)
		}
	}
	return "", intstr.IntOrString{}
}
