package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	apiv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/ingress-nginx/pkg/apis/ingress"
	"k8s.io/klog/v2"
)

const (
	// FullConfiguration is the request of a full configuration
	FullConfiguration = iota
	// DynamicConfiguration should return only if endpoints changes
	DynamicConfiguration
	// BackendConfiguration returns only the Ingress Configmap configuration
	BackendCConfiguration
)

// This file should be in the same directory as controller otherwise we will end up with cyclic imports

// ConfigurationServer defines a new gRPC Service responsible for the configuration exchange between control-plane and data-plane
type ConfigurationServer struct {
	ingress.UnimplementedConfigurationServer

	n *NGINXController
}

func (s *ConfigurationServer) GetConfigurations(ctx context.Context, backend *ingress.BackendName) (*ingress.Configurations, error) {

	if s.n == nil {
		klog.ErrorS(fmt.Errorf("no config available"), "error generating grpc answer")
		return nil, fmt.Errorf("no configuration is available yet")
	}
	if s.n.runningConfig == nil {
		klog.ErrorS(fmt.Errorf("no config available"), "error generating grpc answer")
		return nil, fmt.Errorf("no configuration is available yet")
	}
	payload, err := json.Marshal(s.n.runningConfig)
	if err != nil {
		klog.ErrorS(err, "error marshalling config json")
		return nil, fmt.Errorf("failed marshalling config json: %w", err)
	}

	op := ingress.Configurations_FullconfigOp{FullconfigOp: &ingress.Configurations_FullConfiguration{Configuration: payload}}
	return &ingress.Configurations{Op: &op}, nil
}

func (s *ConfigurationServer) WatchConfigurations(backend *ingress.BackendName, stream ingress.Configuration_WatchConfigurationsServer) error {

	backendName := fmt.Sprintf("%s/%s", backend.Namespace, backend.Name)

	// TODO: Validate backend name to avoid colisions in map
	s.n.GRPCSubscribers.Lock.Lock()
	s.n.GRPCSubscribers.Clients[backendName] = make(chan int)
	s.n.GRPCSubscribers.Lock.Unlock()

	defer func() {
		s.n.GRPCSubscribers.Lock.Lock()
		close(s.n.GRPCSubscribers.Clients[backendName])
		delete(s.n.GRPCSubscribers.Clients, backendName)
		s.n.GRPCSubscribers.Lock.Unlock()
	}()

	if s.n == nil {
		klog.ErrorS(fmt.Errorf("no config available"), "error generating grpc answer")
		return fmt.Errorf("no configuration is available yet")
	}
	if s.n.newConfig == nil {
		klog.ErrorS(fmt.Errorf("no config available"), "error generating grpc answer")
		return fmt.Errorf("no configuration is available yet")
	}

	for {
		syncType := <-s.n.GRPCSubscribers.Clients[backendName]
		var err error
		var payload []byte
		if err = stream.Context().Err(); err != nil {
			return fmt.Errorf("context error: %s", err)
		}
		switch syncType {

		case FullConfiguration:
			payload, err = json.Marshal(s.n.newConfig)
			if err != nil {
				klog.ErrorS(err, "error marshalling config json")
				return fmt.Errorf("failed marshalling config json: %w", err)
			}
			op := &ingress.Configurations_FullconfigOp{FullconfigOp: &ingress.Configurations_FullConfiguration{Configuration: payload}}
			err = stream.Send(&ingress.Configurations{Op: op})

		case DynamicConfiguration:
			err = s.sendDynamicConfig(stream)
		case BackendCConfiguration:
			klog.Errorf("not implemented!") // TODO: Implement

		default:
			klog.ErrorS(fmt.Errorf("invalid operation"), "error getting dynamic configuration")
		}

		if err != nil {
			klog.ErrorS(err, "failed to send configuration")
			continue
		}
	}
}

// configureDynamically encodes new Backends in JSON format and POSTs the
// payload to an internal HTTP endpoint handled by Lua.
func (s *ConfigurationServer) sendDynamicConfig(stream ingress.Configuration_WatchConfigurationsServer) error {
	// TODO: Maybe all this reflection can be run once in caller function (before sending to channels) and we just create
	// more ConfigurationTypes
	backendsChanged := !reflect.DeepEqual(s.n.runningConfig.Backends, s.n.newConfig)
	if backendsChanged {
		payload, err := json.Marshal(s.n.newConfig.Backends)
		if err != nil {
			klog.ErrorS(err, "error marshalling dynamic config")
			return fmt.Errorf("failed to marshall dynamic configuration: %w", err)
		}
		op := &ingress.Configurations_DynamicconfigOp{DynamicconfigOp: &ingress.Configurations_DynamicConfiguration{Configuration: payload}}
		if err := stream.Send(&ingress.Configurations{Op: op}); err != nil {
			return fmt.Errorf("error sending backends: %w", err)
		}
	}

	streamConfigurationChanged := !reflect.DeepEqual(s.n.runningConfig.TCPEndpoints, s.n.newConfig.TCPEndpoints) || !reflect.DeepEqual(s.n.runningConfig.UDPEndpoints, s.n.newConfig.UDPEndpoints)
	if streamConfigurationChanged {
		payload, err := json.Marshal(generateStreamBackend(s.n.newConfig.TCPEndpoints, s.n.newConfig.UDPEndpoints))
		if err != nil {
			klog.ErrorS(err, "error marshalling dynamic config")
			return fmt.Errorf("failed to marshall dynamic configuration: %w", err)
		}
		op := &ingress.Configurations_StreamconfigOp{StreamconfigOp: &ingress.Configurations_StreamConfiguration{Configuration: payload}}
		if err := stream.Send(&ingress.Configurations{Op: op}); err != nil {
			return fmt.Errorf("error sending backends: %w", err)
		}
	}

	serversChanged := !reflect.DeepEqual(s.n.runningConfig.Servers, s.n.newConfig.Servers)
	if serversChanged {
		// SEND just the serts
		/*err := configureCertificates(pcfg.Servers)
		if err != nil {
			return err
		}*/
	}

	return nil
}

func generateStreamBackend(TCPEndpoints []ingress.L4Service, UDPEndpoints []ingress.L4Service) []ingress.Backend {
	streams := make([]ingress.Backend, 0)
	for _, ep := range TCPEndpoints {
		var service *apiv1.Service
		if ep.Service != nil {
			service = &apiv1.Service{Spec: ep.Service.Spec}
		}

		key := fmt.Sprintf("tcp-%v-%v-%v", ep.Backend.Namespace, ep.Backend.Name, ep.Backend.Port.String())
		streams = append(streams, ingress.Backend{
			Name:      key,
			Endpoints: ep.Endpoints,
			Port:      intstr.FromInt(ep.Port),
			Service:   service,
		})
	}
	for _, ep := range UDPEndpoints {
		var service *apiv1.Service
		if ep.Service != nil {
			service = &apiv1.Service{Spec: ep.Service.Spec}
		}

		key := fmt.Sprintf("udp-%v-%v-%v", ep.Backend.Namespace, ep.Backend.Name, ep.Backend.Port.String())
		streams = append(streams, ingress.Backend{
			Name:      key,
			Endpoints: ep.Endpoints,
			Port:      intstr.FromInt(ep.Port),
			Service:   service,
		})
	}
	return streams

}
