/*
Copyright 2022 The Kubernetes Authors.

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
	"context"
	"encoding/json"
	"fmt"

	pb "k8s.io/ingress-nginx/internal/ingress/protoc"
	"k8s.io/klog/v2"
)

func (s *grpcServer) GetConfigurations(ctx context.Context, id *pb.WatchReq) (*pb.Configurations, error) {
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

	return &pb.Configurations{Configuration: payload}, nil
}

func (s *grpcServer) WatchConfigurations(id *pb.WatchReq, stream pb.ConfigWatcher_WatchConfigurationsServer) error {
	var currentBackend, currentConfig string

	if s.n == nil {
		klog.ErrorS(fmt.Errorf("no config available"), "error generating grpc answer")
		return fmt.Errorf("no configuration is available yet")
	}
	if s.n.runningConfig == nil {
		klog.ErrorS(fmt.Errorf("no config available"), "error generating grpc answer")
		return fmt.Errorf("no configuration is available yet")
	}

	for {
		//klog.InfoS("Running again with config", "config", s.n.runningConfig.BackendConfigChecksum)
		if currentBackend != s.n.runningConfig.BackendConfigChecksum || currentConfig != s.n.runningConfig.ConfigurationChecksum {

			payload, err := json.Marshal(s.n.runningConfig)
			if err != nil {
				klog.ErrorS(err, "error marshalling config json")
				return fmt.Errorf("failed marshalling config json: %w", err)
			}

			if err := stream.Context().Err(); err != nil {
				return fmt.Errorf("Context error: %s", err)
			}
			if err := stream.Send(&pb.Configurations{Configuration: payload}); err != nil {
				return fmt.Errorf("failed to send the configuration: %s", err)
			}

			currentBackend, currentConfig = s.n.runningConfig.BackendConfigChecksum, s.n.runningConfig.ConfigurationChecksum
		}

	}
}
