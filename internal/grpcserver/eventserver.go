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

package grpcserver

import (
	"io"

	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/ingress-nginx/pkg/apis/ingress"
	"k8s.io/klog/v2"
)

// EventServer defines a gRPC service responsible to receive and publish events broadcast from data-plane
type EventServer struct {
	ingress.UnimplementedEventServiceServer
	Recorder record.EventRecorder
}

func (s *EventServer) PublishEvent(stream ingress.EventService_PublishEventServer) error {
	for {
		event, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&ingress.EventReturn{})
		}
		if err != nil {
			return err
		}
		if event == nil || event.Backend == nil {
			klog.Warning("Received invalid nil event, skipping")
			continue
		}
		if event.Eventtype != apiv1.EventTypeNormal && event.Eventtype != apiv1.EventTypeWarning {
			klog.Warning("Received invalid event type from %s/%s: %s, skipping", event.Backend.Namespace, event.Backend.Name, event.Eventtype)
			continue
		}

		// TODO: We can check if the Pod really exists, using https://github.com/kubernetes/ingress-nginx/blob/a581a7bebc1f4ff028f1e57dca0ce95abef78c62/internal/k8s/main.go#L91. We just need to receive the clientSet as well as part of the struct :)
		// This needs some security assessment, like an unauthenticated access to this endpoint may leak pods informations, so we should be really careful if we want to protect against pod spoofing vs pod information leaking (validate with CJ Cullen)
		obj := &apiv1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name:      event.Backend.Name,
			Namespace: event.Backend.Namespace,
		}}
		s.Recorder.Eventf(obj, event.Eventtype, event.Reason, event.Message)
	}
}
