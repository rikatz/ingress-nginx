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

package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	v1 "k8s.io/api/core/v1"
	"k8s.io/ingress-nginx/pkg/apis/ingress"
	"k8s.io/klog/v2"
)

/*
This program is created to test the communication between controlplane and dataplane. It can be deprecated in a future
*/

var (
	grpcaddress string
	service     string
	clientname  string
)

func main() {
	flag.StringVar(&grpcaddress, "grpc-address", "127.0.0.1:10000", "defines the grpc server to consume, in format of address:port")
	flag.StringVar(&service, "service", "endpoint", "defines the service to be tested")
	flag.StringVar(&clientname, "clientname", "ingress/pod1", "defines the name/id of the consumer, should be namespace/name")
	flag.Parse()

	rand.Seed(time.Now().UnixMicro())
	nsname := strings.Split(clientname, "/")
	if len(nsname) != 2 {
		klog.Fatal("clientname should be in format namespace/name")
	}
	conn, err := grpc.Dial(grpcaddress, grpc.WithTransportCredentials(insecure.NewCredentials())) // TODO: Receive secure options
	if err != nil {
		klog.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()

	switch service {
	case "eventservice":
		runEventServiceTest(conn, nsname)
	case "configurationservice":
	default:
		klog.Fatalf("invalid service, should be 'eventservice' or 'configurationservice'")
	}

}

func runEventServiceTest(conn *grpc.ClientConn, clientname []string) {
	client := ingress.NewEventServiceClient(conn)

	ctx := context.TODO()
	stream, err := client.PublishEvent(ctx)
	if err != nil {
		klog.Fatalf("error creating client: %v", err)
	}
	var eventtype string
	var reason string
	for {
		number := rand.Intn(100-1) + 1
		msg := fmt.Sprintf("EEE event received - %d", number)
		switch number % 3 {
		case 0:
			eventtype = v1.EventTypeNormal
		case 1:
			eventtype = v1.EventTypeWarning
		case 2:
			eventtype = "Sbrubles"
		}

		switch number % 2 {
		case 0:
			reason = "RELOAD"
		case 1:
			reason = "UPDATE"
		}

		message := &ingress.EventMessage{
			Backend: &ingress.BackendName{
				Namespace: clientname[0],
				Name:      clientname[1],
			},
			Eventtype: eventtype,
			Reason:    reason,
			Message:   msg,
		}

		klog.Infof("sending message %+v", message)
		if err := stream.Send(message); err != nil {
			klog.Errorf("error sending message: %v", err)
		}
		time.Sleep(3 * time.Second)

	}
}
