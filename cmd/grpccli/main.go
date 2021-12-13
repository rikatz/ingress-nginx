/*
Copyright 2021 The Kubernetes Authors.

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
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"

	"google.golang.org/grpc"
	pb "k8s.io/ingress-nginx/internal/ingress/protoc"

	prettyjson "github.com/hokaccha/go-prettyjson"
	controller "k8s.io/ingress-nginx/internal/ingress"
)

const (
	defaultName = "world"
)

var (
	addr = flag.String("addr", "127.0.0.1:11111", "the address to connect to")
)

func main() {
	flag.Parse()
	// Set up a connection to the server.
	conn, err := grpc.Dial(*addr, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewConfigWatcherClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, err := c.GetConfigurations(ctx, &pb.WatchReq{Id: 1})
	if err != nil {
		log.Fatalf("could not get: %v", err)
	}
	returnMsg := r.GetConfiguration()

	var config controller.Configuration
	if err := json.Unmarshal(returnMsg, &config); err != nil {
		log.Fatalf("failed to unmarshall the json config: %w", err)
	}

	s, err := prettyjson.Marshal(config)
	if err != nil {
		log.Fatalf("failed to prettify: %w", err)
	}
	fmt.Println("GETTING")
	fmt.Println(string(s))

	fmt.Println("WATCHING")

	list, err := c.WatchConfigurations(ctx, &pb.WatchReq{Id: 2})
	if err != nil {
		log.Fatalf("could not list: %v", err)
	}
	defer list.CloseSend()
	for {
		conf, err := list.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("Failed to stream %v: %s", c, err.Error())
		}

		var config1 controller.Configuration
		if err := json.Unmarshal(conf.GetConfiguration(), &config1); err != nil {
			log.Fatalf("failed to unmarshall the json config: %w", err)
		}

		s, err := prettyjson.Marshal(config1)
		if err != nil {
			log.Fatalf("failed to prettify: %w", err)
		}
		fmt.Println(string(s))
	}

}
