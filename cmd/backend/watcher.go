package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/mitchellh/hashstructure"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/ingress-nginx/internal/ingress"
	pb "k8s.io/ingress-nginx/internal/ingress/protoc"
	"k8s.io/klog/v2"

	controller "k8s.io/ingress-nginx/internal/ingress"
)

// TODO: This is the main function for us. We need to adapt it to be a GRPC watcher
// and implement all the logic in here
// syncIngress collects all the pieces required to assemble the NGINX
// configuration file and passes the resulting data structures to the backend
// (OnUpdate) when a reload is deemed necessary.
func main() {

	// Set up a connection to the server.
	conn, err := grpc.Dial(*addr, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewConfigWatcherClient(conn)

	config := controller.Configuration{}

	n := NewNGINXController(&config, nil)

	// Contact the server and print out its response.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// TODO: WatchReq should actually be the backend/server name
	// TODO 2: Probably we want a recv/send stream, so we can provide the controller with
	// informations if something went wrong in some of the proxy servers
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

		if err := json.Unmarshal(conf.GetConfiguration(), &config); err != nil {
			log.Fatalf("failed to unmarshall the json config: %w", err)
		}

		if n.runningConfig.Equal(&config) {
			klog.V(3).Infof("No configuration change detected, skipping backend reload")
			continue
		}

		if !n.IsDynamicConfigurationEnough(&config) {
			klog.InfoS("Configuration changes detected, backend reload required")

			hash, _ := hashstructure.Hash(&config, &hashstructure.HashOptions{
				TagName: "json",
			})

			config.ConfigurationChecksum = fmt.Sprintf("%v", hash)

			err := n.OnUpdate(config)
			if err != nil {
				//n.metricCollector.IncReloadErrorCount()
				//n.metricCollector.ConfigSuccess(hash, false)
				// TODO: Below will probably exit the loop and we don't want it
				klog.Errorf("Unexpected failure reloading the backend:\n%v", err)
				//n.recorder.Eventf(k8s.IngressPodDetails, apiv1.EventTypeWarning, "RELOAD", fmt.Sprintf("Error reloading NGINX: %v", err))
				return err
			}

			klog.InfoS("Backend successfully reloaded")
			// TODO: Implement metrics
			/*
				n.metricCollector.ConfigSuccess(hash, true)
				n.metricCollector.IncReloadCount()


			*/
			//n.recorder.Eventf(k8s.IngressPodDetails, apiv1.EventTypeNormal, "RELOAD", "NGINX reload triggered due to a change in configuration")
		}

		isFirstSync := n.runningConfig.Equal(&ingress.Configuration{})
		if isFirstSync {
			// For the initial sync it always takes some time for NGINX to start listening
			// For large configurations it might take a while so we loop and back off
			klog.InfoS("Initial sync, sleeping for 1 second")
			time.Sleep(1 * time.Second)
		}

		retry := wait.Backoff{
			Steps:    15,
			Duration: 1 * time.Second,
			Factor:   0.8,
			Jitter:   0.1,
		}

		err = wait.ExponentialBackoff(retry, func() (bool, error) {
			err := n.configureDynamically(&config)
			if err == nil {
				klog.V(2).Infof("Dynamic reconfiguration succeeded.")
				return true, nil
			}

			klog.Warningf("Dynamic reconfiguration failed: %v", err)
			return false, err
		})
		if err != nil {
			klog.Errorf("Unexpected failure reconfiguring NGINX:\n%v", err)
			return err
		}

		/*
			ri := getRemovedIngresses(n.runningConfig, &config)

			re := getRemovedHosts(n.runningConfig, &config)
			n.metricCollector.RemoveMetrics(ri, re)
		*/
		n.runningConfig = &config

	}

	return nil
}
