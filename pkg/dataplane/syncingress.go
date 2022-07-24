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

package dataplane

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/mitchellh/hashstructure"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/ingress-nginx/internal/ingress/controller/config"
	"k8s.io/ingress-nginx/pkg/apis/ingress"
	"k8s.io/ingress-nginx/pkg/util/file"
	utilingress "k8s.io/ingress-nginx/pkg/util/ingress"
	"k8s.io/klog/v2"
)

// syncIngress collects all the pieces required to assemble the NGINX
// configuration file and passes the resulting data structures to the backend
// (OnUpdate) when a reload is deemed necessary.
func (n *NGINXConfigurer) syncIngress(pcfg *ingress.Configuration) error {
	n.syncRateLimiter.Accept()

	if n.syncQueue.IsShuttingDown() {
		return nil
	}

	if n.runningConfig.Equal(pcfg) {
		klog.V(3).Infof("No configuration change detected, skipping backend reload")
		return nil
	}

	// TODO: We will turn this into a different method to not overload network everytime just a dynamic reload is required
	if !utilingress.IsDynamicConfigurationEnough(pcfg, n.runningConfig) {
		klog.InfoS("Configuration changes detected, backend reload required")

		hash, _ := hashstructure.Hash(pcfg, &hashstructure.HashOptions{
			TagName: "json",
		})

		pcfg.ConfigurationChecksum = fmt.Sprintf("%v", hash)

		err := n.OnUpdate(*pcfg)
		if err != nil {
			n.metricCollector.IncReloadErrorCount()
			n.metricCollector.ConfigSuccess(hash, false)
			klog.Errorf("Unexpected failure reloading the backend:\n%v", err)
			// TODO: Below should be another gRPC call to let controller know there was an error
			// n.recorder.Eventf(k8s.IngressPodDetails, apiv1.EventTypeWarning, "RELOAD", fmt.Sprintf("Error reloading NGINX: %v", err))
			return err
		}

		klog.InfoS("Backend successfully reloaded")
		n.metricCollector.ConfigSuccess(hash, true)
		n.metricCollector.IncReloadCount()
		// TODO: Below should be another gRPC call to let controller know there was an error
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
		Steps:    1 + n.cfg.DynamicConfigurationRetries,
		Duration: time.Second,
		Factor:   1.3,
		Jitter:   0.1,
	}

	retriesRemaining := retry.Steps
	err := wait.ExponentialBackoff(retry, func() (bool, error) {
		err := n.configureDynamically(pcfg)
		if err == nil {
			klog.V(2).Infof("Dynamic reconfiguration succeeded.")
			return true, nil
		}
		retriesRemaining--
		if retriesRemaining > 0 {
			klog.Warningf("Dynamic reconfiguration failed (retrying; %d retries left): %v", retriesRemaining, err)
			return false, nil
		}
		klog.Warningf("Dynamic reconfiguration failed: %v", err)
		return false, err
	})
	if err != nil {
		klog.Errorf("Unexpected failure reconfiguring NGINX:\n%v", err)
		return err
	}

	ri := utilingress.GetRemovedIngresses(n.runningConfig, pcfg)
	re := utilingress.GetRemovedHosts(n.runningConfig, pcfg)
	rc := utilingress.GetRemovedCertificateSerialNumbers(n.runningConfig, pcfg)
	n.metricCollector.RemoveMetrics(ri, re, rc)

	n.runningConfig = pcfg

	return nil
}

// OnUpdate is called by the synchronization loop whenever configuration
// changes were detected. The received backend Configuration is merged with the
// configuration ConfigMap before generating the final configuration file.
// Returns nil in case the backend was successfully reloaded.
func (n *NGINXConfigurer) OnUpdate(ingressCfg ingress.Configuration) error {
	cfg := n.GetBackendConfiguration()
	cfg.Resolver = n.resolver

	content, err := n.generateTemplate(cfg, ingressCfg)
	if err != nil {
		return err
	}

	err = createOpentracingCfg(cfg)
	if err != nil {
		return err
	}

	err = n.testTemplate(content)
	if err != nil {
		return err
	}

	if klog.V(2).Enabled() {
		src, _ := os.ReadFile(cfgPath)
		if !bytes.Equal(src, content) {
			tmpfile, err := os.CreateTemp("", "new-nginx-cfg")
			if err != nil {
				return err
			}
			defer tmpfile.Close()
			err = os.WriteFile(tmpfile.Name(), content, file.ReadWriteByUser)
			if err != nil {
				return err
			}

			diffOutput, err := exec.Command("diff", "-I", "'# Configuration.*'", "-u", cfgPath, tmpfile.Name()).CombinedOutput()
			if err != nil {
				if exitError, ok := err.(*exec.ExitError); ok {
					ws := exitError.Sys().(syscall.WaitStatus)
					if ws.ExitStatus() == 2 {
						klog.Warningf("Failed to executing diff command: %v", err)
					}
				}
			}

			klog.InfoS("NGINX configuration change", "diff", string(diffOutput))

			// we do not defer the deletion of temp files in order
			// to keep them around for inspection in case of error
			os.Remove(tmpfile.Name())
		}
	}

	err = os.WriteFile(cfgPath, content, file.ReadWriteByUser)
	if err != nil {
		return err
	}

	o, err := n.command.ExecCommand("-s", "reload").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v\n%v", err, string(o))
	}

	return nil
}

// TODO: Implement, get this via gRPC from control plane
func (n *NGINXConfigurer) GetBackendConfiguration() config.Configuration {
	return config.Configuration{}
}
