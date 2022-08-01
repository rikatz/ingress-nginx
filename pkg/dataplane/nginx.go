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
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/ingress-nginx/internal/ingress/controller/process"
	ngx_template "k8s.io/ingress-nginx/internal/ingress/controller/template"
	"k8s.io/ingress-nginx/internal/ingress/metric"
	ing_net "k8s.io/ingress-nginx/internal/net"
	"k8s.io/ingress-nginx/internal/net/dns"
	"k8s.io/ingress-nginx/internal/nginx"
	"k8s.io/ingress-nginx/internal/task"
	"k8s.io/ingress-nginx/pkg/apis/ingress"
	"k8s.io/ingress-nginx/pkg/tcpproxy"
	"k8s.io/ingress-nginx/pkg/util/file"
	"k8s.io/klog/v2"
)

// NewNGINXController creates a new NGINX Ingress controller.
func NewNGINXConfigurer(config *Configuration, mc metric.Collector) *NGINXConfigurer {

	h, err := dns.GetSystemNameServers()
	if err != nil {
		klog.Warningf("Error reading system nameservers: %v", err)
	}

	n := &NGINXConfigurer{
		isIPV6Enabled:   ing_net.IsIPv6Enabled(),
		resolver:        h,
		cfg:             config,
		syncRateLimiter: flowcontrol.NewTokenBucketRateLimiter(config.SyncRateLimit, 1),
		stopCh:          make(chan struct{}),
		ngxErrCh:        make(chan error),
		configureLock:   &sync.Mutex{},
		stopLock:        &sync.Mutex{},
		// TOOD: Right now we will receive the full configuration, but we may want to receive and validate just checksums
		runningConfig: new(ingress.Configuration),
		Proxy:         &tcpproxy.TCPProxy{},

		metricCollector: mc,

		command: NewNginxCommand(),
	}

	// TODO: Change to trigger the full reconciliation
	getFullReconciliation := func(obj interface{}) error {
		return nil
	}
	n.syncQueue = task.NewTaskQueue(getFullReconciliation)

	onTemplateChange := func() {
		template, err := ngx_template.NewTemplate(nginx.TemplatePath)
		if err != nil {
			// this error is different from the rest because it must be clear why nginx is not working
			klog.ErrorS(err, "Error loading new template")
			return
		}

		n.t = template
		klog.InfoS("New NGINX configuration template loaded")
		// We trigger an event for a full reconciliation if template changes
		n.syncQueue.EnqueueTask(task.GetDummyObject("template-change"))
	}

	ngxTpl, err := ngx_template.NewTemplate(nginx.TemplatePath)
	if err != nil {
		klog.Fatalf("Invalid NGINX configuration template: %v", err)
	}

	n.t = ngxTpl

	_, err = file.NewFileWatcher(nginx.TemplatePath, onTemplateChange)
	if err != nil {
		klog.Fatalf("Error creating file watcher for %v: %v", nginx.TemplatePath, err)
	}

	filesToWatch := []string{}
	err = filepath.Walk("/etc/nginx/geoip/", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		filesToWatch = append(filesToWatch, path)
		return nil
	})

	if err != nil {
		klog.Fatalf("Error creating file watchers: %v", err)
	}

	for _, f := range filesToWatch {
		_, err = file.NewFileWatcher(f, func() {
			klog.InfoS("File changed detected. Reloading NGINX", "path", f)
			n.syncQueue.EnqueueTask(task.GetDummyObject("file-change"))
		})
		if err != nil {
			klog.Fatalf("Error creating file watcher for %v: %v", f, err)
		}
	}

	return n
}

// Start starts a new NGINX master process running in the foreground.
func (n *NGINXConfigurer) Start() {
	klog.InfoS("Starting NGINX Ingress configurer")

	cmd := n.command.ExecCommand()

	// put NGINX in another process group to prevent it
	// to receive signals meant for the controller
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Pgid:    0,
	}

	if n.cfg.EnableSSLPassthrough {
		n.setupSSLProxy()
	}

	klog.InfoS("Starting NGINX process")
	n.start(cmd)

	// TODO: Implement a "sync / trigger configuration queue to force full ingress resync"
	n.syncQueue.EnqueueTask(task.GetDummyObject("initial-sync"))

	// In case of error the temporal configuration file will
	// be available up to five minutes after the error
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			err := cleanTempNginxCfg()
			if err != nil {
				klog.ErrorS(err, "Unexpected error removing temporal configuration files")
			}
		}
	}()

	for {
		select {
		case err := <-n.ngxErrCh:
			if n.isShuttingDown {
				return
			}

			// if the nginx master process dies, the workers continue to process requests
			// until the failure of the configured livenessProbe and restart of the pod.
			if process.IsRespawnIfRequired(err) {
				return
			}

		// TODO: Implement below, which is the main loop to resync / configure NGINX
		/*
			case event := <-n.updateCh.Out():
				if n.isShuttingDown {
					break
				}

				if evt, ok := event.(store.Event); ok {
					klog.V(3).InfoS("Event received", "type", evt.Type, "object", evt.Obj)
					if evt.Type == store.ConfigurationEvent {
						// TODO: is this necessary? Consider removing this special case
						n.syncQueue.EnqueueTask(task.GetDummyObject("configmap-change"))
						continue
					}

					n.syncQueue.EnqueueSkippableTask(evt.Obj)
				} else {
					klog.Warningf("Unexpected event type received %T", event)
				}*/
		case <-n.stopCh:
			return
		}
	}
}

// Stop gracefully stops the NGINX master process.
func (n *NGINXConfigurer) Stop() error {
	n.isShuttingDown = true

	n.stopLock.Lock()
	defer n.stopLock.Unlock()

	time.Sleep(time.Duration(n.cfg.ShutdownGracePeriod) * time.Second)

	// send stop signal to NGINX
	klog.InfoS("Stopping NGINX process")
	cmd := n.command.ExecCommand("-s", "quit")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		return err
	}

	// wait for the NGINX process to terminate
	timer := time.NewTicker(time.Second * 1)
	for range timer.C {
		if !nginx.IsRunning() {
			klog.InfoS("NGINX process has stopped")
			timer.Stop()
			break
		}
	}

	return nil
}

func (n *NGINXConfigurer) start(cmd *exec.Cmd) {
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		klog.Fatalf("NGINX error: %v", err)
		n.ngxErrCh <- err
		return
	}

	go func() {
		n.ngxErrCh <- cmd.Wait()
	}()
}
