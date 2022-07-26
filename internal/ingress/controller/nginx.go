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
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/eapache/channels"
	apiv1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/ingress-nginx/pkg/tcpproxy"
	utilingress "k8s.io/ingress-nginx/pkg/util/ingress"

	adm_controller "k8s.io/ingress-nginx/internal/admission/controller"
	"k8s.io/ingress-nginx/internal/ingress/controller/process"
	"k8s.io/ingress-nginx/internal/ingress/controller/store"
	"k8s.io/ingress-nginx/internal/ingress/metric"
	"k8s.io/ingress-nginx/internal/ingress/status"
	ing_net "k8s.io/ingress-nginx/internal/net"
	"k8s.io/ingress-nginx/internal/net/dns"
	"k8s.io/ingress-nginx/internal/net/ssl"
	"k8s.io/ingress-nginx/internal/task"
	"k8s.io/ingress-nginx/pkg/apis/ingress"

	"k8s.io/ingress-nginx/internal/grpcserver"

	"google.golang.org/grpc"

	klog "k8s.io/klog/v2"
)

const (
	tempNginxPattern = "nginx-cfg"
	emptyUID         = "-1"
)

// TODO: move somewhere else

// NewNGINXController creates a new NGINX Ingress controller.
func NewNGINXController(config *Configuration, mc metric.Collector) *NGINXController {
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(klog.Infof)
	eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{
		Interface: config.Client.CoreV1().Events(config.Namespace),
	})

	h, err := dns.GetSystemNameServers()
	if err != nil {
		klog.Warningf("Error reading system nameservers: %v", err)
	}

	n := &NGINXController{
		isIPV6Enabled: ing_net.IsIPv6Enabled(),

		resolver:        h,
		cfg:             config,
		syncRateLimiter: flowcontrol.NewTokenBucketRateLimiter(config.SyncRateLimit, 1),

		recorder: eventBroadcaster.NewRecorder(scheme.Scheme, apiv1.EventSource{
			Component: "nginx-ingress-controller",
		}),

		stopCh:   make(chan struct{}),
		updateCh: channels.NewRingChannel(1024),

		ngxErrCh: make(chan error),

		stopLock: &sync.Mutex{},

		runningConfig: new(ingress.Configuration),

		Proxy: &tcpproxy.TCPProxy{},

		metricCollector: mc,
	}

	if n.cfg.ValidationWebhook != "" {
		n.validationWebhookServer = &http.Server{
			Addr: config.ValidationWebhook,
			//G112 (CWE-400): Potential Slowloris Attack
			ReadHeaderTimeout: 10 * time.Second,
			Handler:           adm_controller.NewAdmissionControllerServer(&adm_controller.IngressAdmission{Checker: n}),
			TLSConfig:         ssl.NewTLSListener(n.cfg.ValidationWebhookCertPath, n.cfg.ValidationWebhookKeyPath).TLSConfig(),
			// disable http/2
			// https://github.com/kubernetes/kubernetes/issues/80313
			// https://github.com/kubernetes/ingress-nginx/issues/6323#issuecomment-737239159
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		}
	}

	n.store = store.New(
		config.Namespace,
		config.WatchNamespaceSelector,
		config.ConfigMapName,
		config.TCPConfigMapName,
		config.UDPConfigMapName,
		config.DefaultSSLCertificate,
		config.ResyncPeriod,
		config.Client,
		n.updateCh,
		config.DisableCatchAll,
		config.DeepInspector,
		config.IngressClassConfiguration)

	n.syncQueue = task.NewTaskQueue(n.syncIngress)

	if config.UpdateStatus {
		n.syncStatus = status.NewStatusSyncer(status.Config{
			Client:                 config.Client,
			PublishService:         config.PublishService,
			PublishStatusAddress:   config.PublishStatusAddress,
			IngressLister:          n.store,
			UpdateStatusOnShutdown: config.UpdateStatusOnShutdown,
			UseNodeInternalIP:      config.UseNodeInternalIP,
		})
	} else {
		klog.Warning("Update of Ingress status is disabled (flag --update-status)")
	}

	if err != nil {
		klog.Fatalf("Error creating file watchers: %v", err)
	}

	// TODO: ENFORCE TLS
	n.gRPCServer = grpc.NewServer(config.GRPCOpts...)

	return n
}

// NGINXController describes a NGINX Ingress controller.
type NGINXController struct {
	cfg *Configuration

	recorder record.EventRecorder

	syncQueue *task.Queue

	syncStatus status.Syncer

	syncRateLimiter flowcontrol.RateLimiter

	// stopLock is used to enforce that only a single call to Stop send at
	// a given time. We allow stopping through an HTTP endpoint and
	// allowing concurrent stoppers leads to stack traces.
	stopLock *sync.Mutex

	stopCh   chan struct{}
	updateCh *channels.RingChannel

	// ngxErrCh is used to detect errors with the NGINX processes
	ngxErrCh chan error

	// runningConfig contains the running configuration in the Backend
	runningConfig *ingress.Configuration

	resolver []net.IP

	isIPV6Enabled bool

	isShuttingDown bool

	Proxy *tcpproxy.TCPProxy

	store store.Storer

	metricCollector    metric.Collector
	admissionCollector metric.Collector

	validationWebhookServer *http.Server

	gRPCServer *grpc.Server
}

// Start starts a new NGINX master process running in the foreground.
func (n *NGINXController) Start() {
	klog.InfoS("Starting NGINX Ingress controller")

	n.store.Run(n.stopCh)

	// we need to use the defined ingress class to allow multiple leaders
	// in order to update information about ingress status
	// TODO: For now, as the the IngressClass logics has changed, is up to the
	// cluster admin to create different Leader Election IDs.
	// Should revisit this in a future
	electionID := n.cfg.ElectionID

	setupLeaderElection(&leaderElectionConfig{
		Client:     n.cfg.Client,
		ElectionID: electionID,
		OnStartedLeading: func(stopCh chan struct{}) {
			if n.syncStatus != nil {
				go n.syncStatus.Run(stopCh)
			}

			n.metricCollector.OnStartedLeading(electionID)
			// manually update SSL expiration metrics
			// (to not wait for a reload)
			n.metricCollector.SetSSLExpireTime(n.runningConfig.Servers)
			n.metricCollector.SetSSLInfo(n.runningConfig.Servers)
		},
		OnStoppedLeading: func() {
			n.metricCollector.OnStoppedLeading(electionID)
		},
	})

	go n.syncQueue.Run(time.Second, n.stopCh)
	// force initial sync
	n.syncQueue.EnqueueTask(task.GetDummyObject("initial-sync"))

	if n.validationWebhookServer != nil {
		klog.InfoS("Starting validation webhook", "address", n.validationWebhookServer.Addr,
			"certPath", n.cfg.ValidationWebhookCertPath, "keyPath", n.cfg.ValidationWebhookKeyPath)
		go func() {
			klog.ErrorS(n.validationWebhookServer.ListenAndServeTLS("", ""), "Error listening for TLS connections")
		}()
	}

	if n.gRPCServer != nil {
		klog.InfoS("Starting grpc server", "port", n.cfg.GRPCPort)
		ingress.RegisterEventServiceServer(n.gRPCServer, &grpcserver.EventServer{Recorder: n.recorder})
		ingress.RegisterConfigurationServer(n.gRPCServer, &grpcserver.ConfigurationServer{})

		lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", n.cfg.GRPCPort))
		if err != nil {
			klog.Fatalf("failed to listen: %v", err)
		}
		go func() {
			klog.ErrorS(n.gRPCServer.Serve(lis), "failed to start gRPC Server")
		}()
	}

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
			}
		case <-n.stopCh:
			return
		}
	}
}

// Stop gracefully stops the NGINX master process.
func (n *NGINXController) Stop() error {
	n.isShuttingDown = true

	n.stopLock.Lock()
	defer n.stopLock.Unlock()

	if n.syncQueue.IsShuttingDown() {
		return fmt.Errorf("shutdown already in progress")
	}

	time.Sleep(time.Duration(n.cfg.ShutdownGracePeriod) * time.Second)

	klog.InfoS("Shutting down controller queues")
	close(n.stopCh)
	go n.syncQueue.Shutdown()
	if n.syncStatus != nil {
		n.syncStatus.Shutdown()
	}

	if n.validationWebhookServer != nil {
		klog.InfoS("Stopping admission controller")
		err := n.validationWebhookServer.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

// DefaultEndpoint returns the default endpoint to be use as default server that returns 404.
func (n NGINXController) DefaultEndpoint() ingress.Endpoint {
	return ingress.Endpoint{
		Address: "127.0.0.1",
		Port:    fmt.Sprintf("%v", n.cfg.ListenPorts.Default),
		Target:  &apiv1.ObjectReference{},
	}
}

// IsDynamicConfigurationEnough returns whether a Configuration can be
// dynamically applied, without reloading the backend.
// TODO: Keeping this function here to be used to separate full reloads from hot reloads and send only the clean configuration
func (n *NGINXController) IsDynamicConfigurationEnough(pcfg *ingress.Configuration) (bool, *ingress.Configuration) {
	copyOfRunningConfig := *n.runningConfig
	copyOfPcfg := *pcfg

	copyOfRunningConfig.Backends = []*ingress.Backend{}
	copyOfPcfg.Backends = []*ingress.Backend{}

	utilingress.ClearL4serviceEndpoints(&copyOfRunningConfig)
	utilingress.ClearL4serviceEndpoints(&copyOfPcfg)

	utilingress.ClearCertificates(&copyOfRunningConfig)
	utilingress.ClearCertificates(&copyOfPcfg)

	return copyOfRunningConfig.Equal(&copyOfPcfg), &copyOfPcfg
}
