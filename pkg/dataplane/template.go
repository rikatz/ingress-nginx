package dataplane

import (
	"fmt"
	"strconv"
	"strings"

	"k8s.io/api/core/v1"
	ngx_config "k8s.io/ingress-nginx/internal/ingress/controller/config"
	"k8s.io/ingress-nginx/internal/net/ssl"
	"k8s.io/ingress-nginx/internal/nginx"
	"k8s.io/ingress-nginx/pkg/apis/ingress"
	"k8s.io/ingress-nginx/pkg/tcpproxy"
	utilingress "k8s.io/ingress-nginx/pkg/util/ingress"
	"k8s.io/klog/v2"
)

// generateTemplate returns the nginx configuration file content
func (n NGINXConfigurer) generateTemplate(cfg ngx_config.Configuration, ingressCfg ingress.Configuration) ([]byte, error) {

	if n.cfg.EnableSSLPassthrough {
		servers := []*tcpproxy.TCPServer{}
		for _, pb := range ingressCfg.PassthroughBackends {
			svc := pb.Service
			if svc == nil {
				klog.Warningf("Missing Service for SSL Passthrough backend %q", pb.Backend)
				continue
			}
			port, err := strconv.Atoi(pb.Port.String()) // #nosec
			if err != nil {
				for _, sp := range svc.Spec.Ports {
					if sp.Name == pb.Port.String() {
						port = int(sp.Port)
						break
					}
				}
			} else {
				for _, sp := range svc.Spec.Ports {
					if sp.Port == int32(port) {
						port = int(sp.Port)
						break
					}
				}
			}

			// TODO: Allow PassthroughBackends to specify they support proxy-protocol
			servers = append(servers, &tcpproxy.TCPServer{
				Hostname:      pb.Hostname,
				IP:            svc.Spec.ClusterIP,
				Port:          port,
				ProxyProtocol: false,
			})
		}

		n.Proxy.ServerList = servers
	}

	// NGINX cannot resize the hash tables used to store server names. For
	// this reason we check if the current size is correct for the host
	// names defined in the Ingress rules and adjust the value if
	// necessary.
	// https://trac.nginx.org/nginx/ticket/352
	// https://trac.nginx.org/nginx/ticket/631
	var longestName int
	var serverNameBytes int

	for _, srv := range ingressCfg.Servers {
		hostnameLength := len(srv.Hostname)
		if srv.RedirectFromToWWW {
			hostnameLength += 4
		}
		if longestName < hostnameLength {
			longestName = hostnameLength
		}

		for _, alias := range srv.Aliases {
			if longestName < len(alias) {
				longestName = len(alias)
			}
		}

		serverNameBytes += hostnameLength
	}

	nameHashBucketSize := nginxHashBucketSize(longestName)
	if cfg.ServerNameHashBucketSize < nameHashBucketSize {
		klog.V(3).InfoS("Adjusting ServerNameHashBucketSize variable", "value", nameHashBucketSize)
		cfg.ServerNameHashBucketSize = nameHashBucketSize
	}

	serverNameHashMaxSize := nextPowerOf2(serverNameBytes)
	if cfg.ServerNameHashMaxSize < serverNameHashMaxSize {
		klog.V(3).InfoS("Adjusting ServerNameHashMaxSize variable", "value", serverNameHashMaxSize)
		cfg.ServerNameHashMaxSize = serverNameHashMaxSize
	}

	if cfg.MaxWorkerOpenFiles == 0 {
		// the limit of open files is per worker process
		// and we leave some room to avoid consuming all the FDs available
		maxOpenFiles := rlimitMaxNumFiles() - 1024
		klog.V(3).InfoS("Maximum number of open file descriptors", "value", maxOpenFiles)
		if maxOpenFiles < 1024 {
			// this means the value of RLIMIT_NOFILE is too low.
			maxOpenFiles = 1024
		}
		klog.V(3).InfoS("Adjusting MaxWorkerOpenFiles variable", "value", maxOpenFiles)
		cfg.MaxWorkerOpenFiles = maxOpenFiles
	}

	if cfg.MaxWorkerConnections == 0 {
		maxWorkerConnections := int(float64(cfg.MaxWorkerOpenFiles * 3.0 / 4))
		klog.V(3).InfoS("Adjusting MaxWorkerConnections variable", "value", maxWorkerConnections)
		cfg.MaxWorkerConnections = maxWorkerConnections
	}

	setHeaders := map[string]string{}
	if cfg.ProxySetHeaders != "" {
		// TODO: Get via gRPC
		// cmap, err := n.store.GetConfigMap(cfg.ProxySetHeaders)
		cmap, err := &v1.ConfigMap{}, fmt.Errorf("")
		if err != nil {
			klog.Warningf("Error reading ConfigMap %q from local store: %v", cfg.ProxySetHeaders, err)
		} else {
			setHeaders = cmap.Data
		}
	}

	addHeaders := map[string]string{}
	if cfg.AddHeaders != "" {
		// TODO: Get via gRPC
		// cmap, err := n.store.GetConfigMap(cfg.AddHeaders)
		cmap, err := &v1.ConfigMap{}, fmt.Errorf("")
		if err != nil {
			klog.Warningf("Error reading ConfigMap %q from local store: %v", cfg.AddHeaders, err)
		} else {
			addHeaders = cmap.Data
		}
	}

	sslDHParam := ""
	if cfg.SSLDHParam != "" {
		secretName := cfg.SSLDHParam

		// TODO: get via gRPC or build a cache
		//secret, err := n.store.GetSecret(secretName)
		secret, err := &v1.Secret{}, fmt.Errorf("")
		if err != nil {
			klog.Warningf("Error reading Secret %q from local store: %v", secretName, err)
		} else {
			nsSecName := strings.Replace(secretName, "/", "-", -1)
			dh, ok := secret.Data["dhparam.pem"]
			if ok {
				pemFileName, err := ssl.AddOrUpdateDHParam(nsSecName, dh)
				if err != nil {
					klog.Warningf("Error adding or updating dhparam file %v: %v", nsSecName, err)
				} else {
					sslDHParam = pemFileName
				}
			}
		}
	}

	cfg.SSLDHParam = sslDHParam

	cfg.DefaultSSLCertificate = n.getDefaultSSLCertificate()

	tc := ngx_config.TemplateConfig{
		ProxySetHeaders:          setHeaders,
		AddHeaders:               addHeaders,
		BacklogSize:              sysctlSomaxconn(),
		Backends:                 ingressCfg.Backends,
		PassthroughBackends:      ingressCfg.PassthroughBackends,
		Servers:                  ingressCfg.Servers,
		TCPBackends:              ingressCfg.TCPEndpoints,
		UDPBackends:              ingressCfg.UDPEndpoints,
		Cfg:                      cfg,
		IsIPV6Enabled:            n.isIPV6Enabled && !cfg.DisableIpv6,
		NginxStatusIpv4Whitelist: cfg.NginxStatusIpv4Whitelist,
		NginxStatusIpv6Whitelist: cfg.NginxStatusIpv6Whitelist,
		RedirectServers:          utilingress.BuildRedirects(ingressCfg.Servers),
		IsSSLPassthroughEnabled:  n.cfg.EnableSSLPassthrough,
		ListenPorts:              n.cfg.ListenPorts,
		// TODO: Is this used in the template? I don't think so
		//PublishService:           n.GetPublishService(),
		EnableMetrics:       n.cfg.EnableMetrics,
		MaxmindEditionFiles: n.cfg.MaxmindEditionFiles,
		HealthzURI:          nginx.HealthPath,
		MonitorMaxBatchSize: n.cfg.MonitorMaxBatchSize,
		PID:                 nginx.PID,
		StatusPath:          nginx.StatusPath,
		StatusPort:          nginx.StatusPort,
		StreamPort:          nginx.StreamPort,
		StreamSnippets:      append(ingressCfg.StreamSnippets, cfg.StreamSnippet),
	}

	tc.Cfg.Checksum = ingressCfg.ConfigurationChecksum

	return n.t.Write(tc)
}

func (n *NGINXConfigurer) getDefaultSSLCertificate() *ingress.SSLCert {
	// read custom default SSL certificate, fall back to generated default certificate
	// TODO: Get via gRPC
	/*if n.cfg.DefaultSSLCertificate != "" {
		certificate, err := n.store.GetLocalSSLCert(n.cfg.DefaultSSLCertificate)
		if err == nil {
			return certificate
		}

		klog.Warningf("Error loading custom default certificate, falling back to generated default:\n%v", err)
	}*/

	return n.cfg.FakeCertificate
}
