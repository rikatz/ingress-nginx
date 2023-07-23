package main

import (
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"k8s.io/ingress-nginx/pkg/util/file"
	"k8s.io/ingress-nginx/pkg/util/process"

	"k8s.io/klog/v2"
)

const (
	httpControllerHostPort = "127.0.0.1:3333"
)

func main() {

	err := file.CreateRequiredDirectories()
	if err != nil {
		klog.Fatal(err)
	}

	// TODO: Wait for the shared files to be ready. They should be watched by
	// controller as changes on it trigger reloads.

	reg := prometheus.NewRegistry()

	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{
		PidFn:        func() (int, error) { return os.Getpid(), nil },
		ReportErrors: true,
	}))

	ngx := NewNGINXController()
	go ngx.Start()

	// TODO: This time (30) is configurable as a grace timeout period
	process.HandleSigterm(ngx, 30, func(code int) {
		os.Exit(code)
	})

}
