package main

import (
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	internalprocess "k8s.io/ingress-nginx/internal/ingress/controller/process"
	"k8s.io/ingress-nginx/internal/nginx"

	"k8s.io/klog/v2"
)

// NginxExecTester defines the interface to execute
// command like reload or test configuration
type NginxExecTester interface {
	ExecCommand(args ...string) *exec.Cmd
	Test(cfg string) ([]byte, error)
}

// NginxCommand stores context around a given nginx executable path
type NginxCommand struct {
	Binary string
}

type NGINXController struct {
	// stopLock is used to enforce that only a single call to Stop send at
	// a given time. We allow stopping through an HTTP endpoint and
	// allowing concurrent stoppers leads to stack traces.
	stopLock *sync.Mutex

	isShuttingDown bool
	// ngxErrCh is used to detect errors with the NGINX processes
	ngxErrCh chan error
	stopCh   chan struct{}
	command  NginxExecTester
}

// NewNGINXController creates a new NGINX Ingress controller.
func NewNGINXController() *NGINXController {
	n := &NGINXController{
		ngxErrCh: make(chan error),
		stopCh:   make(chan struct{}),
		stopLock: &sync.Mutex{},
		command:  NewNginxCommand(),
	}

	return n
}

// Start starts a new NGINX master process running in the foreground.
func (n *NGINXController) Start() {
	klog.InfoS("Starting NGINX Ingress controller")

	cmd := n.command.ExecCommand()

	// put NGINX in another process group to prevent it
	// to receive signals meant for the controller
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Pgid:    0,
	}

	httpController := NewHTTPServer(n.command)

	klog.InfoS("Starting NGINX process")
	n.start(cmd)
	httpController.Start()

	for {
		select {
		case err := <-httpController.httpErrCh:
			klog.Errorf("error on http controller: %s", err)
			return

		case err := <-n.ngxErrCh:

			if n.isShuttingDown {
				return
			}
			// if the nginx master process dies, the workers continue to process requests
			// until the failure of the configured livenessProbe and restart of the pod.
			if internalprocess.IsRespawnIfRequired(err) {
				return
			}
		case <-n.stopCh:
			return
		}

	}
}

func (n *NGINXController) start(cmd *exec.Cmd) {
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

// Stop gracefully stops the NGINX master process.
func (n *NGINXController) Stop() error {
	n.isShuttingDown = true

	n.stopLock.Lock()
	defer n.stopLock.Unlock()
	// TODO: This time is configurable
	time.Sleep(time.Duration(300) * time.Second)

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
