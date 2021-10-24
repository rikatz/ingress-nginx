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
	"fmt"
	"net/http"
	"os"
	"syscall"
	"time"

	"k8s.io/klog/v2"
)

var commandRunner NginxCommand = NewNginxCommand()

func reload(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "Invalid request\n")
		return
	}

	o, err := commandRunner.ExecCommand("-s", "reload").CombinedOutput()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, string(o))
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "NGINX Configuration reloaded\n")
}

func start(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "Invalid request\n")
		return
	}
	cmd := commandRunner.ExecCommand()
	// put NGINX in another process group to prevent it
	// to receive signals meant for the controller
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Pgid:    0,
	}

	klog.InfoS("Starting NGINX process")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		klog.Fatalf("NGINX error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, err.Error())
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "NGINX Started\n")

}

func stop(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "Invalid request\n")
		return
	}

	cmd := commandRunner.ExecCommand("-s", "quit")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, err.Error())
		return
	}

	// wait for the NGINX process to terminate
	timer := time.NewTicker(time.Second * 1)
	for range timer.C {
		if !IsRunning() {
			klog.InfoS("NGINX process has stopped")
			timer.Stop()
			break
		}
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "NGINX Stopped\n")

}

func main() {
	http.HandleFunc("/reload", reload)
	http.HandleFunc("/start", start)
	http.HandleFunc("/stop", stop)
	if err := http.ListenAndServe("127.0.0.1:8080", nil); err != nil {
		klog.Fatalf("Failed to start Ingress sidecar: %s", err)
	}
}
