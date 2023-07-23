package main

import (
	"fmt"
	"net/http"
	"os"

	"k8s.io/ingress-nginx/pkg/util/file"
)

type httpServer struct {
	httpErrCh chan error
	mux       *http.ServeMux
	command   NginxExecTester
}

func NewHTTPServer(cmd NginxExecTester) *httpServer {
	mux := http.NewServeMux()

	return &httpServer{
		mux:       mux,
		command:   cmd,
		httpErrCh: make(chan error),
	}
}

func (h *httpServer) Start() {

	h.mux.HandleFunc("/reload", h.reload)
	h.mux.HandleFunc("/test", h.test)

	go func() {
		h.httpErrCh <- http.ListenAndServe(httpControllerHostPort, h.mux)
	}()
}

func (h *httpServer) reload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("endpoint accepts just POST"))
		return
	}
	// We need to copy the file, because we cannot mount a shared file on K8s (AFAIK),
	// and mounting the whole /etc/nginx can be a problem right now :)
	cfgTemp, err := readPostArg(r, "config")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	content, err := os.ReadFile(cfgTemp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	err = os.WriteFile(cfgPath, content, file.ReadWriteByUser)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	o, err := h.command.ExecCommand("-s", "reload").CombinedOutput()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(o)
}

func (h *httpServer) test(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("endpoint accepts just POST"))
		return
	}

	cfgTemp, err := readPostArg(r, "config")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	out, err := h.command.Test(cfgTemp)
	if err != nil {
		// this error is different from the rest because it must be clear why nginx is not working
		oe := fmt.Sprintf(`
-------------------------------------------------------------------------------
Error: %v
%v
-------------------------------------------------------------------------------
`, err, string(out))

		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(oe))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func readPostArg(r *http.Request, arg string) (val string, err error) {
	if err = r.ParseForm(); err != nil {
		return "", fmt.Errorf("error parsing form: %s", err)
	}
	val = r.FormValue(arg)
	if val == "" {
		return "", fmt.Errorf("arg %s cannot be empty", arg)
	}
	return val, nil

}
