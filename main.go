package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

func serveHTTPS() {
	sslProject := map[string]string{
		"mgmt-dev": "8009",
	}
	mux := http.NewServeMux()
	hosts := []string{}
	for name, port := range sslProject {
		/*vhost, err := url.Parse("https://127.0.0.1:"+port)
		if err != nil {
			panic(err)
		}
		proxy := httputil.NewSingleHostReverseProxy(vhost)*/
		if name == "" {
			mux.HandleFunc("example.com/", func(w http.ResponseWriter, r *http.Request) {
				handleTunneling(w, r, port)
				hosts = append(hosts, "example.com")
			})
		} else {
			mux.HandleFunc(name+".example.com/", func(w http.ResponseWriter, r *http.Request) {
				fmt.Println(r.Host)
				hosts = append(hosts, name+".example.com")
				handleTunneling(w, r, port)
			})
		}
	}
	hostPolicy := autocert.HostWhitelist(hosts...)

	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: hostPolicy,
		Cache:      autocert.DirCache("certs"),
	}
	httpsSrv := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      mux,
		TLSConfig:    &tls.Config{GetCertificate: m.GetCertificate},
		Addr:         ":443",
	}

	fmt.Println("Starting serve at 443 port")
	err := httpsSrv.ListenAndServeTLS("", "")
	if err != nil {
		panic(err)
	}
}

func main() {

	go serveHTTPS()

	projects := map[string]string{
		"mgmt":     "8000",
		"mgmt-dev": "8000",
		"msgs":     "8001",
		"ista":     "8002",
		"dcrcare":  "8080",
	}
	mux := http.NewServeMux()
	for name, port := range projects {
		vhost, err := url.Parse("http://127.0.0.1:" + port)
		if err != nil {
			panic(err)
		}
		proxy := httputil.NewSingleHostReverseProxy(vhost)
		if name == "" {
			mux.HandleFunc("example.com/", handler(proxy))
		} else {
			mux.HandleFunc(name+".example.com/", handler(proxy))
		}
	}

	httpSrv := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      mux,
	}
	httpSrv.Addr = ":80"

	fmt.Println("Starting serve at 80 port")
	err := httpSrv.ListenAndServe()
	if err != nil {
		panic(err)
	}
}

func handler(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r.Host)
		p.ServeHTTP(w, r)
	}
}

func handleTunneling(w http.ResponseWriter, r *http.Request, port string) {
	dest_conn, err := net.DialTimeout("tcp", "https://127.0.0.1:"+port, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	go transfer(dest_conn, client_conn)
	go transfer(client_conn, dest_conn)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}
