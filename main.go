package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {

	b, err := os.ReadFile("config.json")
	if err != nil {
		panic(err)
	}
	c := config{}
	err = json.Unmarshal(b, &c)
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", block(c.AllowHost, handler))
	mux.HandleFunc("/favicon.ico", http.NotFound)

	s := http.Server{
		Addr:              c.Listen,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Println(s.ListenAndServe())
}

func handler(w http.ResponseWriter, r *http.Request) {
	u := r.URL.String()
	u = strings.TrimPrefix(u, r.URL.Scheme+"://"+r.Host+"/")
	purl, err := url.Parse(u)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	if purl.Scheme == "" {
		purl.Scheme = "http"
	}
	if purl.Host == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	corsProxy(purl).ServeHTTP(w, r)
}

func corsProxy(url *url.URL) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		proxy := httputil.NewSingleHostReverseProxy(url)
		proxy.ErrorLog = log.Default()

		df := proxy.Director

		proxy.Director = func(r *http.Request) {
			df(r)
			r.Header.Del("referer")
			r.Header.Del("origin")
		}

		proxy.ModifyResponse = func(r *http.Response) error {
			r.Header.Set("Access-Control-Allow-Origin", "*")
			r.Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			r.Header.Set("Access-Control-Allow-Headers", "Accept, Authorization, Cache-Control, Content-Type, DNT, If-Modified-Since, Keep-Alive, Origin, User-Agent, X-Requested-With, Token, x-access-token")
			return nil
		}

		proxy.ServeHTTP(w, r)
	}
}

func block(allowHost []string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			return
		}
		allow := false
		for _, host := range allowHost {
			if strings.HasSuffix(r.Host, host) {
				allow = true
				break
			}
		}
		if !allow {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Forbidden"))
			return
		}
		next(w, r)
	}
}

type config struct {
	AllowHost []string
	Listen    string
}
