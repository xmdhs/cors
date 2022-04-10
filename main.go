package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
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
	mux.HandleFunc("/", block(c.AllowHost, handler(c.AlllowURL)))
	mux.HandleFunc("/favicon.ico", http.NotFound)
	mux.HandleFunc("/robots.txt", http.NotFound)

	s := http.Server{
		Addr:              c.Listen,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Println(s.ListenAndServe())
}

func handler(allowURL []corsURL) http.HandlerFunc {
	for _, u := range allowURL {
		u.regexp = regexp.MustCompile(u.URL)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.String()
		u = strings.TrimPrefix(u, "/")
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
		if !alllowURL(allowURL, purl.String(), r.Method) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("not allow url or method"))
			return
		}
		corsProxy(purl).ServeHTTP(w, r)
	}
}

func corsProxy(u *url.URL) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		proxy := httputil.NewSingleHostReverseProxy(&url.URL{
			Host:   u.Host,
			Scheme: u.Scheme,
		})
		proxy.ErrorLog = log.Default()

		df := proxy.Director

		proxy.Director = func(r *http.Request) {
			df(r)
			r.Header.Del("referer")
			r.Header.Del("origin")
			r.Header.Del("X-Forwarded-For")
			r.Header.Del("X-Real-IP")
			r.Host = u.Host
		}

		proxy.ModifyResponse = func(r *http.Response) error {
			r.Header.Set("Access-Control-Allow-Origin", "*")
			r.Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			r.Header.Set("Access-Control-Allow-Headers", "Accept, Authorization, Cache-Control, Content-Type, DNT, If-Modified-Since, Keep-Alive, Origin, User-Agent")
			r.Header.Set("X-ToProxy", r.Request.URL.String())
			if r.StatusCode >= 300 && r.StatusCode < 400 && r.Header.Get("Location") != "" {
				r.Header.Set("Location", "/"+r.Header.Get("Location"))
			}
			return nil
		}

		r.URL = u
		r.RemoteAddr = ""
		r.RequestURI = u.String()

		proxy.ServeHTTP(w, r)
	}
}

func block(allowHost []string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		allow := false
		rhost := r.Header.Get("referer")
		if rhost == "" {
			rhost = r.Header.Get("origin")
		}
		u, err := url.Parse(rhost)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}
		rhost = u.Hostname()
		for _, host := range allowHost {
			if strings.HasSuffix(rhost, host) {
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

func alllowURL(alllowURL []corsURL, url, method string) bool {
	for _, r := range alllowURL {
		if r.regexp.MatchString(url) {
			mi := methodM[method]
			if r.Method&mi == mi {
				return true
			}
			return false
		}
	}
	return false
}

type config struct {
	AllowHost []string
	Listen    string
	AlllowURL []corsURL
}

type corsURL struct {
	URL    string
	Method int
	regexp *regexp.Regexp
}

var methodM = map[string]int{
	"GET":     1,
	"HEAD":    2,
	"POST":    4,
	"PUT":     8,
	"DELETE":  16,
	"CONNECT": 32,
	"OPTIONS": 64,
	"TRACE":   128,
	"PATCH":   256,
}
