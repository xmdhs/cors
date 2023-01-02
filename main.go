package main

import (
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var all bool

func init() {
	flag.BoolVar(&all, "all", false, "")
	flag.Parse()
}

//go:embed ca-certificates.crt
var crt []byte

func main() {
	p := x509.NewCertPool()
	ok := p.AppendCertsFromPEM(crt)
	if !ok {
		panic("failed to parse root certificate")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig.RootCAs = p

	c := config{}
	if !all {
		b, err := os.ReadFile("config.json")
		if err != nil {
			panic(err)
		}
		err = json.Unmarshal(b, &c)
		if err != nil {
			panic(err)
		}
	} else {
		c.Listen = ":8080"
	}
	var h http.Handler
	if all {
		h = handler(tr)
	} else {
		h = block(c.AllowHost, c.AlllowURL, handler(tr))
	}

	s := http.Server{
		Addr:              c.Listen,
		Handler:           h,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Println(s.ListenAndServe())
}

func handler(t http.RoundTripper) http.HandlerFunc {
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
		corsProxy(purl, t).ServeHTTP(w, r)
	}
}

func corsProxy(u *url.URL, t http.RoundTripper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		proxy := httputil.NewSingleHostReverseProxy(&url.URL{
			Host:   u.Host,
			Scheme: u.Scheme,
		})
		proxy.ErrorLog = log.Default()
		proxy.Transport = t

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

func block(allowHost []string, allowURL []corsURL, next http.HandlerFunc) http.HandlerFunc {
	for i := range allowURL {
		allowURL[i].regexp = regexp.MustCompile(allowURL[i].URL)
	}
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
		if !allow && len(allowHost) != 0 {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Forbidden"))
			return
		}
		ru := r.URL.String()
		ru = strings.TrimPrefix(ru, "/")
		if !alllowURL(allowURL, ru, r.Method) && len(allowURL) != 0 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("not allow url or method"))
			return
		}
		next(w, r)
	}
}

func alllowURL(alllowURL []corsURL, url, method string) bool {
	for _, r := range alllowURL {
		if r.regexp.MatchString(url) {
			mi := methodM[method]
			return r.Method&mi == mi
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
