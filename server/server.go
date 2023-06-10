package server

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"time"

	// "github.com/gorilla/mux"
	"github.com/gorilla/handlers"
	"github.com/sethvargo/go-limiter"
	"github.com/sethvargo/go-limiter/httplimit"
	"github.com/sethvargo/go-limiter/memorystore"
	"github.com/ymktmk/golang-sso-server/auth/sso"
	"github.com/ymktmk/golang-sso-server/config"
	"github.com/ymktmk/golang-sso-server/server/server/accesslog"
)

type server struct {
	oAuth2Service  sso.Interface
	tlsConfig      *tls.Config
	apiRateLimiter limiter.Store
}

func NewSever() (*server, error) {
	c, err := config.NewSsoConfig()
	if err != nil {
		log.Println(err)
		return nil, err
	}

	ssoIf, err := sso.NewSso(c)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	// https://github.com/sethvargo/go-limiter/blob/main/README.md
	store, err := memorystore.New(&memorystore.Config{
		Tokens:   1000,
		Interval: time.Second,
	})
	if err != nil {
		log.Println(err)
		return nil, err
	}

	return &server{
		oAuth2Service:  ssoIf,
		apiRateLimiter: store,
	}, nil
}

func (s *server) Run() error {
	httpServer := s.newHTTPServer()
	return httpServer.ListenAndServe()
}

func (s *server) newHTTPServer() *http.Server {
	endpoint := fmt.Sprintf("localhost:%d", 8000)

	ratelimit_middleware, err := httplimit.NewMiddleware(s.apiRateLimiter, httplimit.IPKeyFunc())
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	httpServer := http.Server{
		Addr: endpoint,
		// https://qiita.com/huji0327/items/c85affaf5b9dbf84c11e
		Handler: ratelimit_middleware.Handle(accesslog.Interceptor(mux)),
	}

	mux.Handle("/oauth2/redirect", handlers.ProxyHeaders(http.HandlerFunc(s.oAuth2Service.HandleRedirect)))
	mux.Handle("/oauth2/callback", handlers.ProxyHeaders(http.HandlerFunc(s.oAuth2Service.HandleCallback)))

	mux.HandleFunc("/", homeHandler)
	mux.HandleFunc("/user", usersHandler)

	return &httpServer
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to the home page!")
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "User info !")
}
