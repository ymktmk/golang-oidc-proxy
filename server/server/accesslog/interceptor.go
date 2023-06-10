package accesslog

import (
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

func Interceptor(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := time.Now()

		rcw := &resultCapturingWriter{ResponseWriter: w}

		h.ServeHTTP(rcw, r)

		log.WithFields(log.Fields{
			"path":     r.URL.Path,
			"method":   r.Method,
			"status":   rcw.status,
			"size":     rcw.size,
			"duration": time.Since(t),
		}).Info()
	})
}
