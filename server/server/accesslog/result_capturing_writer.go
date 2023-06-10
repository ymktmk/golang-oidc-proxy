package accesslog

import (
	"net/http"
)

type resultCapturingWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func (r *resultCapturingWriter) Write(b []byte) (int, error) {
	size, err := r.ResponseWriter.Write(b)
	r.size += size
	return size, err
}

func (r *resultCapturingWriter) WriteHeader(v int) {
	r.ResponseWriter.WriteHeader(v)
	r.status = v
}

func (r *resultCapturingWriter) Flush() {
	r.ResponseWriter.(http.Flusher).Flush()
}
