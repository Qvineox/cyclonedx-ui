package health

import (
	"encoding/json"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"net/http"
)

type Service struct {
	server *health.Server
}

func NewHealthService(h *health.Server) *Service {
	return &Service{server: h}
}

func (health *Service) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/public/health/status", health.Handle)

	return mux
}

func (health *Service) Handle(rw http.ResponseWriter, r *http.Request) {
	check, err := health.server.Check(r.Context(), &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		rw.WriteHeader(http.StatusServiceUnavailable)
		_, _ = rw.Write([]byte(err.Error()))
		return
	}

	marshal, err := json.Marshal(check)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write(marshal)
	return
}
