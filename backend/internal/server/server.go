package server

import (
	"context"
	"github.com/Qvineox/cyclonedx-ui/cfg"
	sbom_v1 "github.com/Qvineox/cyclonedx-ui/gen/go/api/proto/sbom/v1"
	"github.com/Qvineox/cyclonedx-ui/pkg/frontend"
	h "github.com/Qvineox/cyclonedx-ui/pkg/health"
	grpcMiddleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/rs/cors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"log/slog"
	"net/http"
	"strings"

	_ "google.golang.org/grpc/encoding/gzip"
)

func NewServer(ctx context.Context, config cfg.ServerConfig, services Services) (*grpc.Server, http.Handler, error) {
	var mux = http.NewServeMux()
	var gwMux = runtime.NewServeMux()

	var grpcServer = grpc.NewServer(
		grpc.MaxRecvMsgSize(int(config.MaxMessageSize)),
		grpc.MaxSendMsgSize(int(config.MaxMessageSize)),
		grpc.StreamInterceptor(
			grpcMiddleware.ChainStreamServer(
				recovery.StreamServerInterceptor(),
			)),
		grpc.UnaryInterceptor(
			grpcMiddleware.ChainUnaryServer(
				recovery.UnaryServerInterceptor(),
			)),
	)

	sbom_v1.RegisterSbomServiceServer(grpcServer, services.Sbom)
	err := sbom_v1.RegisterSbomServiceHandlerServer(ctx, gwMux, services.Sbom)
	if err != nil {
		panic("failed to register sbom service: " + err.Error())
	}

	if config.Health {
		slog.Warn("server health enabled")
		hs := health.NewServer()

		grpc_health_v1.RegisterHealthServer(grpcServer, hs)

		s := h.NewHealthService(hs)
		mux.Handle("/api/v1/public/health/", s.Handler())
	}

	if config.GRPC.Reflect {
		slog.Warn("server methods reflection enabled")
		reflection.Register(grpcServer)
	}

	mux.Handle("/api/v1/", gwMux)

	if config.HTTP.Web {
		mux.Handle("/", frontend.StaticFilesHandler())
	}

	if config.HTTP.Swagger {
		mux.Handle("/swagger/", frontend.SwaggerHandler())
	}

	slog.Info("configuring cors parameters...")
	c := cors.Options{
		AllowedOrigins:   config.Origins,
		AllowedHeaders:   []string{"*"},
		AllowedMethods:   []string{"HEAD", "GET", "POST", "OPTIONS"},
		AllowCredentials: true,
		MaxAge:           86400,
	}

	if config.CorsDebug {
		c.Debug = true
		c.Logger = corsLogger{}
	}

	restServer := cors.New(c).Handler(mux)

	return grpcServer, restServer, nil
}

type corsLogger struct{}

func (c corsLogger) Printf(s string, i ...interface{}) {
	slog.Info("cors debug",
		slog.String("message", strings.Trim(s, " ")),
	)
}
