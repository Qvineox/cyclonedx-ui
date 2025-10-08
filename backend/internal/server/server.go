package server

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/Qvineox/cyclonedx-ui/cfg"
	sbom_v1 "github.com/Qvineox/cyclonedx-ui/gen/go/api/proto/sbom/v1"
	grpcMiddleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/rs/cors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	_ "google.golang.org/grpc/encoding/gzip"
)

func NewServer(ctx context.Context, config cfg.ServerConfig, services Services) (*grpc.Server, http.Handler, error) {
	var gatewayMux = runtime.NewServeMux()

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
	err := sbom_v1.RegisterSbomServiceHandlerServer(ctx, gatewayMux, services.Sbom)
	if err != nil {
		panic("failed to register sbom service: " + err.Error())
	}

	if config.Health {
		slog.Warn("server health enabled")
		grpc_health_v1.RegisterHealthServer(grpcServer, health.NewServer())
	}

	if config.GRPC.Reflect {
		slog.Warn("server methods reflection enabled")
		reflection.Register(grpcServer)
	}

	slog.Info("configuring cors parameters...")
	restServer := cors.New(cors.Options{
		AllowedOrigins:   config.Origins,
		AllowedHeaders:   []string{"*"},
		AllowedMethods:   []string{"HEAD", "GET", "POST", "OPTIONS"},
		AllowCredentials: true,
		MaxAge:           86400,
	}).Handler(gatewayMux)

	return grpcServer, restServer, nil
}
