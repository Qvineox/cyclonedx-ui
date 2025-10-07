package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/Qvineox/cyclonedx-ui/cfg"
	"github.com/Qvineox/cyclonedx-ui/internal/server"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	var config *cfg.AppConfig

	configPath := flags()
	if configPath == nil || len(*configPath) == 0 {
		config = cfg.NewAppConfigFromEnv()
	} else {
		config = cfg.NewAppConfigFromFile(configPath)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()

	slog.Info(fmt.Sprintf("setting new log level to: %d", config.LogLevel))
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.Level(config.LogLevel),
	})))

	grpcSrv, restSrv, err := server.NewServer(ctx, config.Server, server.Services{})
	if err != nil {
		panic("failed to create server: " + err.Error())
	}

	if config.Server.GRPC.Enable {
		slog.Info("starting grpc server...")
		go func() {
			listener, err := net.Listen("tcp", net.JoinHostPort(config.Server.GRPC.Host, strconv.FormatUint(config.Server.GRPC.Port, 10)))
			if err != nil {
				panic("failed to create http listener: " + err.Error())
			}

			err = grpcSrv.Serve(listener)
			if err != nil {
				panic("failed to start grpc server: " + err.Error())
			}
		}()

		slog.Warn(fmt.Sprintf("grpc server started on %s:%d (health: %s, reflection: %s)",
			config.Server.GRPC.Host,
			config.Server.GRPC.Port,
			strconv.FormatBool(config.Server.Health),
			strconv.FormatBool(config.Server.GRPC.Reflect),
		))
	}

	if config.Server.HTTP.Enable {
		slog.Info("starting http server...")
		go func() {
			err = http.ListenAndServe(net.JoinHostPort(config.Server.HTTP.Host, strconv.FormatUint(config.Server.HTTP.Port, 10)), restSrv)
			if err != nil {
				panic("failed to start http server: " + err.Error())
			}
		}()

		slog.Warn(fmt.Sprintf("http server started on %s:%d", config.Server.HTTP.Host, config.Server.HTTP.Port))
	}

	<-ctx.Done()
}

func flags() (configFilePath *string) {
	configFilePath = flag.String("config", "", "config file path")

	// https://gobyexample.com/command-line-flags

	flag.Parse()
	return
}
